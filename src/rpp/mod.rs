//! # Remote PRIME+PROBE
//! This module is responsible for implementing PRIME+PROBE method of cache activity tracking.
//! The method is described in _NetCAT: Practical Cache Attacks from the Network_.

#![allow(dead_code)]
use crate::connection::{MemoryConnector, Time};
use std::cmp::min;
use std::collections::{HashMap, HashSet};
use std::io::{Error, ErrorKind, Result};

pub static NUM_OF_SETS: usize = 64;
pub static BUFF_LEN: usize = 8388608; // 8 MiB
pub static BYTES_PER_LINE: usize = 64;
pub static LINES_PER_SET: usize = 12;
pub static THRESHOLD: Time = 500;
pub static DELTA: usize = 30;
pub static MAX_RETRY: usize = 100;

type Address = usize;
type Contents = u64;

/// # EvictionSet
/// EvictionSet
type EvictionSet = HashSet<Address>;

/// # Params
/// Parameters for Remote PRIME+PROBE.
#[derive(Clone, Copy)]
pub struct Params {
    num_of_sets: usize,
    buff_len: usize,
    bytes_per_line: usize,
    lines_per_set: usize,
    threshold: Time,
}

impl Params {
    pub fn new(
        num_of_sets: usize,
        buff_len: usize,
        bytes_per_line: usize,
        lines_per_set: usize,
        threshold: Time,
    ) -> Params {
        Params {
            num_of_sets,
            buff_len,
            bytes_per_line,
            lines_per_set,
            threshold,
        }
    }
}

// TODO: writes and reads should not fail on the first try. Implement repeating writes.

/// # RPP
/// Contains the context of the RPP for a given connection.
pub struct RPP {
    params: Params,
    conn: Box<dyn MemoryConnector<Item = Contents>>,
    sets: Vec<EvictionSet>,
    addrs: HashSet<Address>,
}

impl RPP {
    pub fn new(conn: Box<dyn MemoryConnector<Item = Contents>>) -> RPP {
        let mut rpp = RPP {
            params: Params::new(
                NUM_OF_SETS,
                BUFF_LEN,
                BYTES_PER_LINE,
                LINES_PER_SET,
                THRESHOLD,
            ),
            conn: conn,
            sets: Vec::with_capacity(NUM_OF_SETS),
            addrs: (0..BUFF_LEN)
                .step_by(BYTES_PER_LINE)
                .map(|x| x as Address)
                .collect(),
        };

        rpp.build_sets();

        rpp
    }

    pub fn with_params(conn: Box<dyn MemoryConnector<Item = Contents>>, params: Params) -> RPP {
        let mut rpp = RPP {
            params: params,
            conn: conn,
            sets: Vec::with_capacity(params.num_of_sets),
            addrs: (0..params.num_of_sets)
                .step_by(params.lines_per_set)
                .map(|x| x as Address)
                .collect(),
        };

        rpp.build_sets();

        rpp
    }

    fn build_sets(&mut self) {
        self.conn.allocate(self.params.buff_len);
    }

    pub fn build_set(&mut self) -> Result<Box<EvictionSet>> {
        let mut x = 0;
        let mut s = self.forward_selection(&mut x)?;

        self.backward_selection(&mut s, &x)?;

        // repeat cleanup for unless we finish it
        while self.cleanup(&s).is_err() {}

        Ok(s)
    }

    fn forward_selection(&mut self, x: &mut Address) -> Result<Box<EvictionSet>> {
        let mut n = 1;
        // We expect to have this much elems in the resulting set
        let mut latencies = HashMap::with_capacity(self.params.buff_len / 4);

        loop {
            let mut sub_set = self.addrs.iter().take(n).map(|&x| x).collect();
            // First, we write the whole buffer. Some addrs might get evicted by the consequent writes.
            // Repeat until we do not return errors
            while self.write_set(&sub_set).is_err() {}

            for addr in sub_set.iter() {
                let mut cnt = 0;
                let mut lat = 0;
                let mut err = Error::new(ErrorKind::Other, "");

                while cnt < MAX_RETRY {
                    match self.conn.read_timed(*addr) {
                        Ok(l) => {
                            lat = l;
                            break;
                        }
                        Err(e) => err = e,
                    }
                }

                if cnt == MAX_RETRY {
                    return Err(err);
                }
                let lat = latencies.insert(*addr, lat);
            }

            let mut lats = latencies.iter();
            let init = lats.next().expect("At least one item should be here");
            *x = *lats
                .fold(init, |acc, n| {
                    // Compare values (which are latencies)
                    if n.1 > acc.1 {
                        n
                    } else {
                        acc
                    }
                })
                .0; // Take the key from the pair (which is an address with the biggest latency)
                    // Measure hit time for x
            self.conn.write(*x)?;

            let t1 = self.conn.read_timed(*x)?;

            // Potentially take x from the main memory
            sub_set.remove(&x);
            while self.write_set(&sub_set).is_err() {}

            let t2 = self.conn.read_timed(*x)?;

            // TODO: dynamic thresh hold
            if t2 - t1 > self.params.threshold && sub_set.len() >= self.params.lines_per_set {
                return Ok(Box::new(sub_set));
            }

            n += 1;
        }
    }

    fn backward_selection(&mut self, s: &mut EvictionSet, x: &Address) -> Result<()> {
        let mut n = 1;
        loop {
            assert!(
                s.len() >= self.params.lines_per_set,
                "Eviction set shrunk down too much"
            );
            // if S is relatively small, then we do not use step adjusting
            n = if s.len() < self.params.lines_per_set + DELTA {
                1
            } else {
                min(n, s.len() / 2)
            };
            let s_rm: HashSet<Address> = s.iter().take(n).map(|&x| x).collect();

            // Measure cache hit time for x
            self.conn.write(*x)?;

            let t1 = self.conn.read_timed(*x)?;

            // potentially read x from the main memory
            self.write_set_except(s, &s_rm)?;

            let t2 = self.conn.read_timed(*x)?;

            // is x still evicted?
            if t2 - t1 > self.params.threshold {
                s.retain(|x| !s_rm.contains(x));
                // during the next step we will try to remove 10 more addrs
                n += 10;
            } else {
                // we removed too much
                n -= 1;
            }

            if s.len() == self.params.lines_per_set {
                return Ok(());
            }
        }
    }

    fn cleanup(&mut self, s: &EvictionSet) -> Result<()> {
        // remove addrs, which we used for eviction set
        self.addrs.difference(s);
        let mut error = false;
        // we do not want to allocate memory on the fly
        let mut to_be_removed = EvictionSet::with_capacity(s.len() / 4);
        let addrs = self.addrs.clone();

        for &x in addrs.iter() {
            // measure x hit time
            if self.conn.write(x).is_err() {
                error = true;
                break;
            }

            let t1 = match self.conn.read_timed(x) {
                Ok(t) => t,
                // pass the error up
                Err(_) => {
                    error = true;
                    break;
                }
            };

            // potentially read x from the main memory
            if let Err(_) = self.write_set(s) {
                error = true;
                break;
            }
            let t2 = match self.conn.read_timed(x) {
                Ok(t) => t,
                // pass the error up
                Err(_) => {
                    error = true;
                    break;
                }
            };

            // We evicted x? then we do not need it anymore
            if t2 - t1 > self.params.threshold {
                to_be_removed.insert(x);
            }
        }

        // remove all unused addrs
        s.difference(&to_be_removed);

        if error {
            return Err(Error::new(ErrorKind::Other, "Error during cleanup"));
        }

        Ok(())
    }

    fn write_set(&mut self, s: &EvictionSet) -> Result<()> {
        for addr in s.iter() {
            if let Err(m) = self.conn.write(*addr) {
                return Err(m);
            }
        }

        Ok(())
    }

    fn write_set_except(&mut self, s: &EvictionSet, s_rm: &EvictionSet) -> Result<()> {
        // UGLY: can make it with Iterators?
        for &x in s.iter().filter(|x| !s_rm.contains(x)) {
            if let Err(s) = self.conn.write(x) {
                return Err(s);
            }
        }
        Ok(())
    }
}

pub mod test {
    use super::*;
    use crate::connection::local::LocalMemoryConnector;
    use crate::connection::MemoryConnector;
    use rand;
    use rand::Rng;
    use std::collections::HashSet;

    pub struct NaiveRpp {
        params: Params,
        conn: Box<dyn MemoryConnector<Item = Contents>>,
        sets: Vec<EvictionSet>,
        addrs: HashSet<Address>,
    }

    impl NaiveRpp {
        pub fn new(conn: Box<dyn MemoryConnector<Item = Contents>>) -> NaiveRpp {
            let mut rpp = NaiveRpp {
                params: Params::new(
                    NUM_OF_SETS,
                    BUFF_LEN,
                    BYTES_PER_LINE,
                    LINES_PER_SET,
                    THRESHOLD,
                ),
                conn: conn,
                sets: Vec::with_capacity(NUM_OF_SETS),
                addrs: (0..BUFF_LEN)
                    .step_by(BYTES_PER_LINE)
                    .map(|x| x as Address)
                    .collect(),
            };
            rpp
        }

        pub fn naive_build_set(&mut self) -> Result<Box<EvictionSet>> {
            self.conn.allocate(self.params.buff_len);
            let mut rnd = rand::thread_rng();
            let &x = self
                .addrs
                .iter()
                .nth(rnd.gen_range(0, self.addrs.len()))
                .unwrap();
            let mut ev_set = self.addrs.clone();
            let mut i = 0;

            loop {
                println!("Iteration: {}", i);
                i += 1;
                self.write_set(&ev_set);
                let t1 = self.conn.read_timed(x).unwrap();
                let s;
                {
                    let s1 = ev_set
                        .iter()
                        .nth(rnd.gen_range(0, ev_set.len()))
                        .unwrap()
                        .clone();

                    ev_set.remove(&s1);
                    s = s1;
                }

                self.write_set(&ev_set);
                let t2 = self.conn.read_timed(x).unwrap();

                if t1 - t2 <= self.params.threshold {
                    ev_set.insert(s);
                }

                if ev_set.len() == 12 {
                    return Ok(Box::new(ev_set));
                }
            }
        }

        fn write_set(&mut self, s: &EvictionSet) -> Result<()> {
            for addr in s.iter() {
                if let Err(m) = self.conn.write(*addr) {
                    return Err(m);
                }
            }
            Ok(())
        }

        fn write_set_except(&mut self, s: &EvictionSet, s_rm: &EvictionSet) -> Result<()> {
            // UGLY: can make it with Iterators?
            for &x in s.iter().filter(|x| !s_rm.contains(x)) {
                if let Err(s) = self.conn.write(x) {
                    return Err(s);
                }
            }
            Ok(())
        }
    }
}
