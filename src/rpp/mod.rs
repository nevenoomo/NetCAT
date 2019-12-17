//! # Remote PRIME+PROBE
//! This module is responsible for implementing PRIME+PROBE method of cache activity tracking.
//! The method is described in _NetCAT: Practical Cache Attacks from the Network_.

#![allow(dead_code)]
#![allow(dead_code)]
use crate::connection::MemoryConnector;
use std::cmp::min;
use std::collections::{HashMap, HashSet};

pub static NUM_OF_SETS: usize = 64;
pub static BUFF_LEN: usize = 8388608; // 8 MiB
pub static BYTES_PER_LINE: usize = 64;
pub static LINES_PER_SET: usize = 12;
pub static THRESHOLD: usize = 100;

type Address = usize;

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
    threshold: usize,
}

impl Params {
    pub fn new(
        num_of_sets: usize,
        buff_len: usize,
        bytes_per_line: usize,
        lines_per_set: usize,
        threshold: usize,
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

/// # RPP
/// Contains the context of the RPP for a given connection.
pub struct RPP {
    params: Params,
    conn: Box<dyn MemoryConnector<Item = Address>>,
    sets: Vec<EvictionSet>,
    addrs: HashSet<Address>,
}

impl RPP {
    pub fn new(conn: Box<dyn MemoryConnector<Item = Address>>) -> RPP {
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

    pub fn with_params(conn: Box<dyn MemoryConnector<Item = Address>>, params: Params) -> RPP {
        let mut rpp = RPP {
            params: params,
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

    fn build_sets(&mut self) {}

    fn build_set(&mut self) -> Result<Box<EvictionSet>, String> {
        let mut x = 0;
        let mut s = match self.forward_selection(&mut x) {
            Ok(s) => s,
            Err(m) => return Err(m), // Pass the error further
        };

        if let Err(m) = self.backward_selection(&mut s, &x) {
            return Err(m);
        }

        // repeat cleanup for unless we finish it
        // IDEA: is it ok? We may lose a lot of time here
        while let Err(_) = self.cleanup(&s) {}

        Ok(s)
    }

    fn forward_selection(&self, x: &mut Address) -> Result<Box<EvictionSet>, String> {
        let mut n = 1;
        // We expect to have this much elems in the resulting set
        let mut latencies = HashMap::with_capacity(self.params.buff_len / 4);

        loop {
            let mut sub_set = self.addrs.iter().take(n).map(|&x| x).collect();
            // First, we write the whole buffer. Some addrs might get evicted by the consequent writes.
            // Repeat until we do not return errors
            while let Err(_) = self.write_set(&sub_set) {}

            for addr in sub_set.iter() {
                latencies.insert(*addr, self.conn.read_timed(*addr));
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
            if let Err(s) = self.conn.write(*x) {
                return Err(s);
            }
            let t1 = match self.conn.read_timed(*x) {
                Ok(t) => t,
                Err(s) => return Err(s),
            };

            // Potentially take x from the main memory
            sub_set.remove(&x);
            while let Err(_) = self.write_set(&sub_set) {}

            let t2 = match self.conn.read_timed(*x) {
                Ok(t) => t,
                Err(s) => return Err(s),
            };

            // TODO: dynamic threash hold
            if t2 - t1 > self.params.threshold as u64 {
                return Ok(Box::new(sub_set));
            }

            n += 1;
        }
    }

    fn backward_selection(&self, s: &mut EvictionSet, x: &Address) -> Result<(), String> {
        let mut n = 1;

        loop {
            // if S is relatively small, then we do not use step adjusting
            n = min(n, s.len() / 2);
            let s_rm: HashSet<Address> = s.iter().take(n).map(|&x| x).collect();

            // Measure cache hit time for x
            if let Err(m) = self.conn.write(*x) {
                return Err(m);
            }
            let t1 = match self.conn.read_timed(*x) {
                Ok(t) => t,
                // pass the error up
                Err(s) => return Err(s),
            };

            // potentially read x from the main memory
            if let Err(m) = self.write_set_except(s, &s_rm) {
                return Err(m);
            }
            let t2 = match self.conn.read_timed(*x) {
                Ok(t) => t,
                // pass the error up
                Err(s) => return Err(s),
            };

            // is x still evicted?
            if t2 - t1 > self.params.threshold as u64 {
                s.retain(|x| s_rm.contains(x));
                // during the next step we will try to remove 10 more addrs
                n += 10;
            } else {
                // we removed too much
                n -= 1;
            }

            if s.len() == self.params.lines_per_set {
                break;
            }
        }

        Ok(())
    }

    fn cleanup(&mut self, s: &EvictionSet) -> Result<(), ()> {
        // remove addrs, which we used for eviction set
        self.addrs.difference(s);
        let mut error = false;
        // we do not want to allocate memory on the fly
        let mut to_be_removed = EvictionSet::with_capacity(s.len() / 4);

        for &x in self.addrs.iter() {
            // measure x hit time
            if let Err(_) = self.conn.write(x) {
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
            if t2 - t1 > self.params.threshold as u64 {
                to_be_removed.insert(x);
            }
        }

        // remove all unused addrs
        s.difference(&to_be_removed);

        // this is not informative, but this step is not critical
        if error {
            return Err(());
        }

        Ok(())
    }

    fn write_set(&self, s: &EvictionSet) -> Result<(), String> {
        for addr in s.iter() {
            if let Err(m) = self.conn.write(*addr) {
                return Err(m);
            }
        }

        Ok(())
    }

    fn write_set_except(&self, s: &EvictionSet, s_rm: &EvictionSet) -> Result<(), String> {
        // UGLY: can make it with Iterators?
        for &x in s.iter().filter(|x| !s_rm.contains(x)) {
            if let Err(s) = self.conn.write(x) {
                return Err(s);
            }
        }
        Ok(())
    }
}
