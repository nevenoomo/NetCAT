//! # Remote PRIME+PROBE
//! This module is responsible for implementing PRIME+PROBE method of cache activity tracking.
//! The method is described in _NetCAT: Practical Cache Attacks from the Network_.

#![allow(dead_code)]
use crate::connection::{MemoryConnector, Time};
use rand;
use std::cmp::min;
use std::collections::{HashMap, HashSet};
use std::io::Result;

pub static NUM_OF_SETS: usize = 64;
pub static BUFF_LEN: usize = 8388608; // 8 MiB
pub static BYTES_PER_LINE: usize = 64;
pub static LINES_PER_SET: usize = 12;
pub static THRESHOLD: Time = 260;
pub static DELTA: usize = 30;
pub static MAX_RETRY: usize = 100;

type Address = usize;
type Contents = u8;

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
            addrs: (0usize..BUFF_LEN).step_by(BYTES_PER_LINE).collect(),
        };

        rpp.build_sets();

        rpp
    }

    pub fn with_params(conn: Box<dyn MemoryConnector<Item = Contents>>, params: Params) -> RPP {
        let mut rpp = RPP {
            params: params,
            conn: conn,
            sets: Vec::with_capacity(params.num_of_sets),
            addrs: (0usize..params.num_of_sets)
                .step_by(params.lines_per_set)
                .collect(),
        };

        rpp.build_sets();

        rpp
    }

    fn build_sets(&mut self) {
        self.conn.allocate(self.params.buff_len);
    }

    // note that this step might fail only due to read & write fails. read and write fail only as the last resort
    pub fn build_set(&mut self) -> Result<Box<EvictionSet>> {
        let (mut s, x) = self.forward_selection()?;
        self.backward_selection(&mut s, x)?;
        self.cleanup(&s)?;

        Ok(s)
    }

    fn forward_selection(&mut self) -> Result<(Box<EvictionSet>, Address)> {
        let mut n = self.params.lines_per_set + 1;
        // We expect to have this much elems in the resulting set
        let mut latencies = HashMap::with_capacity(self.params.buff_len / 4);

        loop {
            let mut sub_set = self.addrs.iter().take(n).map(|&x| x).collect();
            // First, we write the whole buffer. Some addrs might get evicted by the consequent writes.
            // If this fails, then repeating won't help
            self.write_set(&sub_set)?;

            // Measure access time for all entries of a selected subset
            for addr in sub_set.iter() {
                let (_, lat) = self.conn.read_timed(*addr)?;
                latencies.insert(*addr, lat);
            }

            // Now we find an address with the highest access time
            let x = *latencies
                .iter()
                .max_by_key(|(_, &v)| v)
                .expect("ERROR: Forward selection. Cannot deside on max addr lat.")
                .0; // Take the key from the pair (which is an address with the biggest latency)

            // Measure cache hit time for x
            self.conn.write(x, &rand::random())?;
            let (_, t1) = self.conn.read_timed(x)?;

            // Potentially take x from the main memory
            sub_set.remove(&x);
            self.write_set(&sub_set)?;
            let (_, t2) = self.conn.read_timed(x)?;

            // TODO: dynamic threshhold
            // Determine if x got evicted from the cache by this set
            if t2 - t1 > self.params.threshold {
                return Ok((Box::new(sub_set), x));
            }

            n += 1;
        }
    }

    // Here we assume that set `s` truly evicts address `x`
    fn backward_selection(&mut self, s: &mut EvictionSet, x: Address) -> Result<()> {
        assert!(
            s.len() >= self.params.lines_per_set,
            "ERROR: the initial set for backwards selection is too narrow."
        );
        // we may begin by trying to remove part of the overhead. If we fail, the trying less in ok
        // TODO: Maybe use other method for finding initial point.
        let mut n = (s.len() - self.params.lines_per_set) / 2;
        loop {
            assert!(
                s.len() >= self.params.lines_per_set,
                "ERROR: Set shrunk too much during backwards selection"
            );

            // if S is relatively small, then we do not use step adjusting
            n = if s.len() < self.params.lines_per_set + DELTA {
                1
            } else {
                min(n, s.len() / 2)
            };
            let s_rm: EvictionSet = s.iter().take(n).map(|&x| x).collect();

            // Measure cache hit time for x
            self.conn.write(x, &rand::random())?;
            let (_, t1) = self.conn.read_timed(x)?;

            // Potentially read x from the main memory
            self.write_set_except(s, &s_rm)?;
            let (_, t2) = self.conn.read_timed(x)?;

            // Determine if `x` got evicted by a reduced set S\S_rm
            if t2 - t1 > self.params.threshold {
                // Truly remove S_rm from S
                s.retain(|x| !s_rm.contains(x));
                // Suring the next step we will try to remove 10 more addrs
                n += 10;
            } else {
                // We removed too much
                n -= 1;
            }

            // Stop when the size of the set equals the size of a cache set
            if s.len() == self.params.lines_per_set {
                return Ok(());
            }
        }
    }

    fn cleanup(&mut self, s: &EvictionSet) -> Result<()> {
        // First we remove addr in set `S` from global addr pool
        self.addrs.retain(|x| !s.contains(x));
        // We will be iterating over the set and removing from it. Rust does not allow that, thus making a copy
        let addrs: HashSet<usize> = self.addrs.iter().cloned().collect();

        for x in addrs {
            // measure x hit time
            self.conn.write(x, &rand::random())?;
            let (_, t1) = self.conn.read_timed(x)?;

            // potentially read x from the main memory
            self.write_set(s)?;
            let (_, t2) = self.conn.read_timed(x)?;

            // We evicted x? Then we do not need it anymore
            if t2 - t1 > self.params.threshold {
                self.addrs.remove(&x);
            }
        }

        Ok(())
    }

    fn write_set(&mut self, s: &EvictionSet) -> Result<()> {
        for addr in s.iter() {
            self.conn.write(*addr, &rand::random())?;
        }

        Ok(())
    }

    fn write_set_except(&mut self, s: &EvictionSet, s_rm: &EvictionSet) -> Result<()> {
        for &x in s.iter().filter(|x| !s_rm.contains(x)) {
            self.conn.write(x, &rand::random())?;
        }

        Ok(())
    }
}

pub mod test {
    use super::*;
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
            let rpp = NaiveRpp {
                params: Params::new(
                    NUM_OF_SETS,
                    BUFF_LEN,
                    BYTES_PER_LINE,
                    LINES_PER_SET,
                    THRESHOLD,
                ),
                conn: conn,
                sets: Vec::with_capacity(NUM_OF_SETS),
                addrs: (0usize..BUFF_LEN).step_by(BYTES_PER_LINE).collect(),
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

                // Measure access time for __evicted__ x
                self.write_set(&ev_set)?;
                let (_, t1) = self.conn.read_timed(x)?;
                
                // Remove random entry
                let &s = ev_set.iter().nth(rnd.gen_range(0, ev_set.len())).unwrap();
                ev_set.remove(&s);

                // Measure access time for potentially __not evicted__ x 
                // We assure that `x` is in the cache
                self.conn.write(x, &rand::random())?;
                self.write_set(&ev_set)?;
                let (_, t2) = self.conn.read_timed(x)?;

                // If we `t2` is so much lower than `t1`, then `x` has not been evicted from the cache
                if t1 - t2 >= self.params.threshold {
                    ev_set.insert(s);
                }

                if ev_set.len() == 12 {
                    return Ok(Box::new(ev_set));
                }
            }
        }

        fn write_set(&mut self, s: &EvictionSet) -> Result<()> {
            for addr in s.iter() {
                self.conn.write(*addr, &rand::random())?;
            }
    
            Ok(())
        }
    
        fn write_set_except(&mut self, s: &EvictionSet, s_rm: &EvictionSet) -> Result<()> {
            for &x in s.iter().filter(|x| !s_rm.contains(x)) {
                self.conn.write(x, &rand::random())?;
            }
    
            Ok(())
        }
    }
}
