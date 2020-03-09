//! # Remote PRIME+PROBE
//! This module is responsible for implementing PRIME+PROBE method of cache activity tracking.
//! The method is described in _NetCAT: Practical Cache Attacks from the Network_.

#![allow(dead_code)]
use crate::connection::{MemoryConnector, Time};
use hdrhistogram::Histogram;
use rand;
use std::cmp::min;
use std::collections::{HashMap, HashSet};
use std::io::Result;

pub const NUM_OF_SETS: usize = 64;
pub const BUFF_LEN: usize = 8388608; // 8 MiB
pub const BYTES_PER_LINE: usize = 64;
pub const LINES_PER_SET: usize = 12;
pub const THRESHOLD: Time = 260;
pub const DELTA: usize = 30;
pub const MAX_RETRY: usize = 100;
pub const TIMINGS_INIT_FILL: usize = 10000;
pub const PERCENTILE: f64 = 1.0; // only 1% of the data lies behind the value

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
    timings: Histogram<u64>, // we will be using this to dynamically scale threshold
}

impl RPP {
    pub fn new(conn: Box<dyn MemoryConnector<Item = Contents>>) -> RPP {
        let hist = Histogram::new(5).expect("could not create hist"); // 5 sets the precision and it is the maximum possible
        
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
            timings: hist,
        };
        
        rpp.fill_hist();
        rpp.build_sets();

        rpp
    }

    pub fn with_params(conn: Box<dyn MemoryConnector<Item = Contents>>, params: Params) -> RPP {
        let hist = Histogram::new(5).expect("could not create hist"); // 5 sets the precision and it is the maximum possible

        let mut rpp = RPP {
            params: params,
            conn: conn,
            sets: Vec::with_capacity(params.num_of_sets),
            addrs: (0usize..params.num_of_sets)
                .step_by(params.lines_per_set)
                .collect(),
            timings: hist,
        };

        rpp.fill_hist();
        rpp.build_sets();

        rpp
    }

    fn fill_hist(&mut self) {
        use rand::seq::IteratorRandom;
        // we assume that the memory region is not cached
        let mut rng = rand::thread_rng();

        for &ofs in self.addrs.iter().choose_multiple(&mut rng, TIMINGS_INIT_FILL) {
            // here we read from the main memory
            let (_, t1) = self.conn.read_timed(ofs).expect("Could not read in hist");

            // here we fist write the value to cache it and read again from cache
            self.conn.write(ofs, &rand::random()).expect("Could not write for hist");
            let (_, t2) = self.conn.read_timed(ofs).expect("Could not read in hist");

            // we expect the latency from main memory to be bigger that from LLC
            if t1 < t2 {
                continue;
            }

            self.timings.record(t1 - t2).expect("Could not fill hist");
        }
    }

    fn threshold(&self) -> Time {
        self.timings.value_at_percentile(PERCENTILE)
    }

    fn record(&mut self, val: Time) {
        self.timings.record(val).expect("Failed to record new timing");
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

            // Determine if x got evicted from the cache by this set
            let diff = t2 - t1; 
            if diff > self.threshold() {
                self.record(diff);
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
            let diff = t2 - t1; 
            if diff > self.threshold() {
                self.record(diff);
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
            let diff = t2 - t1; 
            if diff > self.threshold() {
                self.record(diff);
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