//! # Remote PRIME+PROBE
//! This module is responsible for implementing PRIME+PROBE method of cache activity tracking.
//! The method is described in _NetCAT: Practical Cache Attacks from the Network_.
use crate::connection::MemoryConnector;
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

    fn build_set(&self) -> Result<Box<EvictionSet>, String> {
        let s = match self.forward_selection() {
            Ok(s) => s,
            Err(s) => return Err(s), // Pass the error further
        };

        Ok(s)
    }

    fn forward_selection(&self) -> Result<Box<EvictionSet>, String> {
        let mut n = 1;
        // We expect to have this much elems in the resulting set
        let mut latencies = HashMap::with_capacity(self.params.buff_len / 4);

        loop {
            let mut sub_set = self.addrs.iter().take(n).map(|&x| x).collect();
            // First, we write the whole buffer. Some addrs might get evicted by the consequent writes.
            self.write_set(&sub_set);

            for addr in sub_set.iter() {
                latencies.insert(*addr, self.conn.read_timed(*addr));
            }

            let mut lats = latencies.iter();
            let init = lats.next().expect("At least one item should be here");
            let x = *lats
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
            if let Err(s) = self.conn.write(x) {
                return Err(s);
            }
            let t1 = match self.conn.read_timed(x) {
                Ok(t) => t,
                Err(s) => return Err(s),
            };

            // Potentially take x from the main memory
            sub_set.remove(&x);
            self.write_set(&sub_set);
            let t2 = match self.conn.read_timed(x) {
                Ok(t) => t,
                Err(s) => return Err(s),
            };

            if t2 - t1 > self.params.threshold as u64 {
                return Ok(Box::new(sub_set));
            }

            n += 1;
        }

        Err("".to_string())
    }

    fn write_set(&self, s: &EvictionSet) {
        for addr in s.iter() {
            self.conn.write(*addr);
        }
    }
}
