//! # Remote PRIME+PROBE
//! This module is responsible for implementing PRIME+PROBE method of cache activity tracking.
//! The method is described in _NetCAT: Practical Cache Attacks from the Network_.
#![allow(dead_code)]

mod params;
mod rpp_connector;

use crate::connection::{MemoryConnector, Time};
use console::style;
use hdrhistogram::Histogram;
use indicatif;
pub use params::*;
use rand;
use rpp_connector::RppConnector;
use serde::{Deserialize, Serialize};
use std::cmp::min;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Result;
use std::io::{Error, ErrorKind};

pub const DELTA: usize = 30;
pub const TIMINGS_INIT_FILL: usize = 1000;
pub const TIMING_REFRESH_RATE: usize = 1000;
pub const INSERT_RATE: usize = 100;
pub const PERCENTILE: f64 = 50.0;

pub type Address = usize;
pub type Contents = u8;

#[macro_export]
macro_rules! median {
    ($blk:block) => {{
        const STABILIZE_CNT: usize = 10;
        let mut vec = Vec::with_capacity(STABILIZE_CNT);
        for _ in 0..STABILIZE_CNT {
            vec.push($blk);
        }
        vec.sort();
        vec[(vec.len() - 1) / 2]
    }};
}

/// # EvictionSet
/// EvictionSet
pub type EvictionSet = HashSet<Address>;

/// A custom code, representing one page color
pub type ColorCode = usize;

/// A custom code, representing one page color
pub type ColoredSetCode = usize;

#[derive(Copy, Clone, Default, Debug, PartialOrd, PartialEq, Eq, Ord, Serialize, Deserialize)]
pub struct SetCode(pub ColorCode, pub ColoredSetCode);

type SetsKey = BTreeSet<Address>;
type EvictionSets = Vec<EvictionSet>;
// a mapping from the color code to the eviction sets, corresponding to this color
type ColoredSets = Vec<EvictionSets>;
// a mapping from the color code to the page numbers (aka addr/4096) of this color
type ColorKeys = Vec<SetsKey>;

/// Probe results with wraped data
// NOTE maybe downgrade to Option??
#[derive(Clone, Debug, PartialOrd, PartialEq, Eq, Ord, Serialize, Deserialize)]
pub enum ProbeResult<T> {
    Activated(T),
    Stale(T),
}

impl<T> ProbeResult<T> {
    pub fn is_activated(&self) -> bool {
        if let ProbeResult::Activated(_) = self {
            return true;
        }

        false
    }

    pub fn is_stale(&self) -> bool {
        !self.is_activated()
    }
}

pub type Latencies = Vec<Time>;

/// # RPP
/// Contains the context of the RPP for a given connection.
pub struct Rpp {
    params: RppParams,
    conn: RppConnector<Contents>,
    colored_sets: ColoredSets, // maps a color code
    color_keys: ColorKeys,
    addrs: HashSet<Address>,
    timings: Histogram<u64>, // we will be using this to dynamically scale threshold
    quite: bool,
}

impl Rpp {
    /// Creates a new instance with the default params.
    /// `quite` tells, whether the progress should be reported on the screen
    pub fn new(conn: Box<dyn MemoryConnector<Item = Contents>>, quite: bool) -> Rpp {
        let params: CacheParams = Default::default();
        Self::with_params(conn, quite, params)
    }

    /// Creates a new instance with the provided params and starts building eviction sets
    /// `quite` tells, whether the progress should be reported on the screen
    pub fn with_params(
        conn: Box<dyn MemoryConnector<Item = Contents>>,
        quite: bool,
        cparams: CacheParams,
    ) -> Rpp {
        let hist = Histogram::new(5).expect("could not create hist"); // 5 sets the precision and it is the maximum possible
        let params: RppParams = cparams.into();

        let mut rpp = Rpp {
            colored_sets: ColoredSets::with_capacity(params.n_colors),
            color_keys: ColorKeys::with_capacity(params.n_colors),
            params,
            conn: conn.into(),
            // TODO: do we really need ADDR_NUM here? We need at least as much page as there are colors. Maybe manipulate `params.n_colors`?
            addrs: (0usize..ADDR_NUM).map(|x| x * PAGE_SIZE).collect(), // here we collect page aligned (e.i. at the begining of the page) adresses
            timings: hist,
            quite,
        };
        rpp.build_sets();

        rpp
    }

    /// Primes the given set of addresses
    pub fn prime(&mut self, set_code: &SetCode) -> Result<()> {
        let it = self.colored_sets[set_code.0][set_code.1].clone();
        self.conn.evict(it.into_iter())
    }

    /// Probes the given set of addresses. Returns true if a set activation detected
    /// Returns `Activated(lats)`, where `lats` is a vector of latencies for addresses in
    /// the given set, if the cache activation has been measured, or `Stale(lats)` otherwise
    pub fn probe(&mut self, set_code: &SetCode) -> Result<ProbeResult<Latencies>> {
        use ProbeResult::*;

        let set: Vec<usize> = self.colored_sets[set_code.0][set_code.1]
            .iter()
            .copied()
            .collect();
        let lats = set
            .into_iter()
            .map(|x| self.conn.time(x))
            .collect::<Result<Vec<Time>>>()?;

        let max = lats.iter().max().unwrap();
        let min = lats.iter().min().unwrap();

        // NOTE This might be unstable
        if max - min > self.threshold() {
            return Ok(Activated(lats));
        }

        Ok(Stale(lats))
    }

    /// Primes all sets in a vector
    pub fn prime_all(&mut self, set_codes: &Vec<SetCode>) -> Result<()> {
        set_codes.iter().map(|x| self.prime(x)).collect()
    }

    /// Probes all sets in a vector
    pub fn probe_all(&mut self, set_codes: &Vec<SetCode>) -> Result<Vec<ProbeResult<Latencies>>> {
        set_codes.iter().map(|x| self.probe(x)).collect()
    }

    /// Test whether an activation has been observed in the provided Probe Results
    pub fn is_activated<T>(probes: &Vec<ProbeResult<T>>) -> bool {
        probes.iter().any(ProbeResult::is_activated)
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
            let t1 = self.conn.time(ofs).expect("Could not read in hist");

            // here we fist write the value to cache it and read again from cache
            self.conn.cache(ofs).expect("Could not write for hist");
            let t2 = self.conn.time(ofs).expect("Could not read in hist");

            // we expect the latency from main memory to be bigger that from LLC
            if t1 < t2 {
                continue;
            }

            let hit_miss = t1 - t2;
            self.timings.record(hit_miss).expect("Could not fill hist");
        }
    }

    #[inline(always)]
    fn reset_timings(&mut self) {
        self.timings.clear();
        self.fill_hist();
    }

    fn threshold(&mut self) -> Time {
        static mut CALLED: usize = 0;

        unsafe {
            // unsafe, because mutating static variable
            CALLED += 1;
            if CALLED > TIMING_REFRESH_RATE {
                self.reset_timings();
            }
        }

        self.timings.value_at_percentile(PERCENTILE)
    }

    fn trsh_noup(&self) -> Time {
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

    pub fn profiled(&self) -> usize {
        self.colored_sets.iter().map(|v| v.len()).sum()
    }

    fn build_sets(&mut self) {
        if !self.quite {
            println!(
                "Building sets: {}",
                style("STARTED").green()
            )
        }
        self.conn.allocate(self.params.v_buf);
        self.fill_hist();

        let pb = indicatif::ProgressBar::new(self.params.n_sets as u64);

        if !self.quite {
            pb.set_style(indicatif::ProgressStyle::default_bar().template("{prefix:.bold} [{elapsed}] [{bar:40.cyan/blue}] {percent}% ({eta})")
            .progress_chars("#>-"));
            pb.set_prefix("Building sets:");
        }
        while self.profiled() != self.params.n_sets {
            match self.build_set() {
                Ok(set) => self.check_set(set),
                Err(e) => {
                    println!("{}", style(e).red());
                    self.reset_timings();
                }
            }
            if !self.quite {
                pb.set_position(self.profiled() as u64);
            }
        }

        if !self.quite {
            pb.finish_and_clear();
            println!(
                "Building sets: {}",
                style("FINISHED").green()
            );
        }
    }

    fn check_set(&mut self, set: EvictionSet) {
        if let Err(e) = self.add_sets(set) {
            println!("{}", e);
        }
    }

    // note that this step might fail only due to read & write fails. read and write fail only as the last resort
    fn build_set(&mut self) -> Result<EvictionSet> {
        let (mut s, x) = self.forward_selection()?;
        self.backward_selection(&mut s, x)?;
        self.cleanup(&s)?;

        Ok(s)
    }

    fn add_sets(&mut self, set: EvictionSet) -> Result<()> {
        const CTL_BIT: usize = 6; // 6 - 12 (lower bits - lower val)
        const NUM_VARIANTS: usize = 64; // bits 12 - 6 determine the cache set. We have 2^6 = 64 options to change those
        for i in 1..NUM_VARIANTS {
            let new_set = set.iter().copied().map(|x| x ^ (i << CTL_BIT)).collect(); // xor all options with addrs from the given set
            self.add_set(new_set)?;
        }

        self.add_set(set)
    }

    fn add_set(&mut self, set: EvictionSet) -> Result<()> {
        let mut set_pages_nums = set.iter().map(|&x| x / PAGE_SIZE).collect();
        let possible_keys: Vec<_> = self
            .color_keys
            .iter()
            .enumerate()
            .filter(|(_, v)| !v.is_disjoint(&set_pages_nums))
            .map(|(k, _)| k)
            .collect();

        // DEBUG: Page coloring may be not enabled for a given OS
        // we expect only one color to be found, as a page can have only one color
        if possible_keys.len() > 1 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "ERROR: Cannot deside on set's color",
            ));
        }

        if possible_keys.len() == 0 {
            self.colored_sets.push(vec![set]);
            self.color_keys.push(set_pages_nums);
            return Ok(());
        }

        let color_code = possible_keys[0];

        if !self.is_unique(color_code, &set)? {
            return Ok(());
        }

        // add our set to the corresponding key
        self.colored_sets[color_code].push(set);

        // union of the previous page nums and new page nums
        self.color_keys[color_code].append(&mut set_pages_nums);

        Ok(())
    }

    fn is_unique(&mut self, color_code: ColorCode, set: &EvictionSet) -> Result<bool> {
        const REPEATING: usize = 4; // We will try for multiple times,
                                    // taking the most probable result
        let mut unique = true;
        for other_set in self.colored_sets[color_code].iter() {
            let mut results = HashMap::with_capacity(2); // Bool -> usize
            for _ in 0..REPEATING {
                *results
                    .entry(Self::test_uniq(
                        set,
                        other_set,
                        self.trsh_noup(),
                        &mut self.conn,
                    )?)
                    .or_insert(0) += 1;
            }

            // We consider the most probable result to be true
            unique = unique && results.into_iter().max_by_key(|(_, v)| *v).unwrap().0;
        }

        Ok(unique)
    }

    fn test_uniq(
        set: &EvictionSet,
        other_set: &EvictionSet,
        trsh: Time,
        conn: &mut RppConnector<Contents>,
    ) -> Result<bool> {
        use rand::seq::IteratorRandom;
        let test_addr = *other_set.iter().choose(&mut rand::thread_rng()).unwrap();
        conn.cache(test_addr)?;
        let t1 = conn.time(test_addr)?;
        conn.evict(set.iter().copied())?;
        let t2 = conn.time(test_addr)?;

        if t2 < t1 || t2 - t1 < trsh {
            return Ok(false);
        }
        Ok(true)
    }

    fn forward_selection(&mut self) -> Result<(EvictionSet, Address)> {
        let mut n = self.params.n_lines + 1;
        let mut latencies = HashMap::new();

        loop {
            let mut sub_set: EvictionSet = self.addrs.iter().take(n).copied().collect();
            // First, we write the whole buffer. Some addrs might get evicted by the consequent writes.
            // If this fails, then repeating won't help
            self.conn.evict(sub_set.iter().copied())?;

            // Measure access time for all entries of a selected subset
            for addr in sub_set.iter() {
                let lat = self.conn.time(*addr)?;
                latencies.insert(*addr, lat);
            }

            // Now we find an address with the highest access time
            let x = *latencies.iter().max_by_key(|(_, &v)| v).unwrap().0; // Take the key from the pair (which is an address with the biggest latency)

            // Measure cache hit time for x
            self.conn.cache(x)?;
            let t1 = self.conn.time(x)?;

            // Potentially take x from the main memory
            sub_set.remove(&x);
            self.conn.evict(sub_set.iter().copied())?;
            let t2 = self.conn.time(x)?;

            // Both t1 and t2 are from cache
            if t1 > t2 {
                continue;
            }
            // Determine if x got evicted from the cache by this set
            let diff = t2 - t1;
            if diff > self.threshold() {
                self.record_n(diff, (n / INSERT_RATE) as u64);
                return Ok((sub_set, x));
            }

            n += 1;
            if n % INSERT_RATE == 0 {
                self.record(diff);
            }
        }
    }

    // Here we assume that set `s` truly evicts address `x`
    fn backward_selection(&mut self, s: &mut EvictionSet, x: Address) -> Result<()> {
        if s.len() < self.params.n_lines {
            return Err(Error::new(
                ErrorKind::Other,
                "ERROR: the initial set for backwards selection is too narrow.",
            ));
        } else if s.len() == self.params.n_lines {
            return Ok(());
        }

        // we may begin by trying to remove part of the overhead. If we fail, the trying less in ok
        let mut n = 1;
        let mut i = 0;
        let mut last_i = 0;
        loop {
            i += 1;
            if s.len() < self.params.n_lines {
                return Err(Error::new(
                    ErrorKind::Other,
                    "ERROR: Set shrunk too much during backwards selection",
                ));
            }

            // if S is relatively small, then we do not use step adjusting
            n = if s.len() <= self.params.n_lines + DELTA {
                1
            } else {
                min(n, s.len() / 2)
            };

            let s_rm: EvictionSet = s.iter().take(n).copied().collect();

            // Measure cache hit time for x
            self.conn.cache(x)?;
            let t1 = self.conn.time(x)?;

            // Potentially read x from the main memory
            self.conn.evict(s.difference(&s_rm).copied())?;
            let t2 = self.conn.time(x)?;

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
            if s.len() == self.params.n_lines {
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
            self.conn.cache(x)?;
            let t1 = self.conn.time(x)?;

            // potentially read x from the main memory
            self.conn.evict(&mut s.iter().copied())?;
            let t2 = self.conn.time(x)?;

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

    // -------------------------METHODS FOR ONLINE TRACKER---------------------

    /// Returns the number of profiled colors
    pub fn colors_len(&self) -> usize {
        self.colored_sets.len()
    }

    /// Returns an iterator over all profiled `ColorCode`s
    pub fn colors<'a>(&'a self) -> impl Iterator<Item = ColorCode> + 'a {
        self.colored_sets.iter().enumerate().map(|(i, _)| i)
    }

    /// Returns the number of eviction sets, profiled for the given color
    pub fn color_len(&self, color_code: ColorCode) -> usize {
        self.colored_sets[color_code].len()
    }

    /// Return an iterator over `SetCodes` for the given color
    pub fn iter_color<'a>(
        &'a self,
        color_code: ColorCode,
    ) -> impl Iterator<Item = ColoredSetCode> + 'a {
        0..self.colored_sets[color_code].len()
    }
    /// Returns an iterator over all proviled `SetCode`s
    pub fn iter<'a>(&'a self) -> impl Iterator<Item = SetCode> + 'a {
        self.colored_sets
            .iter()
            .enumerate()
            .flat_map(|(color_code, v)| {
                v.iter()
                    .enumerate()
                    .map(move |(set_code, _)| SetCode(color_code, set_code))
            })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn new_rpp_test() {
        let conn = Box::new(crate::connection::local::LocalMemoryConnector::new());
        super::Rpp::new(conn, false);
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
