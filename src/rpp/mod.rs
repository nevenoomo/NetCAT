//! # Remote PRIME+PROBE
//! This module is responsible for implementing PRIME+PROBE method of cache activity tracking.
//! The method is described in _NetCAT: Practical Cache Attacks from the Network_.
#![allow(dead_code)]

pub mod params;
mod timing_classif;

use crate::connection::{Address, CacheConnector, Time};
use console::style;
use indicatif;
pub use params::*;
use rand;
use rand::seq::IteratorRandom;
use serde::{Deserialize, Serialize};
use std::cmp::min;
use std::collections::{BTreeSet, HashSet};
use std::io::Result;
use std::io::{Error, ErrorKind};
use std::iter::FromIterator;
use timing_classif::{CacheTiming, TimingClassifier};

pub const DELTA: usize = 5;
pub const TIMINGS_INIT_FILL: usize = 100;
pub const TIMING_REFRESH_RATE: usize = 100;

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
// when we find a new set, consisting of page aligned addresses starting at the beginning of the page
// we get 64 more sets, which will be of the same color as we change only bits from 6 to 12, which are
// for page offset
type ColoredSets = Vec<EvictionSets>;

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
pub struct Rpp<C> {
    params: RppParams,
    conn: C,
    colored_sets: ColoredSets, // maps a color code to sets
    addrs: HashSet<Address>,
    classifier: TimingClassifier, // we will be using this to dynamically scale threshold
    quite: bool,
}

impl<C: CacheConnector<Item = Contents>> Rpp<C> {
    /// Creates a new instance with the default params.
    /// `quite` tells, whether the progress should be reported on the screen
    pub fn new(conn: C, quite: bool) -> Rpp<C> {
        let params: CacheParams = Default::default();
        Self::with_params(conn, quite, params)
    }

    /// Creates a new instance with the provided params and starts building eviction sets
    /// `quite` tells, whether the progress should be reported on the screen
    pub fn with_params(conn: C, quite: bool, cparams: CacheParams) -> Rpp<C> {
        let classifier = TimingClassifier::new();
        let params: RppParams = cparams.into();

        let mut rpp = Rpp {
            colored_sets: ColoredSets::with_capacity(params.n_colors),
            conn,
            addrs: (0usize..params.v_buf / PAGE_SIZE)
            .map(|x| x * PAGE_SIZE)
            .collect(), // here we collect page aligned (e.i. at the begining of the page) addresses
            classifier,
            quite,
            params,
        };
        rpp.build_sets();

        rpp
    }

    /// Primes the given set of addresses
    pub fn prime(&mut self, set_code: &SetCode) -> Result<()> {
        let addrs = self.colored_sets[set_code.0][set_code.1].clone();
        self.conn.cache_all(addrs.into_iter())
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
            .map(|x| self.conn.time_access(x))
            .collect::<Result<Vec<Time>>>()?;

        let miss = lats.iter().find(|&&lat| self.classifier.is_miss(lat));

        // We test whether an activation
        if miss.is_some() {
            return Ok(Activated(lats));
        }

        Ok(Stale(lats))
    }

    /// Primes all sets in a vector
    pub fn prime_all(&mut self, set_codes: &[SetCode]) -> Result<()> {
        set_codes.iter().map(|x| self.prime(x)).collect()
    }

    /// Probes all sets in a vector
    pub fn probe_all(&mut self, set_codes: &[SetCode]) -> Result<Vec<ProbeResult<Latencies>>> {
        set_codes.iter().map(|x| self.probe(x)).collect()
    }

    fn train_classifier(&mut self) {
        // we assume that the memory region is not cached
        let mut rng = rand::thread_rng();

        for ofs in self
            .addrs
            .iter()
            .copied()
            .choose_multiple(&mut rng, TIMINGS_INIT_FILL)
        {
            // here we read from the main memory
            let miss_time = self
                .conn
                .time_access(ofs)
                .expect("Failed to time memory access");

            // here we cache the address and read again from cache
            self.conn
                .cache(ofs)
                .expect("Failed to cache addr in while training");
            let hit_time = self
                .conn
                .time_access(ofs)
                .expect("Failed to time cache access");

            // we expect the latency from main memory to be bigger that from LLC
            if hit_time > miss_time {
                continue;
            }

            self.classifier.record(CacheTiming::Hit(hit_time));
            self.classifier.record(CacheTiming::Miss(miss_time));
        }
    }

    pub fn profiled(&self) -> usize {
        self.colored_sets.iter().map(|v| v.len()).sum()
    }

    fn build_sets(&mut self) {
        if !self.quite {
            eprintln!("Building sets: {}", style("STARTED").green())
        }
        self.conn.reserve(self.params.v_buf);
        self.train_classifier();

        let pb = indicatif::ProgressBar::new(self.params.n_sets as u64);

        if !self.quite {
            pb.set_style(
                indicatif::ProgressStyle::default_bar()
                    .template("{prefix:.bold} [{elapsed}] [{bar:40.cyan/blue}] {percent}% ({eta})")
                    .progress_chars("#>-"),
            );
            pb.set_prefix("Building sets:");
        }

        let mut err_cnt = 0;

        while self.profiled() < self.params.n_sets {
            match self.build_set() {
                Ok(set) => self.check_set(set),
                Err(e) => {
                    if !self.quite {
                        match e.kind() {
                            ErrorKind::UnexpectedEof => panic!("{}", style(e).red()),
                            ErrorKind::InvalidInput => (),
                            _ => eprintln!("{}", style(e).red()),
                        }
                    }
                    // If case of error we retrain the classifier to ensure correct timings
                    if err_cnt > TIMING_REFRESH_RATE {
                        // Something really bad happened. Need to refresh data.
                        err_cnt = 0;
                        self.classifier.clear();
                    }

                    self.train_classifier();
                    err_cnt += 1;
                }
            }
            if !self.quite {
                pb.set_position(self.profiled() as u64);
            }
        }

        if !self.quite {
            pb.finish_and_clear();
            eprintln!("Building sets: {}", style("FINISHED").green());
        }
    }

    fn check_set(&mut self, set: EvictionSet) {
        match self.is_unique(&set, 0) {
            Ok(u) if !u => return,
            Err(e) if !self.quite => {
                eprintln!("{}", style(e).red());
                return;
            }
            _ => (),
        }
        if let Err(e) = self.add_sets(set) {
            if !self.quite {
                eprintln!("{}", style(e).red());
            }
        }
    }

    fn check_evicts<I: Iterator<Item = Address>>(&mut self, set: I, addr: Address) -> Result<bool> {
        // bring `addr` into cache
        self.conn.cache(addr)?;

        // bring addrs from the `set` into cache, which shold cause eviction of addr
        self.conn.cache_all(set)?;

        // time access to `addr`
        let lat = self.conn.time_access(addr)?;

        // it should be a miss
        if self.classifier.is_miss(lat) {
            self.classifier.record(CacheTiming::Miss(lat));
            return Ok(true);
        }

        self.classifier.record(CacheTiming::Hit(lat));
        Ok(false)
    }

    // this step might fails only due to read & write fails. read and write fail only as the last resort
    // TODO this may halt forever
    fn build_set(&mut self) -> Result<EvictionSet> {
        let (mut s, x) = self.forward_selection()?;
        self.backward_selection(&mut s, x)?;
        self.cleanup(&s)?;

        Ok(s)
    }

    fn add_sets(&mut self, set: EvictionSet) -> Result<()> {
        const CTL_BIT: usize = 6; // 6 - 12 (lower bits - lower val)
        const NUM_VARIANTS: usize = 64; // bits 12 - 6 determine the cache set. We have 2^6 = 64 options to change those

        // this vector corresponds to the new color which we have profiled
        // one color corresponds to as much sets as there are on one page
        // other sets for pages with the same color will not pass the uniqueness check
        let mut sets = Vec::with_capacity(self.params.n_sets_per_page);
        sets.push(set.clone());
        for i in 1..NUM_VARIANTS {
            // We construct 64 new sets given one
            let new_set = set.iter().copied().map(|x| x ^ (i << CTL_BIT)).collect(); // xor all options with addrs from the given set
            sets.push(new_set);
        }

        // Finally, we record a new color
        self.colored_sets.push(sets);

        Ok(())
    }

    /// Check whether a given set is unique
    /// Will test it against all other sets with different colors
    /// **and addresses with bits 6-12 equal to `idx`**. This is
    /// the nessessary condition for them to interfere with each other.
    fn is_unique(&mut self, set: &EvictionSet, idx: usize) -> Result<bool> {
        const REPEATING: usize = 5; // We will try for multiple times,
                                    // taking the most probable result
        let mut unique = true;

        // We need to check sets from vector inside `colored_sets` vector with the
        // given `idx`
        for other_set in self.colored_sets.iter().map(|v| &v[idx]) {
            let mut score = 0;
            for _ in 0..REPEATING {
                // Taking a random addr from the other set
                let test_addr = *other_set.iter().choose(&mut rand::thread_rng()).unwrap();

                // Bring it into the cache
                self.conn.cache(test_addr)?;

                // Now cache all addrs from the tested set
                // If the set is unique, then it will fill **another cache set** and not
                // evict `test_addr`
                self.conn.cache_all(set.iter().copied())?;

                // We expect this to be a cache hit, as our new set is unique and
                // cover a **completely different** cache set
                let lat = self.conn.time_access(test_addr)?;

                if self.classifier.is_hit(lat) {
                    score += 1;
                } else {
                    score -= 1;
                }
            }

            // We consider the most probable result to be true
            unique = unique && score > 0;
        }

        Ok(unique)
    }

    fn forward_selection(&mut self) -> Result<(EvictionSet, Address)> {
        let mut n = self.params.n_lines + 1;
        if self.addrs.len() < n {
            return Err(Error::new(ErrorKind::UnexpectedEof, "ERROR: No addrs left"));
        }
        let total_addrs = self.addrs.len();

        while n <= total_addrs {
            let mut max_lat = 0;
            let mut max_idx = 0;

            let mut sub_set: Vec<Address> = self.addrs.iter().copied().take(n).collect();

            // Walk over all the addrs of a selected subset and finding the address with the maximum latency
            for (i, &addr) in sub_set.iter().enumerate() {
                let lat = self.conn.time_access(addr)?;
                if lat > max_lat {
                    max_lat = lat;
                    max_idx = i;
                }
            }
            // `max_addr` is a candidate address
            let max_addr = sub_set.swap_remove(max_idx);

            if self.check_evicts(sub_set.iter().copied(), max_addr)? {
                // From Vec to HashSet
                let sub_set = EvictionSet::from_iter(sub_set.into_iter());
                return Ok((sub_set, max_addr));
            }

            n += 1;
        }

        // Here we excided the number of addrs, but registered no eviction
        // We remove the faulty address not to cause more issues
        // MAYBE remove address, which we could not evict?
        Err(Error::new(
            ErrorKind::Other,
            "ERROR: cannot build set for the chosen address.",
        ))
    }

    // Here we assume that set `s` truly evicts address `x`
    fn backward_selection(&mut self, s: &mut EvictionSet, x: Address) -> Result<()> {
        if s.len() < self.params.n_lines {
            return Err(Error::new(
                ErrorKind::Other,
                "ERROR: the initial set for backwards selection is too narrow.",
            ));
        }
        if s.len() == self.params.n_lines {
            return Ok(());
        }

        let mut n = 1;
        // Stop when the size of the set equals the size of a cache set
        while s.len() > self.params.n_lines + DELTA && n > 0 {
            // if S is relatively small, then we do not use step adjusting
            n = min(n, s.len() >> 1); // >> 1 == / 2

            let s_rm = s
                .iter()
                .copied()
                .choose_multiple(&mut rand::thread_rng(), n);

            if self.check_evicts(s.iter().filter(|x| !s_rm.contains(x)).copied(), x)? {
                // Truly remove S_rm from S
                s.retain(|x| !s_rm.contains(x));

                // During the next step we will try to remove 10 more addrs
                n += 10;
            } else {
                // We removed too much
                n -= 1;
            }
        }

        if n == 0 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "ERROR: Forward selection provided faulty data, which caused backward selection to fail"
            ));
        }

        while s.len() > self.params.n_lines {
            let rm_addr = s.iter().copied().choose(&mut rand::thread_rng()).unwrap();

            if self.check_evicts(s.iter().filter(|&&x| x != rm_addr).copied(), x)? {
                // Truly remove S_rm from S
                s.remove(&rm_addr);
            }
        }

        if s.len() < self.params.n_lines {
            return Err(Error::new(
                ErrorKind::Other,
                "ERROR: Set shrunk too much during backwards selection",
            ));
        }

        return Ok(());
    }

    fn cleanup(&mut self, s: &EvictionSet) -> Result<()> {
        // First we remove addr in set `S` from global addr pool
        self.addrs.retain(|x| !s.contains(x));

        // We will be iterating over the set and removing from it. Rust does not allow that, thus making a copy
        // TODO this is an antipattern. Should avoid that
        let addrs: Vec<usize> = self.addrs.iter().copied().collect();

        for x in addrs.into_iter() {
            // If `x` is evicted by our new cache set, then we do not need it anymore
            if self.check_evicts(s.iter().copied(), x)? {
                self.addrs.remove(&x);
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

    /// Return an iterator over `ColoredSetCodes` for the given color
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

/// Test whether an activation has been observed in the provided Probe Results
#[inline(always)]
pub fn has_activation<T>(probes: &[ProbeResult<T>]) -> bool {
    probes.iter().any(ProbeResult::is_activated)
}

#[cfg(test)]
mod tests {
    #[test]
    fn new_rpp_test() {
        let conn = crate::connection::local::LocalMemoryConnector::new();
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
