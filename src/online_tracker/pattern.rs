use super::{SetCode, REPEATINGS};
use crate::rpp::{ProbeResult, ColorCode, ColoredSetCode};
use custom_derive::custom_derive;
use newtype_derive::*;
use std::io::{Error, ErrorKind, Result};
use std::iter::FromIterator;
use std::collections::HashMap;

pub const WINDOW_SIZE: usize = 10;

pub type PatternIdx = usize;
pub type PossiblePatterns = HashMap<ColorCode, Vec<Option<ColoredSetCode>>>;


custom_derive! {
    #[derive(Debug, Default, Clone, PartialEq, Eq, NewtypeFrom,
        NewtypeDeref, NewtypeDerefMut,
        NewtypeIndex(usize), NewtypeIndexMut(usize))]
    pub struct Pattern(Vec<SetCode>);
}

impl FromIterator<SetCode> for Pattern {
    fn from_iter<I: IntoIterator<Item = SetCode>>(iter: I) -> Self {
        Pattern(Vec::from_iter(iter))
    }
}

impl Pattern {
    #[inline(always)]
    pub fn find(patterns: PossiblePatterns) -> Result<Self> {
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
        // UGLY should have a separete error type
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

    pub fn window<'a>(&'a self, pos: PatternIdx) -> impl Iterator<Item = &SetCode> + 'a {
        let pat_len = self.0.len() as i64;
        let left = (pos as i64 - WINDOW_SIZE as i64 / 2).rem_euclid(pat_len) as usize;

        self.0.iter().cycle().skip(left).take(WINDOW_SIZE)
    }

    #[inline(always)]
    pub fn next_pos(&self, pos: PatternIdx) -> PatternIdx {
        // We have recorded a pattern such that it
        // reflects the order of the cache sets in
        // for a ring buffer, thus it suffies to just
        // take the next index

        (pos + 1) % self.0.len()
    }

    pub fn recover_next<A>(
        &self,
        pos: PatternIdx,
        probe_res: &[ProbeResult<A>],
    ) -> Result<PatternIdx> {
        // First we try to find an activation *right after* the current position.
        // Here we assume that just an other packet interfered with our
        // sequence.
        if let Some(idx) = &probe_res[WINDOW_SIZE / 2..]
            .iter()
            .enumerate()
            .find_map(|(idx, x)| if x.is_stale() { None } else { Some(idx) })
        {
            // We have found the index at which the activation *in the window*
            // was registered. We need to:
            //
            // 1. Make it the index of the set in the *whole pattern* by adding **pos**
            // 2. Make it the **next expected** position by +1
            return Ok((pos + idx + 1) % self.0.len());
        }
        // Here we have found no activation after the current position.
        // We should try loking for *before*.
        if let Some(idx) = &probe_res[..WINDOW_SIZE / 2]
            .iter()
            .enumerate()
            .find_map(|(idx, x)| if x.is_stale() { None } else { Some(idx) })
        {
            // Here we:
            //
            // 1. Make the pos the index of the pattern by subtrackting idx
            // (remember, that we registered activation **behind** the *pos*)
            // 2. Make it the **next expected** by + 1
            return Ok((pos as i64 - ((WINDOW_SIZE / 2) as i64 - *idx as i64) + 1)
                .rem_euclid(self.0.len() as i64) as usize);
        }

        // We failed to find any of the activations. This is a harsh error, which we cannot
        // recover from.
        Err(Error::new(
            ErrorKind::Other,
            "ERROR: Cannot recover position",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_test() {
        let pattern: Pattern = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
            .into_iter()
            .map(|x| SetCode(x, 1))
            .collect();

        let w: Vec<usize> = pattern.window(2).map(|SetCode(x, _)| *x).collect();

        assert_eq!(
            w,
            [7, 8, 9, 0, 1, 2, 3, 4, 5, 6],
            "The window is not correct"
        );
    }

    #[test]
    fn recover_test() {
        let current_pos = 2;
        let pattern: Pattern = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
            .into_iter()
            .map(|x| SetCode(x, 1))
            .collect();

        // window is [7, 8, 9, 0, 1, 2, 3, 4, 5, 6]
        //                           ^ current_pos

        let recoverable_after = vec![
            ProbeResult::Stale(()),
            ProbeResult::Stale(()),
            ProbeResult::Stale(()),
            ProbeResult::Stale(()),
            ProbeResult::Stale(()),
            ProbeResult::Stale(()),     // <- current_pos
            ProbeResult::Activated(()), // <- corresponds to 3
            ProbeResult::Stale(()),
            ProbeResult::Stale(()),
            ProbeResult::Stale(()),
        ];
        let recoverable_after_expected = 3usize;

        let recoverable_before = vec![
            ProbeResult::Stale(()),
            ProbeResult::Activated(()), // <- corresponds to 8
            ProbeResult::Stale(()),
            ProbeResult::Stale(()),
            ProbeResult::Stale(()),
            ProbeResult::Stale(()), // <- current_pos
            ProbeResult::Stale(()),
            ProbeResult::Stale(()),
            ProbeResult::Stale(()),
            ProbeResult::Stale(()),
        ];
        let recoverable_before_expected = 8usize;

        let unrecoverable = vec![ProbeResult::Stale(()); 10];

        assert_eq!(
            pattern
                .recover_next(current_pos, &recoverable_after)
                .expect("Recovery after resulted in an error"),
            recoverable_after_expected,
            "Wrong recovery if after"
        );
        assert_eq!(
            pattern
                .recover_next(current_pos, &recoverable_before)
                .expect("Recovery before resulted in an error"),
            recoverable_before_expected,
            "Wrong recovery if before"
        );
        assert!(
            pattern.recover_next(current_pos, &unrecoverable).is_err(),
            "Recovery did not result in an error, but should"
        )
    }
}
