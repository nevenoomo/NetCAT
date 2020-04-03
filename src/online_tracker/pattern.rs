use super::SetCode;
use custom_derive::custom_derive;
use newtype_derive::*;
use std::io::{Error, ErrorKind, Result};
use std::iter::FromIterator;

pub const WINDOW_SIZE: usize = 10;

pub type PatternIdx = usize;

custom_derive! {
    #[derive(Debug, Default, Clone, PartialEq, Eq, NewtypeFrom,
        NewtypeDeref, NewtypeDerefMut,
        NewtypeIndex(usize), NewtypeIndexMut(usize) )]
    pub struct Pattern(Vec<SetCode>);
}

impl FromIterator<SetCode> for Pattern {
    fn from_iter<I: IntoIterator<Item = SetCode>>(iter: I) -> Self {
        Pattern(Vec::from_iter(iter))
    }
}

impl Pattern {
    #[inline(always)]
    pub fn new() -> Self {
        Pattern(Vec::new())
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
        probe_res: &Vec<Option<A>>,
    ) -> Result<PatternIdx> {
        // First we try to find an activation *right after* the current position.
        // Here we assume that just an other packet interfered with our
        // sequence.
        if let Some(idx) = &probe_res[WINDOW_SIZE / 2..]
            .iter()
            .enumerate()
            .find_map(|(idx, x)| if x.is_none() { None } else { Some(idx) })
        {
            return Ok((pos + idx) % self.0.len());
        }
        // Here we have found no activation after the current position.
        // We should try loking for *before*.
        if let Some(idx) = &probe_res[..WINDOW_SIZE / 2]
            .iter()
            .enumerate()
            .find_map(|(idx, x)| if x.is_none() { None } else { Some(idx) })
        {
            return Ok((pos as i64 - ((WINDOW_SIZE / 2) as i64 - *idx as i64))
                .rem_euclid(self.0.len() as i64) as usize);
        }

        // We failed to find any of the activations. This is a harsh error, which we cannot
        // recover from.
        return Err(Error::new(
            ErrorKind::Other,
            "ERROR: Cannot recover position",
        ));
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
            None,
            None,
            None,
            None,
            None,
            None,                // <- current_pos
            Some(SetCode(1, 2)), // <- corresponds to 3
            None,
            None,
            None,
        ];
        let recoverable_after_expected = 3usize;

        let recoverable_before = vec![
            None,
            Some(SetCode(1, 2)), // <- corresponds to 8
            None,
            None,
            None,
            None, // <- current_pos
            None,
            None,
            None,
            None,
        ];
        let recoverable_before_expected = 8usize;

        let unrecoverable: Vec<Option<SetCode>> = vec![None; 10];

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
