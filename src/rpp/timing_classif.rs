//! # Timing Classification
//!
//! Provides resources for distiguishing between a cache hit and a cache miss by access time

use super::Time;
use hdrhistogram::Histogram;

pub const PERCENTILE: f64 = 50.0;

/// Enum for distinguishing between cache hit and miss timings
pub enum CacheTiming {
    Hit(Time),
    Miss(Time),
}

impl CacheTiming {
    pub fn time(self) -> Time {
        match self {
            Self::Hit(t) => t,
            Self::Miss(t) => t,
        }
    }

    /// Tests, wheter the enum value is `Hit`
    pub fn is_hit(&self) -> bool {
        if let Self::Hit(_) = self {
            return true;
        }

        false
    }

    /// Tests, wheter the enum value is `Miss`
    pub fn is_miss(&self) -> bool {
        if let Self::Miss(_) = self {
            return true;
        }

        false
    }
}

/// Classifier of access timing. First needs to be trained by recording known timings.
/// Those are collected in two clusters.
pub struct TimingClassifier {
    hits: Histogram<u64>,
    misses: Histogram<u64>,
    hit_centroid: i128,
    miss_centroid: i128,
}

impl TimingClassifier {
    pub fn new() -> Self {
        let hits = Histogram::new(5).expect("Could not create a histogram for hit timings"); // 5 sets the precision and it is the maximum possible
        let misses = Histogram::new(5).expect("Could not create a histogram for miss timings");

        TimingClassifier {
            hits,
            misses,
            hit_centroid: 0,
            miss_centroid: 0,
        }
    }

    /// Records a new timing
    // And updates centroids
    pub fn record(&mut self, timing: CacheTiming) {
        match timing {
            CacheTiming::Hit(t) => {
                self.hits
                    .record(t)
                    .expect("Failed to record new hit timing");
                self.hit_centroid = self.hits.value_at_percentile(PERCENTILE) as i128;
            }
            CacheTiming::Miss(t) => {
                self.misses
                    .record(t)
                    .expect("Failed to record new miss timing");
                self.miss_centroid = self.misses.value_at_percentile(PERCENTILE) as i128;
            }
        }
    }

    /// Classifies the given timing. If undecisive (which should not generally occur), defaults to cache hit
    #[inline(always)]
    pub fn classify(&self, t: Time) -> CacheTiming {
        let t1 = t as i128;
        if (self.miss_centroid - t1).abs() < (self.hit_centroid - t1).abs() {
            // the time is closer to miss timings
            CacheTiming::Miss(t)
        } else {
            // the time is closer to hit timings
            CacheTiming::Hit(t)
        }
    }

    /// Tests whether a given timing is a hit
    #[inline(always)]
    pub fn is_hit(&self, t: Time) -> bool {
        self.classify(t).is_hit()
    }

    /// Tests whether a given timing is a miss
    #[inline(always)]
    pub fn is_miss(&self, t: Time) -> bool {
        self.classify(t).is_miss()
    }
}
