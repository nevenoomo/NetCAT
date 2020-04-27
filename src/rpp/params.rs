pub const PAGE_SIZE: usize = 4096; // 4 KiB
pub const ADDR_NUM: usize = 15000; // We take this number from the netcat article

pub static XEON_E5: CacheParams = CacheParams {
    bytes_per_line: 64,
    lines_per_set: 20,
    cache_size: 20_971_520, // 20 MiB
};

pub static XEON_E5_DDIO: CacheParams = CacheParams {
    bytes_per_line: 64,
    lines_per_set: 2,
    cache_size: 20_971_520, // 20 MiB
};

pub static CORE_I7: CacheParams = CacheParams {
    bytes_per_line: 64,
    lines_per_set: 12,
    cache_size: 6_291_456, // 6 MiB
};

// This is for testing, i7 has no DDIO
pub static CORE_I7_DDIO: CacheParams = CacheParams {
    bytes_per_line: 64,
    lines_per_set: 2,
    cache_size: 6_291_456, // 6 MiB
};

pub static XEON_PLATINUM: CacheParams = CacheParams {
    bytes_per_line: 64,
    lines_per_set: 11,
    cache_size: 34_603_008, // 33 MiB
};

pub static XEON_PLATINUM_DDIO: CacheParams = CacheParams {
    bytes_per_line: 64,
    lines_per_set: 2,
    cache_size: 34_603_008, // 33 MiB
};

/// Parameters for Remote PRIME+PROBE.
/// Describes the last level cache of the targeted prosessor
#[derive(Clone, Copy)]
pub struct CacheParams {
    bytes_per_line: usize,
    lines_per_set: usize,
    cache_size: usize,
}

impl CacheParams {
    pub fn new(bytes_per_line: usize, lines_per_set: usize, cache_size: usize) -> CacheParams {
        CacheParams {
            bytes_per_line,
            lines_per_set,
            cache_size,
        }
    }
}

impl Default for CacheParams {
    fn default() -> Self {
        CORE_I7
    }
}

#[derive(Clone, Default)]
pub(super) struct RppParams {
    // number of lines per cache set
    pub(super) n_lines: usize,
    // total number of sets in a given cache
    pub(super) n_sets: usize,
    // number of sets, which would cover one memory page
    pub(super) n_sets_per_page: usize,
    // number of different colors available for this cache
    pub(super) n_colors: usize,
    // size of the work buffer for allocating in RPP
    pub(super) v_buf: usize,
}

impl From<CacheParams> for RppParams {
    fn from(cp: CacheParams) -> Self {
        let mut p: RppParams = Default::default();
        p.n_lines = cp.lines_per_set;
        p.n_sets = cp.cache_size / (cp.lines_per_set * cp.bytes_per_line);
        p.v_buf = ADDR_NUM * PAGE_SIZE;
        p.n_sets_per_page = PAGE_SIZE / (cp.bytes_per_line * p.n_lines);
        p.n_colors = cp.cache_size / (PAGE_SIZE * p.n_lines);

        p
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn param_test() {
        let cache_params = CacheParams::new(64, 12, 6_291_456);
        let rpp_params: RppParams = cache_params.into();

        assert_eq!(rpp_params.n_sets, 8192, "Number of sets is wrong");
        assert_eq!(rpp_params.n_sets_per_page, 64, "Number of sets is wrong");
        assert_eq!(rpp_params.n_colors, 128, "Number of sets is wrong");
    }
}
