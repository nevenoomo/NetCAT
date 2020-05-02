pub const PAGE_SIZE: usize = 4096; // 4 KiB

pub static XEON_E5: CacheParams = CacheParams {
    bytes_per_line: 64,
    lines_per_set: 20,
    reachable_lines: 20,
    cache_size: 20_971_520, // 20 MiB
    addr_num: 5000,
};

pub static XEON_E5_DDIO: CacheParams = CacheParams {
    bytes_per_line: 64,
    lines_per_set: 20,
    reachable_lines: 2,
    cache_size: 20_971_520, // 20 MiB
    addr_num: 5000,
};

pub static CORE_I7: CacheParams = CacheParams {
    bytes_per_line: 64,
    lines_per_set: 12,
    reachable_lines: 12,
    cache_size: 6_291_456, // 6 MiB
    addr_num: 5000,
};

// This is for testing, i7 has no DDIO
pub static CORE_I7_DDIO: CacheParams = CacheParams {
    bytes_per_line: 64,
    lines_per_set: 12,
    reachable_lines: 2,
    cache_size: 6_291_456, // 6 MiB
    addr_num: 5000,
};

pub static XEON_PLATINUM: CacheParams = CacheParams {
    bytes_per_line: 64,
    lines_per_set: 11,
    reachable_lines: 11,
    cache_size: 34_603_008, // 33 MiB
    addr_num: 5000,
};

pub static XEON_PLATINUM_DDIO: CacheParams = CacheParams {
    bytes_per_line: 64,
    lines_per_set: 11,
    reachable_lines: 2,
    cache_size: 34_603_008, // 33 MiB
    addr_num: 5000,
};

/// Parameters for Remote PRIME+PROBE.
/// Describes the last level cache of the targeted prosessor
#[derive(Clone, Copy)]
pub struct CacheParams {
    bytes_per_line: usize,
    lines_per_set: usize,
    reachable_lines: usize,
    cache_size: usize,
    addr_num: usize,
}

impl CacheParams {
    /// `addr_num` - number of adresses needed for successfull building of cache sets
    pub fn new(bytes_per_line: usize, lines_per_set: usize, reachable_lines: usize, cache_size: usize, addr_num: usize) -> CacheParams {
        CacheParams {
            bytes_per_line,
            lines_per_set,
            reachable_lines,
            cache_size,
            addr_num,
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
    // number of lines per eviction set
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
        p.n_lines = cp.reachable_lines;

        // total sets in cache
        p.n_sets = cp.cache_size / (cp.lines_per_set * cp.bytes_per_line);

        // size of page aligned buffer
        p.v_buf = cp.addr_num * PAGE_SIZE;

        // each 64 byte on one page is mapped to different cache sets
        p.n_sets_per_page = PAGE_SIZE / cp.bytes_per_line;

        // how many pages may reside in cache and not have cache sets intersect
        p.n_colors = p.n_sets / p.n_sets_per_page;

        p
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn param_test_i7() {
        let cache_params = CORE_I7;
        let rpp_params: RppParams = cache_params.into();

        assert_eq!(rpp_params.n_sets, 8192, "Number of sets is wrong");
        assert_eq!(rpp_params.n_sets_per_page, 64, "Number of sets is wrong");
        assert_eq!(rpp_params.n_colors, 128, "Number of sets is wrong");
    }

    #[test]
    fn param_test_e5() {
        let cache_params = XEON_E5;
        let rpp_params: RppParams = cache_params.into();

        assert_eq!(rpp_params.n_sets, 16384, "Number of sets is wrong");
        assert_eq!(rpp_params.n_sets_per_page, 64, "Number of sets is wrong");
        assert_eq!(rpp_params.n_colors, 256, "Number of sets is wrong");
    }

    #[test]
    fn param_test_e5_ddio() {
        let cache_params = XEON_E5_DDIO;
        let rpp_params: RppParams = cache_params.into();

        assert_eq!(rpp_params.n_sets, 16384, "Number of sets is wrong");
        assert_eq!(rpp_params.n_sets_per_page, 64, "Number of sets is wrong");
        assert_eq!(rpp_params.n_colors, 256, "Number of sets is wrong");
    }
}
