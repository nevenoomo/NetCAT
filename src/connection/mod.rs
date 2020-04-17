//! # Connection
//! This module provides a number of uniform interfaces for different connections.
pub mod local;
pub mod rdma;
use std::io::Result;

pub type Time = u64;
pub type Address = usize;

// TODO maybe use this macro
// #[macro_export]
// macro_rules! timed {
//     ($(s:stmt)*) => {{
//         use std::time::Instant;
//         let now = Instant::now();
//         $(
//             $s
//         )*
//         now
//             .elapsed()
//             .as_nanos()
//             .try_into()
//             .unwrap_or(Time::max_value())
//     }};
// }

/// Interface for accessing memory depending on the offset.
pub trait MemoryConnector {
    type Item;

    /// Allocate buffer with a given size
    fn allocate(&mut self, size: usize);
    /// Read single item from the given offset. If successful, then item is returned, else - the `error` is returned.
    fn read(&self, ofs: usize) -> Result<Self::Item>;

    /// Read single item from the given offset. If successful, then item and latency are returned, else - the `error` is returned.
    fn read_timed(&self, ofs: usize) -> Result<(Self::Item, Time)>;

    /// Write single item to the given offset. If successful, then nothing is returned, else - the `error` is returned.
    fn write(&mut self, ofs: usize, what: &Self::Item) -> Result<()>;

    /// Write single item to the given offset. If successful, then latency is returned, else - the `error` is returned.
    fn write_timed(&mut self, ofs: usize, what: &Self::Item) -> Result<Time>;
}

/// Interface for manipulating processor cache
pub trait CacheConnector {
    /// A memory item, which will be used
    type Item;

    /// Caches a memory item at the given address
    fn cache(&mut self, addr: Address) -> Result<()>;

    #[inline(always)]
    /// Caches all given addresses
    fn cache_all<I: Iterator<Item = Address>>(&mut self, mut addrs: I) -> Result<()> {
        addrs.try_for_each(|addr| self.cache(addr))
    }

    /// Times access to the given address
    fn time_access(&mut self, addr: Address) -> Result<Time>;

    /// Reserves memory to be used for operations
    fn reserve(&mut self, size: usize);
}
