//! # Connection
//! This module provides a number of uniform interfaces for different connections.
pub mod local;
pub mod rdma;
pub type Time = u64;

use std::io::Result;

/// # MemoryConnector
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

    /// Read memory region from the given offset into a given buffer. If successful, then then number of bytes read is returned, else - the `error` is returned.
    fn read_buf(&self, ofs: usize, buf: &mut [Self::Item]) -> Result<usize>;

    /// Read memory region from the given offset into a given buffer. If successful, then then number of bytes read latency is returned, else - the `error` is returned.
    fn read_buf_timed(&self, ofs: usize, buf: &mut [Self::Item]) -> Result<(usize, Time)>;

    /// Write provided buffer to the memory region at the given offset. If successful, then number of written bytes is returned, else - the `error` is returned.
    fn write_buf(&mut self, ofs: usize, buf: &[Self::Item]) -> Result<usize>;

    /// Write provided buffer to the memory region at the given offset. If successful, then the number of written bytes latency is returned, else - the `error` is returned.
    fn write_buf_timed(&mut self, ofs: usize, buf: &[Self::Item]) -> Result<(usize, Time)>;
}
