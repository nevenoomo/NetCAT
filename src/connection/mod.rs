//! # Connection
//! This module provides a number of uniform interfaces for different connections.

type Time = u64;

/// # MemoryConnector
/// Interface for accessing memory depending on the offset.
pub trait MemoryConnector {
    type Item;

    /// Allocate buffer with a given size
    fn allocate(&mut self, size: usize);
    
    /// Read memory region from the given offset. If successful, then item is returned, else - the error message is returned.
    fn read(&self, ofs: usize) -> Result<Self::Item, String>;

    /// Read memory region from the given offset. If successful, then latency is returned, else - the error message is returned.
    fn read_timed(&self, ofs: usize) -> Result<Time, String>;

    /// Write memory region from the given offset. If successful, then nothing is returned, else - the error message is returned.
    fn write(&self, ofs: usize) -> Result<(), String>; 

    /// Write memory region from the given offset. If successful, then latency is returned, else - the error message is returned.
    fn write_timed(&self, ofs: usize) -> Result<Time, String>;
}