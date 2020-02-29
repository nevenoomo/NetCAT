//! # Connection
//! This module provides a number of uniform interfaces for different connections.
pub mod local;
pub mod rdma;
pub type Time = u128;

use std::io::Result;

/// # MemoryConnector
/// Interface for accessing memory depending on the offset.
pub trait MemoryConnector {
    type Item;

    /// Allocate buffer with a given size
    fn allocate(&mut self, size: usize);
    
    /// Read memory region from the given offset. If successful, then item is returned, else - the error message is returned.
    fn read(&self, ofs: usize) -> Result<Self::Item>;

    /// Read memory region from the given offset. If successful, then latency is returned, else - the error message is returned.
    fn read_timed(&self, ofs: usize) -> Result<Time>;

    /// Write memory region from the given offset. If successful, then nothing is returned, else - the error message is returned.
    fn write(&mut self, ofs: usize, what: &Self::Item) -> Result<()>; 

    /// Write memory region from the given offset. If successful, then latency is returned, else - the error message is returned.
    fn write_timed(&mut self, ofs: usize, what: &Self::Item) -> Result<Time>;
}