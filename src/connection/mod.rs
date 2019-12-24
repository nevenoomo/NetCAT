//! # Connection
//! This module provides a number of uniform interfaces for different connections.
pub type Time = i128;


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
    fn write(&mut self, ofs: usize) -> Result<(), String>; 

    /// Write memory region from the given offset. If successful, then latency is returned, else - the error message is returned.
    fn write_timed(&mut self, ofs: usize) -> Result<Time, String>;
}

pub struct LocalMemoryConnector {
    buf: Vec<u8>,
}

impl LocalMemoryConnector {
    pub fn new() -> LocalMemoryConnector {
        LocalMemoryConnector{
            buf: Vec::new()
        }
    }
}

impl MemoryConnector for LocalMemoryConnector {
    type Item = u64;

    fn allocate(&mut self, size: usize){
        self.buf = vec![0u8; size];
    }

    fn read(&self, ofs: usize) -> Result<Self::Item, String>{
        Ok(self.buf[ofs] as u64)
    }

    fn write(&mut self, ofs: usize) -> Result<(), String>{
        self.buf[ofs] = 123; // does not matter what to write

        Ok(())
    }

    fn read_timed(&self, ofs: usize) -> Result<Time, String>{
        let now = std::time::SystemTime::now();
        self.read(ofs);


        Ok(now.elapsed().unwrap().as_nanos() as i128)
    }

    fn write_timed(&mut self, ofs: usize) -> Result<Time, String>{
        let now = std::time::SystemTime::now();
        self.write(ofs);

        Ok(now.elapsed().unwrap().as_nanos() as i128)
    }
}