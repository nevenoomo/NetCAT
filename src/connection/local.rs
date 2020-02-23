use crate::connection::{MemoryConnector, Time};
use std::io::Result;

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

    fn read(&self, ofs: usize) -> Result<Self::Item>{
        Ok(self.buf[ofs] as u64)
    }

    fn write(&mut self, ofs: usize) -> Result<()>{
        self.buf[ofs] = 123; // does not matter what to write

        Ok(())
    }

    fn read_timed(&self, ofs: usize) -> Result<Time>{
        let now = std::time::SystemTime::now();
        self.read(ofs);


        Ok(now.elapsed().unwrap().as_nanos() as i128)
    }

    fn write_timed(&mut self, ofs: usize) -> Result<Time>{
        let now = std::time::SystemTime::now();
        self.write(ofs);

        Ok(now.elapsed().unwrap().as_nanos() as i128)
    }
}