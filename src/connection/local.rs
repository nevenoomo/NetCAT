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
    type Item = u8;

    fn allocate(&mut self, size: usize){
        self.buf = vec![0u8; size];
    }

    fn read(&self, ofs: usize) -> Result<Self::Item>{
        Ok(self.buf[ofs])
    }

    fn write(&mut self, ofs: usize, what: &Self::Item) -> Result<()>{
        self.buf[ofs] = *what;

        Ok(())
    }

    fn read_timed(&self, ofs: usize) -> Result<(Self::Item, Time)>{
        let now = std::time::SystemTime::now();
        let res = self.read(ofs)?;
        let elapsed = now.elapsed().unwrap().as_nanos();

        Ok((res, elapsed))
    }

    fn write_timed(&mut self, ofs: usize, _what: &Self::Item) -> Result<Time>{
        let now = std::time::SystemTime::now();
        self.write(ofs, &0)?;
        let elapsed = now.elapsed().unwrap().as_nanos();

        Ok(elapsed)
    }

    fn read_buf(&self, ofs: usize, buf: &mut [Self::Item]) -> Result<usize>{
        buf.copy_from_slice(&self.buf[..buf.len()]);

        Ok(buf.len())
    }

    fn read_buf_timed(&self, ofs: usize, buf: &mut [Self::Item]) -> Result<(usize, Time)>{
        let now = std::time::SystemTime::now();
        let n = self.read_buf(ofs, buf)?;
        let elapsed = now.elapsed().unwrap().as_nanos();

        Ok((n, elapsed))
    }

    fn write_buf(&mut self, ofs: usize, buf: &[Self::Item]) -> Result<usize>{
        (&mut self.buf[..buf.len()]).copy_from_slice(buf);

        Ok(buf.len())
    }

    fn write_buf_timed(&mut self, ofs: usize, buf: &[Self::Item]) -> Result<(usize, Time)>{
        let now = std::time::SystemTime::now();
        let n = self.write_buf(ofs, buf)?;
        let elapsed = now.elapsed().unwrap().as_nanos();

        Ok((n, elapsed))
    }
}