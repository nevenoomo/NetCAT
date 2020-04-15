use crate::connection::{MemoryConnector, CacheConnector, Time, Address};
use std::convert::TryInto;
use std::io::Result;

#[derive(Default)]
pub struct LocalMemoryConnector {
    buf: Vec<u8>,
}

impl LocalMemoryConnector {
    pub fn new() -> LocalMemoryConnector {
        LocalMemoryConnector { buf: Vec::new() }
    }
}

#[cfg(feature = "clflush")]
pub fn flush<T>(buf: &[T]) {
    for v in buf.iter() {
        let p = (v as *const T).cast();
        unsafe {
            core::arch::x86_64::_mm_clflush(p);
        }
    }
}

impl MemoryConnector for LocalMemoryConnector {
    type Item = u8;

    #[inline(always)]
    fn allocate(&mut self, size: usize) {
        self.buf = vec![1u8; size];
    }

    #[inline(always)]
    fn read(&self, ofs: usize) -> Result<Self::Item> {
        Ok(self.buf[ofs])
    }

    #[inline(always)]
    fn write(&mut self, ofs: usize, what: &Self::Item) -> Result<()> {
        self.buf[ofs] = *what;

        Ok(())
    }

    #[inline(always)]
    fn read_timed(&self, ofs: usize) -> Result<(Self::Item, Time)> {
        let now = std::time::Instant::now();
        let res = self.read(ofs)?;
        let elapsed = now
            .elapsed()
            .as_nanos()
            .try_into()
            .unwrap_or(Time::max_value());
        Ok((res, elapsed))
    }

    #[inline(always)]
    fn write_timed(&mut self, ofs: usize, what: &Self::Item) -> Result<Time> {
        let now = std::time::Instant::now();
        self.write(ofs, what)?;
        let elapsed = now
            .elapsed()
            .as_nanos()
            .try_into()
            .unwrap_or(Time::max_value());

        Ok(elapsed)
    }

    #[inline(always)]
    fn read_buf(&self, ofs: usize, buf: &mut [Self::Item]) -> Result<usize> {
        buf.copy_from_slice(&self.buf[ofs..ofs + buf.len()]);

        Ok(buf.len())
    }

    #[inline(always)]
    fn read_buf_timed(&self, ofs: usize, buf: &mut [Self::Item]) -> Result<(usize, Time)> {
        let now = std::time::Instant::now();
        let n = self.read_buf(ofs, buf)?;
        let elapsed = now
            .elapsed()
            .as_nanos()
            .try_into()
            .unwrap_or(Time::max_value());

        Ok((n, elapsed))
    }

    #[inline(always)]
    fn write_buf(&mut self, ofs: usize, buf: &[Self::Item]) -> Result<usize> {
        (&mut self.buf[ofs..ofs + buf.len()]).copy_from_slice(buf);

        Ok(buf.len())
    }

    #[inline(always)]
    fn write_buf_timed(&mut self, ofs: usize, buf: &[Self::Item]) -> Result<(usize, Time)> {
        let now = std::time::Instant::now();
        let n = self.write_buf(ofs, buf)?;
        let elapsed = now
            .elapsed()
            .as_nanos()
            .try_into()
            .unwrap_or(Time::max_value());

        Ok((n, elapsed))
    }
}

impl CacheConnector for LocalMemoryConnector {
    type Item = u8;

    #[inline(always)]
    fn cache(&mut self, addr: usize) -> Result<()> {
        self.read(addr)?;
        Ok(())
    } 

    #[inline(always)]
    fn time_access(&mut self, addr: Address) -> Result<Time> {
        let now = std::time::Instant::now();
        self.read(addr)?;
        let elapsed = now
            .elapsed()
            .as_nanos()
            .try_into()
            .unwrap_or(Time::max_value());
        
        Ok(elapsed)
    }

    #[inline(always)]
    fn reserve(&mut self, size: usize) {
        self.allocate(size)
    }
}