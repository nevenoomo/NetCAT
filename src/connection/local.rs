use crate::connection::{Address, CacheConnector, MemoryConnector, Time};
use std::convert::TryInto;
use std::io::Result;
use std::cmp::max;

#[derive(Default)]
pub struct LocalMemoryConnector {
    buf: Vec<Vec<u8>>,
}

impl LocalMemoryConnector {
    pub fn new() -> LocalMemoryConnector {
        LocalMemoryConnector { buf: Vec::new() }
    }
}

pub fn flush<T>(p: *const T) {
    let p = p as *const u8;
    unsafe {
        core::arch::x86_64::_mm_clflush(p);
    }
}

impl MemoryConnector for LocalMemoryConnector {
    type Item = u8;

    #[inline(always)]
    fn allocate(&mut self, size: usize) {
        self.buf = vec![vec![1u8; 4096]; max(1, size >> 12)];
    }

    #[inline(always)]
    fn read(&self, ofs: usize) -> Result<Self::Item> {
        Ok(self.buf[ofs >> 12][ofs & 0xfff])
    }

    #[inline(always)]
    fn write(&mut self, ofs: usize, what: &Self::Item) -> Result<()> {
        self.buf[ofs >> 12][ofs & 0xfff] = *what;

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
