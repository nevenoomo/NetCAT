use crate::connection::{Address, CacheConnector, MemoryConnector, Time};
use std::alloc;
use std::convert::TryInto;
use std::io::Result;

pub struct LocalMemoryConnector {
    buf: *mut u8,
}

impl LocalMemoryConnector {
    pub fn new() -> LocalMemoryConnector {
        LocalMemoryConnector {
            buf: std::ptr::null_mut(),
        }
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

    fn allocate(&mut self, size: usize) {
        let layout = alloc::Layout::from_size_align(size, 4096).unwrap();

        self.buf = unsafe { alloc::alloc(layout) };
    }

    // here inline(never) is used to fool prefetcher. Otherwise the buffer will get cached
    // and the timing won't work
    #[inline(never)]
    fn read(&self, ofs: usize) -> Result<Self::Item> {
        Ok(unsafe { *self.buf.offset(ofs as isize) })
    }

    #[inline(never)]
    fn write(&mut self, ofs: usize, what: &Self::Item) -> Result<()> {
        unsafe { *self.buf.offset(ofs as isize) = *what };

        Ok(())
    }

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

    #[inline(never)]
    fn cache(&mut self, addr: usize) -> Result<()> {
        self.read(addr)?;
        Ok(())
    }

    #[inline(never)]
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

    #[inline(never)]
    fn cache_all<I: Iterator<Item = Address>>(&mut self, mut addrs: I) -> Result<()> {
        addrs.try_for_each(|addr| self.cache(addr))
    }

    fn reserve(&mut self, size: usize) {
        self.allocate(size)
    }
}
