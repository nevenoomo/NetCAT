use crate::connection::{MemoryConnector, Time};
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

    fn allocate(&mut self, size: usize) {
        self.buf = vec![0u8; size];
    }

    fn read(&self, ofs: usize) -> Result<Self::Item> {
        Ok(self.buf[ofs])
    }

    fn write(&mut self, ofs: usize, what: &Self::Item) -> Result<()> {
        self.buf[ofs] = *what;

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

    fn write_timed(&mut self, ofs: usize, _what: &Self::Item) -> Result<Time> {
        let now = std::time::Instant::now();
        self.write(ofs, &0)?;
        let elapsed = now
            .elapsed()
            .as_nanos()
            .try_into()
            .unwrap_or(Time::max_value());

        Ok(elapsed)
    }

    fn read_buf(&self, ofs: usize, buf: &mut [Self::Item]) -> Result<usize> {
        buf.copy_from_slice(&self.buf[ofs..ofs + buf.len()]);

        Ok(buf.len())
    }

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

    fn write_buf(&mut self, ofs: usize, buf: &[Self::Item]) -> Result<usize> {
        (&mut self.buf[ofs..ofs + buf.len()]).copy_from_slice(buf);

        Ok(buf.len())
    }

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
