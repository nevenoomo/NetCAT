use super::Address;
use crate::connection::{MemoryConnector, Time};
use rand::distributions::{Distribution, Standard};
use std::io::Result;

pub(super) struct RppConnector<C>(Box<dyn MemoryConnector<Item = C>>);

impl<C> RppConnector<C> {
    pub(super) fn new(conn: Box<dyn MemoryConnector<Item = C>>) -> RppConnector<C> {
        RppConnector(conn)
    }
}

impl<C> RppConnector<C>
where
    Standard: Distribution<C>,
{
    // allocates new way in cache (read for local, write for DDIO)
    #[cfg(not(feature = "local"))]
    pub(super) fn cache(&mut self, x: Address) -> Result<()> {
        self.0.write(x, &rand::random())
    }

    #[cfg(feature = "local")]
    pub(super) fn cache(&mut self, x: Address) -> Result<()> {
        self.0.read(x)?;
        Ok(())
    }

    // alocates cache lines for all iterator values, which might cause eviction
    #[cfg(not(feature = "local"))]
    pub(super) fn evict<I: Iterator<Item = Address>>(&mut self, it: I) -> Result<()> {
        for x in it {
            self.0.write(x, &rand::random())?;
        }

        Ok(())
    }

    #[cfg(feature = "local")]
    pub(super) fn evict<I: Iterator<Item = Address>>(&mut self, it: I) -> Result<()> {
        for x in it {
            self.0.read(x)?;
        }

        Ok(())
    }

    // -----------------------------PROXIES----------------------------

    pub(super) fn time(&mut self, addr: Address) -> Result<Time> {
        self.0.read_timed(addr).map(|(_, t)| t)
    }

    pub(super) fn allocate(&mut self, size: usize) {
        self.0.allocate(size)
    }
}

impl<C> From<Box<dyn MemoryConnector<Item = C>>> for RppConnector<C> {
    fn from(conn: Box<dyn MemoryConnector<Item = C>>) -> Self {
        Self::new(conn)
    }
}
