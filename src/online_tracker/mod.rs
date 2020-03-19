use crate::connection::rdma;
use crate::rpp;
use std::collections::HashMap;
use std::io::Result;
use std::net::ToSocketAddrs;

pub const REPEATINGS: usize = 8;

pub struct OnlineTracker {
    rpp: rpp::Rpp,
}

impl OnlineTracker {
    pub fn new<A: ToSocketAddrs>(addr: A) -> OnlineTracker {
        let conn = Box::new(rdma::RdmaServerConnector::new(addr));
        let rpp = rpp::Rpp::new(conn);

        OnlineTracker { rpp }
    }

    pub fn locate_rx(&mut self) -> Result<ColorKey> {
        let color_len = self.rpp.colors_len();
        let mut patterns = HashMap::with_capacity(color_len);

        for (key, color) in self.rpp.colors() {
            let mut pattern = Vec::with_capacity(color.len());
            for (i, set) in color.iter().enumerate() {
                self.rpp.prime(set);

                self.set_packets();

                if self.rpp.probe(set) {
                    pattern.push(i);
                }
            }
            patterns.insert(key, pattern);
        }

        let color_key = Self::find_pattern()?;

        Ok(color_key)
    }
}
