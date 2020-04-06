//! # RDMA
//! This module is responsible for RDMA connections and maintaining overall RDMA state
#![allow(dead_code)]
use crate::connection::{MemoryConnector, Time};
use bincode;
use ibverbs;
use std::convert::TryInto;
use std::io::{Error, ErrorKind, Result};
use std::net;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Instant;

const LOCAL_BUF_SIZE: usize = 4096;
const WR_ID: u64 = 12_949_723_411_804_112_106; // some random value
pub type RdmaPrimitive = u8;
static mut FORK_INITED: bool = false;

struct InitializedQp {
    qp: Arc<ibverbs::QueuePair>,
    rkey: ibverbs::RemoteKey,
    raddr: ibverbs::RemoteAddr,
}

impl InitializedQp {
    fn rkey(&self) -> u32 {
        self.rkey.0
    }

    fn raddr(&self) -> u64 {
        self.raddr.0
    }
}

/// Holds all of the context for a single connection
pub struct RdmaServerConnector {
    // field order matters!!! Otherwise will panic on drop.
    iqp: InitializedQp,
    cq: Arc<ibverbs::CompletionQueue>,
    mr: RwLock<ibverbs::MemoryRegion<RdmaPrimitive>>,
    pd: Arc<ibverbs::ProtectionDomain>,
    ctx: Arc<ibverbs::Context>,
}

impl RdmaServerConnector {
    fn aquire_ctx() -> Result<Arc<ibverbs::Context>> {
        let dev_list = Self::get_devs()?;

        // Get the first device
        let dev = match dev_list.get(0) {
            Some(d) => d,
            None => {
                return Err(Error::new(
                    ErrorKind::Other,
                    "ERROR: No RDMA devices in list",
                ))
            }
        };

        // Here the device is opened. Port (1) and GID are queried automaticaly
        match dev.open() {
            Ok(c) => Ok(c),
            Err(e) => Err(Error::new(
                ErrorKind::Other,
                format!("ERROR: aquiring RDMA context failed: {}", e),
            )),
        }
    }

    fn aquire_pd(ctx: Arc<ibverbs::Context>) -> Result<Arc<ibverbs::ProtectionDomain>> {
        // Create a protection domain
        match ctx.alloc_pd() {
            Ok(pd) => Ok(Arc::new(pd)),
            Err(_) => Err(Error::new(
                ErrorKind::Other,
                "ERROR: allocating Protection Domain failed",
            )),
        }
    }

    fn aquire_cq(ctx: Arc<ibverbs::Context>) -> Result<Arc<ibverbs::CompletionQueue>> {
        let dev_attr = match ctx.query_device() {
            Ok(da) => da,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("ERROR: cannot get device attributes: {}", e),
                ))
            }
        };

        // Create Complition Queue
        match ctx.create_cq(dev_attr.max_cqe, 0) {
            Ok(cq) => Ok(Arc::new(cq)),
            Err(e) => Err(Error::new(
                ErrorKind::Other,
                format!("ERROR: creating Completion Queue failed: {}", e),
            )),
        }
    }

    fn register_mr(
        pd: &ibverbs::ProtectionDomain,
    ) -> Result<RwLock<ibverbs::MemoryRegion<RdmaPrimitive>>> {
        // here we need to allocate memory and register a memory region just for RDMA porposes
        match pd.allocate::<RdmaPrimitive>(LOCAL_BUF_SIZE) {
            Ok(mr) => Ok(RwLock::new(mr)),
            Err(e) => Err(Error::new(
                ErrorKind::Other,
                format!("ERROR: registering Memory Region failed: {}", e),
            )),
        }
    }

    fn setup_qp<'a, A: net::ToSocketAddrs>(
        addr: A,
        pd: &'a ibverbs::ProtectionDomain,
        cq: &'a ibverbs::CompletionQueue,
        lkey: ibverbs::RemoteKey,
        laddr: ibverbs::RemoteAddr,
    ) -> Result<InitializedQp> {
        let qp_init = {
            let qp_builder = pd.create_qp(cq, cq, ibverbs::ibv_qp_type::IBV_QPT_RC); // client access flags default to ALLOW_LOCAL_WRITES which is ok
            match qp_builder.build() {
                Ok(qp) => qp,
                Err(e) => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("ERROR: failed to initialize Queue Pair: {}", e),
                    ))
                }
            }
        };

        // This info will be sended to the remote server,
        // but we also expect to get the same insformation set from the server later
        let rmsg = Self::xchg_endp(addr, qp_init.endpoint(), lkey, laddr)?;
        let rkey = rmsg.rkey;
        let raddr = rmsg.raddr;
        let rendpoint = rmsg.into();

        match qp_init.handshake(rendpoint) {
            Ok(qp) => Ok(InitializedQp {
                qp: Arc::new(qp),
                rkey,
                raddr,
            }),
            Err(e) => Err(Error::new(
                ErrorKind::Other,
                format!("ERROR: failed to handshake: {}", e),
            )),
        }
    }

    fn xchg_endp<A: net::ToSocketAddrs>(
        addr: A,
        endp: ibverbs::QueuePairEndpoint,
        lkey: ibverbs::RemoteKey,
        laddr: ibverbs::RemoteAddr,
    ) -> Result<ibverbs::EndpointMsg> {
        let mut msg = ibverbs::EndpointMsg::from(endp);
        msg.rkey = lkey; //self.mr.rkey();
        msg.raddr = laddr;

        let mut stream = match net::TcpStream::connect(addr) {
            Ok(st) => st,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("ERROR: failed to connect to server: {}", e),
                ))
            }
        };

        let ser_msg = match bincode::serialize(&msg) {
            Ok(data) => data,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("ERROR: failed to serialize message: {}", e),
                ))
            }
        };

        // Sending info for RDMA handshake over TcpStream;
        // NOTE using writers in such a way may cause issues. May use .try_clone() instead
        if let Err(e) = bincode::serialize_into(&mut stream, &ser_msg) {
            return Err(Error::new(
                ErrorKind::Other,
                format!("ERROR: failed to transmit serealized message: {}", e),
            ));
        }

        // Recieving and desirializing info from the server
        let rmsg: ibverbs::EndpointMsg = match bincode::deserialize_from(&mut stream) {
            Ok(data) => data,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("ERROR: failed to recieve data: {}", e),
                ))
            }
        };

        Ok(rmsg)
    }

    fn setup_ib<A: net::ToSocketAddrs>(addr: A) -> Result<RdmaServerConnector> {
        if !unsafe { FORK_INITED } {
            Self::fork_init()?;
            unsafe { FORK_INITED = true };
        }
        let ctx = Self::aquire_ctx()?;
        let pd = Self::aquire_pd(ctx.clone())?;
        let cq = Self::aquire_cq(ctx.clone())?;
        let mr = Self::register_mr(&pd)?;
        let lkey = mr.read().unwrap().rkey();
        let laddr = ibverbs::RemoteAddr((&(mr.read().unwrap())[0] as *const RdmaPrimitive) as u64);
        let iqp = Self::setup_qp(addr, &pd, &cq, lkey, laddr)?;

        Ok(RdmaServerConnector {
            ctx,
            pd,
            cq,
            mr,
            iqp,
        })
    }

    /// Creates a new `RdmaConnector` to interact with a RDMA peer. The first available
    /// RDMA device is used.
    /// ## Panics
    /// Panics if there is no support for RDMA in the kernel, no RDMA devices where found,
    /// or if a device cannot be opened
    pub fn new<A: net::ToSocketAddrs>(addr: A) -> RdmaServerConnector {
        Self::setup_ib(addr).unwrap_or_else(|e| panic!("{}", e))
    }

    fn get_devs() -> Result<ibverbs::DeviceList> {
        match ibverbs::devices() {
            Ok(dl) => Ok(dl),
            Err(e) => Err(Error::new(
                ErrorKind::Other,
                format!("ERROR: cannot get device list: {}", e),
            )),
        }
    }

    fn fork_init() -> Result<()> {
        let res;
        // in case we use fork latter
        unsafe {
            res = ibverbs::ffi::ibv_fork_init();
        }

        match res {
            0 => Ok(()),
            _ => Err(Error::new(
                ErrorKind::Other,
                format!(
                    "ERROR: could not initialize fork: {}",
                    Error::last_os_error()
                ),
            )),
        }
    }

    fn post_read(&self, addr: u64) -> Result<()> {
        unsafe {
            self.iqp.qp.post_read_single(
                &self.mr.read().unwrap(),
                addr,
                self.iqp.rkey.0,
                WR_ID,
                true,
            )
        }
    }

    fn post_write(&self, addr: u64) -> Result<()> {
        unsafe {
            self.iqp.qp.post_write_single(
                &self.mr.read().unwrap(),
                addr,
                self.iqp.rkey.0,
                WR_ID,
                true,
            )
        }
    }

    fn post_read_buf(&self, addr: u64, n: usize) -> Result<()> {
        unsafe {
            self.iqp.qp.post_read_buf(
                &self.mr.read().unwrap(),
                n,
                addr,
                self.iqp.rkey.0,
                WR_ID,
                true,
            )
        }
    }

    fn post_write_buf(&self, addr: u64, n: usize) -> Result<()> {
        unsafe {
            self.iqp.qp.post_write_buf(
                &self.mr.read().unwrap(),
                n,
                addr,
                self.iqp.rkey.0,
                WR_ID,
                true,
            )
        }
    }

    fn poll_cq_is_done(&self, compl: &mut [ibverbs::ffi::ibv_wc]) -> Result<()> {
        loop {
            let completed = match self.cq.poll(compl) {
                Ok(o) => o,
                Err(_) => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("ERROR: could not poll CQ: {}", Error::last_os_error()),
                    ))
                }
            };
            if completed.is_empty() {
                continue;
            }
            match completed.iter().find(|wc| wc.wr_id() == WR_ID) {
                Some(_) => return Ok(()),
                None => continue,
            }
        }
    }
}

impl MemoryConnector for RdmaServerConnector {
    type Item = RdmaPrimitive;

    fn allocate(&mut self, _size: usize) {}

    fn read(&self, ofs: usize) -> Result<Self::Item> {
        let mut completions = [ibverbs::ibv_wc::default(); 16];
        self.post_read(self.iqp.raddr.0 + (ofs as u64))?;
        self.poll_cq_is_done(&mut completions)?;

        Ok(self.mr.read().unwrap()[0])
    }

    fn read_timed(&self, ofs: usize) -> Result<(Self::Item, Time)> {
        let now = Instant::now();
        let item = self.read(ofs)?; // allocation time is nearly constant, thus it won't affect measurements
        let elapsed = now
            .elapsed()
            .as_nanos()
            .try_into()
            .unwrap_or(Time::max_value());

        Ok((item, elapsed))
    }

    fn write(&mut self, ofs: usize, what: &Self::Item) -> Result<()> {
        let mut completions = [ibverbs::ibv_wc::default(); 16];
        {
            let mut buf = match self.mr.write() {
                Ok(b) => b,
                Err(_) => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        "ERROR: could not aquire write lock",
                    ))
                }
            };
            buf[0] = *what;
        }

        self.post_write(self.iqp.raddr.0 + (ofs as u64))?;
        self.poll_cq_is_done(&mut completions)?;

        Ok(())
    }

    fn write_timed(&mut self, ofs: usize, what: &Self::Item) -> Result<Time> {
        let now = Instant::now();
        self.write(ofs, what)?;
        let elapsed = now
            .elapsed()
            .as_nanos()
            .try_into()
            .unwrap_or(Time::max_value());

        Ok(elapsed)
    }

    fn read_buf(&self, ofs: usize, buf: &mut [Self::Item]) -> Result<usize> {
        let mut completions = [ibverbs::ibv_wc::default(); 16];

        self.post_read_buf(self.iqp.raddr.0 + (ofs as u64), buf.len())?;
        self.poll_cq_is_done(&mut completions)?;

        let src = self.mr.read().unwrap();
        buf.copy_from_slice(&src[..buf.len()]);

        Ok(buf.len())
    }

    fn read_buf_timed(&self, ofs: usize, buf: &mut [Self::Item]) -> Result<(usize, Time)> {
        let now = Instant::now();
        let n = self.read_buf(ofs, buf)?; // allocation time is nearly constant, thus it won't affect measurements
        let elapsed = now
            .elapsed()
            .as_nanos()
            .try_into()
            .unwrap_or(Time::max_value());

        Ok((n, elapsed))
    }

    fn write_buf(&mut self, ofs: usize, buf: &[Self::Item]) -> Result<usize> {
        let mut completions = [ibverbs::ibv_wc::default(); 16];
        {
            let mut dst = match self.mr.write() {
                Ok(b) => b,
                Err(_) => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        "ERROR: could not aquire write lock",
                    ))
                }
            };
            (&mut dst[..buf.len()]).copy_from_slice(buf);
        }

        self.post_write_buf(self.iqp.raddr.0 + (ofs as u64), buf.len())?;
        self.poll_cq_is_done(&mut completions)?;

        Ok(buf.len())
    }

    fn write_buf_timed(&mut self, ofs: usize, buf: &[Self::Item]) -> Result<(usize, Time)> {
        let now = Instant::now();
        let n = self.write_buf(ofs, buf)?;
        let elapsed = now
            .elapsed()
            .as_nanos()
            .try_into()
            .unwrap_or(Time::max_value());

        Ok((n, elapsed))
    }
}
