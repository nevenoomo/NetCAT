//! # RDMA
//! This module is responsible for RDMA connections and maintaining overall RDMA state
#![allow(dead_code)]
use crate::connection::{MemoryConnector, Time};
use bincode;
use ibverbs;
use std::io::{Error, ErrorKind, Result, Write};
use std::mem;
use std::net;
use std::sync::Arc;

const LOCAL_BUF_SIZE: usize = 4096;
pub type RdmaPrimitive = u8;

struct InitializedQp {
    qp: ibverbs::QueuePair,
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
    ctx: Arc<ibverbs::Context>,
    cq: ibverbs::CompletionQueue,
    pd: ibverbs::ProtectionDomain,
    mr: ibverbs::MemoryRegion<RdmaPrimitive>,
    iqp: InitializedQp,
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
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("ERROR: aquiring RDMA context failed: {}", e),
                ))
            }
        }
    }

    fn aquire_pd(ctx: Arc<ibverbs::Context>) -> Result<ibverbs::ProtectionDomain> {
        // Create a protection domain
        match ctx.alloc_pd() {
            Ok(pd) => Ok(pd),
            Err(_) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    "ERROR: allocating Protection Domain failed",
                ))
            }
        }
    }

    fn aquire_cq(ctx: Arc<ibverbs::Context>) -> Result<ibverbs::CompletionQueue> {
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
            Ok(cq) => Ok(cq),
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("ERROR: creating Completion Queue failed: {}", e),
                ))
            }
        }
    }

    fn register_mr(pd: &ibverbs::ProtectionDomain) -> Result<ibverbs::MemoryRegion<RdmaPrimitive>> {
        // here we need to allocate memory and register a memory region just for RDMA porposes
        match pd.allocate::<RdmaPrimitive>(LOCAL_BUF_SIZE) {
            Ok(mr) => Ok(mr),
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("ERROR: registering Memory Region failed: {}", e),
                ))
            }
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
            let qp_builder = pd.create_qp(cq, cq, ibverbs::ibv_qp_type::IBV_QPT_RC);
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
            Ok(qp) => Ok(InitializedQp { qp, rkey, raddr }),
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("ERROR: failed to handshake: {}", e),
                ))
            }
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
        // UGLY: This could be done with one line as
        // bincode can serialize into a writer (which a stream is), but it would take ownership
        // of stream. `try_clone()` may be used.
        let mut sent = 0;
        loop {
            match stream.write(&ser_msg[sent..]) {
                Ok(n) => {
                    sent += n;
                    if sent == ser_msg.len() {
                        break;
                    }
                }
                Err(e) => panic!("ERROR: failed to transmit serealized message: {}", e),
            }
        }

        // This looks so much better.
        let rmsg: ibverbs::EndpointMsg = match bincode::deserialize_from(stream) {
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

    fn setup_ib<A: net::ToSocketAddrs>(&mut self, addr: A) -> Result<()> {
        Self::fork_init()?;
        self.ctx = Self::aquire_ctx()?;
        self.pd = Self::aquire_pd(self.ctx.clone())?;
        self.cq = Self::aquire_cq(self.ctx.clone())?;
        self.mr = Self::register_mr(&self.pd)?;
        let lkey = self.mr.rkey();
        let laddr = ibverbs::RemoteAddr((&self.mr[0] as *const RdmaPrimitive) as u64);
        self.iqp = Self::setup_qp(addr, &self.pd, &self.cq, lkey, laddr)?;

        Ok(())
    }

    /// Creates a new `RdmaConnector` to interact with a RDMA peer. The first available
    /// RDMA device is used.
    /// ## Panics
    /// Panics if there is no support for RDMA in the kernel, no RDMA devices where found,
    /// or if a device cannot be opened
    pub fn new<A: net::ToSocketAddrs>(addr: A) -> RdmaServerConnector {
        #[allow(invalid_value)]
        let mut rdma_con: RdmaServerConnector = unsafe { mem::MaybeUninit::uninit().assume_init() };

        rdma_con.setup_ib(addr).unwrap_or_else(|e| panic!("{}", e));

        rdma_con
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
        // TODO maybe a flag should be placed for not using this function multiple times?
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
}

impl MemoryConnector for RdmaServerConnector {
    type Item = RdmaPrimitive;

    /// Allocate buffer with a given size
    fn allocate(&mut self, size: usize) {}

    /// Read memory region from the given offset. If successful, then item is returned, else - the error message is returned.
    fn read(&self, ofs: usize) -> Result<Self::Item> {
        Ok(Default::default())
    }

    /// Read memory region from the given offset. If successful, then latency is returned, else - the error message is returned.
    fn read_timed(&self, ofs: usize) -> Result<Time> {
        Ok(Default::default())
    }

    /// Write memory region from the given offset. If successful, then nothing is returned, else - the error message is returned.
    fn write(&mut self, ofs: usize) -> Result<()> {
        Ok(Default::default())
    }

    /// Write memory region from the given offset. If successful, then latency is returned, else - the error message is returned.
    fn write_timed(&mut self, ofs: usize) -> Result<Time> {
        Ok(Default::default())
    }
}
