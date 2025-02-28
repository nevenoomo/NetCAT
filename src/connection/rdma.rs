//! # RDMA
//! This module is responsible for RDMA connections and maintaining overall RDMA state
#![allow(dead_code)]
use crate::connection::{Address, CacheConnector, MemoryConnector, PacketSender, Time};
use std::convert::TryInto;
use std::io::{Error, ErrorKind, Result};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
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
    mr: ibverbs::MemoryRegion<RdmaPrimitive>,
    pd: Arc<ibverbs::ProtectionDomain>,
    ctx: Arc<ibverbs::Context>,
}

impl RdmaServerConnector {
    fn aquire_ctx() -> Result<Arc<ibverbs::Context>> {
        let dev_list = Self::get_devs()?;

        // Get the first device
        let dev = dev_list
            .get(0)
            .ok_or_else(|| Error::new(ErrorKind::Other, "ERROR: No RDMA devices in list"))?;

        // Here the device is opened. Port (1) and GID are queried automaticaly
        dev.open().map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("ERROR: aquiring RDMA context failed: {}", e),
            )
        })
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
        let dev_attr = ctx.query_device().map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("ERROR: cannot get device attributes: {}", e),
            )
        })?;

        // Create Complition Queue
        match ctx.create_cq(dev_attr.max_cqe, 0) {
            Ok(cq) => Ok(Arc::new(cq)),
            Err(e) => Err(Error::new(
                ErrorKind::Other,
                format!("ERROR: creating Completion Queue failed: {}", e),
            )),
        }
    }

    fn register_mr(pd: &ibverbs::ProtectionDomain) -> Result<ibverbs::MemoryRegion<RdmaPrimitive>> {
        // here we need to allocate memory and register a memory region just for RDMA porposes
        pd.allocate::<RdmaPrimitive>(LOCAL_BUF_SIZE).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("ERROR: registering Memory Region failed: {}", e),
            )
        })
    }

    fn setup_qp<'a, A: ToSocketAddrs>(
        addr: A,
        pd: &'a ibverbs::ProtectionDomain,
        cq: &'a ibverbs::CompletionQueue,
        lkey: ibverbs::RemoteKey,
        laddr: ibverbs::RemoteAddr,
    ) -> Result<InitializedQp> {
        let qp_init = {
            let qp_builder = pd.create_qp(cq, cq, ibverbs::ibv_qp_type::IBV_QPT_RC); // client access flags default to ALLOW_LOCAL_WRITES which is ok
            qp_builder.build().map_err(|e| {
                Error::new(
                    ErrorKind::Other,
                    format!("ERROR: failed to initialize Queue Pair: {}", e),
                )
            })?
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

    fn xchg_endp<A: ToSocketAddrs>(
        addr: A,
        endp: ibverbs::QueuePairEndpoint,
        lkey: ibverbs::RemoteKey,
        laddr: ibverbs::RemoteAddr,
    ) -> Result<ibverbs::EndpointMsg> {
        let mut msg = ibverbs::EndpointMsg::from(endp);
        msg.rkey = lkey;
        msg.raddr = laddr;

        let mut stream = TcpStream::connect(addr).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("ERROR: failed to connect to server: {}", e),
            )
        })?;

        // Sending info for RDMA handshake over TcpStream;
        bincode::serialize_into(&mut stream, &msg).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("ERROR: failed to transmit serealized message: {}", e),
            )
        })?;

        // Recieving and desirializing info from the server
        let rmsg: ibverbs::EndpointMsg = bincode::deserialize_from(&mut stream).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("ERROR: failed to recieve data: {}", e),
            )
        })?;

        Ok(rmsg)
    }

    fn setup_ib<A: ToSocketAddrs>(addr: A) -> Result<RdmaServerConnector> {
        if !unsafe { FORK_INITED } {
            Self::fork_init()?;
            unsafe { FORK_INITED = true };
        }
        let ctx = Self::aquire_ctx()?;
        let pd = Self::aquire_pd(ctx.clone())?;
        let cq = Self::aquire_cq(ctx.clone())?;
        let mr = Self::register_mr(&pd)?;
        let lkey = mr.rkey();
        let laddr = ibverbs::RemoteAddr((&mr[0..]).as_ptr() as u64);
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
    pub fn new<A: ToSocketAddrs>(addr: A) -> Result<RdmaServerConnector> {
        Self::setup_ib(addr)
    }

    fn get_devs() -> Result<ibverbs::DeviceList> {
        ibverbs::devices().map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("ERROR: cannot get device list: {}", e),
            )
        })
    }

    fn fork_init() -> Result<()> {
        // in case we use fork latter

        if unsafe { ibverbs::ffi::ibv_fork_init() } != 0 {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "ERROR: could not initialize fork: {}",
                    Error::last_os_error()
                ),
            ));
        }

        Ok(())
    }

    #[inline(always)]
    fn post_read(&self, addr: u64) -> Result<()> {
        unsafe {
            self.iqp
                .qp
                .post_read_single(&self.mr, addr, self.iqp.rkey.0, WR_ID, true)
        }
    }

    #[inline(always)]
    fn post_write(&self, addr: u64) -> Result<()> {
        unsafe {
            self.iqp
                .qp
                .post_write_single(&self.mr, addr, self.iqp.rkey.0, WR_ID, true)
        }
    }

    #[inline(always)]
    fn post_read_buf(&self, addr: u64, n: usize) -> Result<()> {
        unsafe {
            self.iqp
                .qp
                .post_read_buf(&self.mr, n, addr, self.iqp.rkey.0, WR_ID, true)
        }
    }

    #[inline(always)]
    fn post_write_buf(&self, addr: u64, n: usize) -> Result<()> {
        unsafe {
            self.iqp
                .qp
                .post_write_buf(&self.mr, n, addr, self.iqp.rkey.0, WR_ID, true)
        }
    }

    #[inline(always)]
    fn poll_cq_is_done(&self, compl: &mut [ibverbs::ffi::ibv_wc]) -> Result<()> {
        loop {
            let completed = self.cq.poll(compl).expect("ERROR: Could not poll CQ.");
            if completed.is_empty() {
                continue;
            }
            if completed.iter().any(|wc| wc.wr_id() == WR_ID) {
                return Ok(());
            }
        }
    }

    #[inline(always)]
    fn write_from_mr(&mut self, addr: Address) -> Result<()> {
        let mut completions = [ibverbs::ibv_wc::default()];
        self.post_write(self.iqp.raddr.0 + (addr as u64))?;
        self.poll_cq_is_done(&mut completions)?;

        Ok(())
    }
}

impl MemoryConnector for RdmaServerConnector {
    type Item = RdmaPrimitive;

    #[inline(always)]
    fn allocate(&mut self, _size: usize) {}

    #[inline(always)]
    fn read(&self, ofs: usize) -> Result<Self::Item> {
        let mut completions = [ibverbs::ibv_wc::default()];
        self.post_read(self.iqp.raddr.0 + (ofs as u64))?;
        self.poll_cq_is_done(&mut completions)?;

        Ok(self.mr[0])
    }

    #[inline(always)]
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

    #[inline(always)]
    fn write(&mut self, addr: usize, what: &Self::Item) -> Result<()> {
        // the desired value is taken from the memory region
        self.mr[0] = *what;
        self.write_from_mr(addr)
    }

    #[inline(always)]
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
}

impl CacheConnector for RdmaServerConnector {
    type Item = RdmaPrimitive;

    #[inline(always)]
    fn reserve(&mut self, _size: usize) {}

    #[inline(always)]
    fn cache(&mut self, addr: Address) -> Result<()> {
        // we do not really care of the contents of the MR
        // as the writen value will not be used
        self.write_from_mr(addr).map_err(|e| {
            Error::new(
                ErrorKind::NotConnected,
                format!("ERROR: Could not cache address: {}", e),
            )
        })
    }

    #[inline(always)]
    fn time_access(&mut self, addr: Address) -> Result<Time> {
        self.read_timed(addr).map(|(_, t)| t).map_err(|e| {
            Error::new(
                ErrorKind::NotConnected,
                format!("ERROR: Could not time access: {}", e),
            )
        })
    }
}

pub struct RemotePacketSender {
    sock: UdpSocket,
    sock_addr: SocketAddr,
}

impl RemotePacketSender {
    pub fn new<A: ToSocketAddrs>(addr: A) -> Result<RemotePacketSender> {
        // We do it this way and not by `connection` method be able to send to
        // closed ports (with connection we would get ICMP back and fail next time)
        let sock_addr = addr.to_socket_addrs()?.next().ok_or_else(|| {
            Error::new(ErrorKind::InvalidData, "ERROR: could not resolve address.")
        })?;

        // Allow the machine to automatically choose port for us
        let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| {
            Error::new(
                ErrorKind::AddrNotAvailable,
                format!("ERROR: could not bind to address: {}", e),
            )
        })?;
        // MAYBE set nonblocking

        Ok(RemotePacketSender { sock, sock_addr })
    }
}

impl PacketSender for RemotePacketSender {
    #[inline(always)]
    fn send_packet(&mut self) -> Result<()> {
        self.sock.send_to(&[0], self.sock_addr).map_err(|e| {
            Error::new(
                ErrorKind::NotConnected,
                format!("ERROR: Cannot send packet: {}", e),
            )
        })?;
        Ok(())
    }
}
