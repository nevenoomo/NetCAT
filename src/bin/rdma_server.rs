use ibverbs;
use std::net;
use std::env;

const BUF_SIZE: usize = 8388608; // 8 MB
const ADDR_KEY: &str = "RDMA_ADDR";

fn get_devs() -> ibverbs::DeviceList {
    ibverbs::devices().unwrap_or_else(|e| {
        panic!("ERROR: aquiring RDMA device list {}", e);
    })
}

fn fork_init() {
    let res;
    // in case we use fork latter
    // TODO maybe a flag should be placed for not using this function multiple times?
    unsafe {
        res = ibverbs::ffi::ibv_fork_init();
    }
    if res != 0 {
        panic!("Last OS error: {:?}", Error::last_os_error());
    }
}

fn main() {
    fork_init();
    let dev_list = get_devs();

    // Get the first device
    let dev = dev_list
        .get(0)
        .unwrap_or_else(|| panic!("ERROR: No RDMA devices in list"));

    // Here the device is opened. Port (1) and GID are queried automaticaly
    let ctx = dev
        .open()
        .unwrap_or_else(|e| panic!("ERROR: aquiring RDMA context failed: {}", e));

    let dev_attr = ctx.clone()
        .query_device()
        .unwrap_or_else(|e| panic!("ERROR: cannot get device attributes: {}", e));

    // Create a protection domain
    let pd = ctx.clone()
        .alloc_pd()
        .unwrap_or_else(|_| panic!("ERROR: allocating Protection Domain failed"));

    // Create Complition Queue
    let cq = ctx.clone()
        .create_cq(dev_attr.max_cqe, 0)
        .unwrap_or_else(|e| panic!("ERROR: creating Completion Queue failed: {}", e));

    // here we need to allocate memory and register a memory region just for RDMA porposes
    let mut mr = pd
        .allocate::<RdmaPrimitive>(BUF_SIZE)
        .unwrap_or_else(|e| {
            panic!("ERROR: registering Memory Region failed: {}", e);
        });

    let laddr = (&mr[0] as *const RdmaPrimitive) as u64;

    let qp_init = pd
        .create_qp(&cq, &cq, ibverbs::ibv_qp_type::IBV_QPT_RC)
        .build()
        .unwrap_or_else(|e| panic!("ERROR: failed to initialize Queue Pair: {}", e));

    // This info will be sended to the remote server,
    // but we also expect to get the same insformation set from the server later
    let endpoint = qp_init.endpoint();

    let mut msg = ibverbs::EndpointMsg::from(endpoint);
    msg.rkey = mr.rkey();
    msg.raddr = ibverbs::RemoteAddr(laddr);

    let addr = env::var(ADDR_KEY).unwrap_or("127.0.0.1:9003");

    let listner = net::TcpListener::bind(addr).expect("Listener failed");
    let (mut stream, addr) = listner.accept().expect("Accepting failed");
    
    println!("Client connected!"); 

    let ser_msg = match bincode::serialize(&msg) {
        Ok(data) => data,
        Err(e) => panic!("ERROR: failed to serialize message: {}", e),
    };
    // This looks so much better.
    let mut rmsg: ibverbs::EndpointMsg = bincode::deserialize_from(stream)
        .unwrap_or_else(|e| panic!("ERROR: failed to recieve data: {}", e));
    
    let rkey = rmsg.rkey;
    let raddr = rmsg.raddr;
    let rendpoint = rmsg.into();

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

    let qp = qp_init
        .handshake(rendpoint)
        .unwrap_or_else(|e| panic!("ERROR: failed to handshake: {}", e));

    println!("RDMA handshake successfull");
}
