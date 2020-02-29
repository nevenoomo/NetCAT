use netcat::connection::rdma::RdmaServerConnector;
use netcat::connection::MemoryConnector;

const VAL: u8 = 123;

fn main() {
    let some_data = vec![1,2,3,4,5];
    let mut recv_buf = Vec::with_capacity(5);

    let mut client = RdmaServerConnector::new("10.0.2.4:9003");
    println!("RDMA handshake successful!");

    println!();
    println!("--------------RDMA RW ROUTINE START------------------");
    println!("Try writing to the server memory");
    let lat = client.write_timed(0, &VAL).unwrap();
    println!("Write successful. Latency: {}. See the other side", lat);

    println!();
    println!("Trying to read from the remote server and measure latency");
    let (val, lat) = client.read_timed(0).unwrap();
    println!("Read successful. Got: {}. Latency: {}", val, lat);

    println!();
    println!("BATCHED RW");
    println!("Try writing a buffer to the server memory");
    let (_, lat) = client.write_buf_timed(0, some_data.as_slice()).unwrap();
    println!("Write successful. Latency: {}. See the other side", lat);

    println!();
    println!("Trying to read from the remote server and measure latency");
    let (_, lat) = client.read_buf_timed(0, recv_buf.as_mut_slice()).unwrap();
    println!("Read successful. Latency: {}", lat);
    println!("--------------RDMA RW ROUTINE END------------------");

    println!("Routrine successful!");
}
