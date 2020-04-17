use netcat::connection::rdma::RdmaServerConnector;
use netcat::connection::MemoryConnector;

const VAL: u8 = 123;

fn main() {
    let mut client = RdmaServerConnector::new("10.0.2.4:9003");
    println!("RDMA handshake successful!");

    println!();
    println!("--------------RDMA RW ROUTINE START------------------");
    println!("Try writing to the server memory, sending val: {}", VAL);
    let lat = client.write_timed(0, &VAL).unwrap();
    println!("Write successful. Latency: {}. See the other side", lat);

    println!();
    println!("Trying to read from the remote server and measure latency");
    let (val, lat) = client.read_timed(0).unwrap();
    println!("Read successful. Got: {}. Latency: {}", val, lat);
    println!("--------------RDMA RW ROUTINE END------------------");

    println!("Routrine successful!");
}
