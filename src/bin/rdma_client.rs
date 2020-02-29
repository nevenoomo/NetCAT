use netcat::connection::rdma::RdmaServerConnector;
use netcat::connection::MemoryConnector;

const VAL: u8 = 123;

fn main() {
    let mut client = RdmaServerConnector::new("10.0.2.4:9003");
    println!("RDMA handshake successful!");
    
    println!("Try writing to the server memory");
    let lat = client.write_timed(0, &VAL).unwrap();
    println!("Write successful. Latency: {}. See the other side", lat);

    println!("Trying to read from the remote server");
    let ret = client.read(0).unwrap();
    println!("Read successful. Got: {}", ret);

    println!("Trying to read from the remote server and measure latency");
    let lat = client.read_timed(0).unwrap();
    println!("Read successful. Latency: {}", lat);

    println!("Routrine successful!");
}