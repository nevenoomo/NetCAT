use netcat::connection::rdma::RdmaServerConnector;

fn main() {
    let _client = RdmaServerConnector::new("10.0.2.4:9003");
    println!("RDMA handshake successful!");
}