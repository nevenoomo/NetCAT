use netcat::connection::rdma::RdmaServerConnector;

fn main() {
    let _client = RdmaServerConnector::new("127.0.0.1:9003");
    println!("RDMA handshake successful!");
}