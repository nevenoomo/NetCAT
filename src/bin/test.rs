use ibverbs;
use crate::connection::rdma::RdmaServerConnector;

fn main() {
    let mut client = RdmaServerConnector::new("127.0.0.1:9003");
}