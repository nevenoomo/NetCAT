use ibverbs;

fn main() {
    unsafe{
        ibverbs::ffi::ibv_fork_init();
    }

    let dl = ibverbs::devices();
    if let Err(e) = dl {
        println!("{}", e);
    } else {
        println!("1");
    }
}