use rand::{self, Rng};
use std::time::{SystemTime, Instant};

#[test]
fn local_latency() {
    let mut buf = vec![1; 8388608];
    let mut rng = rand::thread_rng();
    let mut lats = Vec::new();

    // Evict the whole cache
    #[cfg(not(feature = "clflush"))]
    for v in buf.iter_mut() {
        *v = rand::random();
    }
    #[cfg(feature = "clflush")]
    netcat::connection::local::flush(&buf);

    for _ in 0..10000 {
        let ofs = rng.gen_range(0, 8388608);
        println!("Addr: {}", ofs);

        // Measure evicted x time
        let now = Instant::now();
        let _x1 = buf[ofs];
        let elapsed1 = now.elapsed().as_nanos();
        println!("Evicted address access time: {}ns", elapsed1);

        // Measure in cache x time
        buf[ofs] = rand::random();
        let now = Instant::now();
        let _x1 = buf[ofs];
        let elapsed2 = now.elapsed().as_nanos();

        if elapsed1 < elapsed2 {
            continue;
        }

        println!("In cache address access time: {}ns", elapsed2);
        println!("Difference: {}ns", elapsed1 - elapsed2);

        lats.push(elapsed1 - elapsed2);
    }
    lats.sort();
    println!("All lats: {:?}", lats);
    println!("Median: {}", lats[(lats.len() - 1) / 2]);
}

#[test]
fn cache_allocation_test() {
    let mut buf = vec![1u8; 8388608];
    let mut rng = rand::thread_rng();

    // Evict the whole cache
    #[cfg(not(feature = "clflush"))]
    for v in buf.iter_mut() {
        *v = rand::random();
    }
    #[cfg(feature = "clflush")]
    netcat::connection::local::flush(&buf);

    let ofs = rng.gen_range(0, 8388608);
    buf[ofs] = rng.gen();
    let now = SystemTime::now();
    let _x = buf[ofs];
    let elapsed1 = now.elapsed().unwrap().as_nanos();
    let now = SystemTime::now();
    let _x = buf[ofs];
    let elapsed2 = now.elapsed().unwrap().as_nanos();

    println!("Writing to the address: {}", ofs);
    println!("First read: {}", elapsed1);
    println!("Second read: {}", elapsed2);
}
