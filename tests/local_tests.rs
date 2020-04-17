#![feature(asm)]

use rand::{self, Rng};
use std::time::{SystemTime, Instant};

#[test]
fn local_latency() {
    // By doing such a buffer we fool the prefetcher and can ditinguish hits and misses
    let mut buf = vec![vec![0u8; 4096]; 8388608 / 4096];
    let mut rng = rand::thread_rng();
    let mut lats = Vec::new();
    let mut fail_cnt = 0;

    for _ in 0..80000 {
        let ofs = rng.gen_range(0, 8388608);
        println!("Addr: {}", ofs);
        let ofs_hi = (ofs as usize) >> 12;
        let ofs_lo = (ofs as usize) & 0xfff;

        let sub_buf = &buf[ofs_hi];
        // let buf_addr = buf[ofs_hi].as_mut_ptr();

        // Measure evicted x time
        let now = Instant::now();
        let _x1 = sub_buf[ofs_lo];
        let elapsed1 = now.elapsed().as_nanos();

        // let elapsed1 = time_r(unsafe { buf_addr.offset(ofs & 0xfff) });

        // Measure in cache x time
        let now = Instant::now();
        let _x2 = sub_buf[ofs_lo];
        let elapsed2 = now.elapsed().as_nanos();


        // let elapsed2 = time_r(unsafe { buf_addr.offset(ofs & 0xfff) });

        if elapsed1 <= elapsed2 {
            fail_cnt += 1;
            continue;
        }

        println!("Evicted address access time: {}", elapsed1);
        println!("In cache address access time: {}", elapsed2);
        println!("Difference: {}", elapsed1 - elapsed2);
        
        lats.push(elapsed1 - elapsed2);
    }
    lats.sort();

    println!("Fails: {}", fail_cnt);
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
