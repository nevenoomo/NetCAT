use std::time::SystemTime;
use rand;

#[test]
fn local_latency() {
    let mut buf = vec![1; 8388608];
    let mut x = Box::new(10);

    // Evict the whole cache 
    for v in buf.iter_mut() {
        *v = rand::random();
    }

    // Measure evicted x time
    let now = SystemTime::now();
    let x1 = *x;
    let elapsed1 = now.elapsed().unwrap().as_nanos();
    println!("Evicted address access time: {}ns", elapsed1);

    // Measure in cache x time
    *x = rand::random();        
    let now = SystemTime::now();
    let _x1 = *x;
    let elapsed2 = now.elapsed().unwrap().as_nanos();
    println!("In cache address access time: {}ns", elapsed2);
    println!("Difference: {}ns", elapsed1 - elapsed2);
}