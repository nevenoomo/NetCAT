use criterion::{criterion_group, criterion_main, Criterion};
use netcat::connection::local::*;
use netcat::rpp::Rpp;

pub fn rpp_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("RRIME+PROBE benchmark");

    group.sample_size(100);

    group.bench_function("RPP bench", |b| {
        b.iter(|| {
            let conn = Box::new(LocalMemoryConnector::new());
            let quite = true;
            let _rpp = Rpp::new(conn, quite);
        })
    });
}

criterion_group!(benches, rpp_bench);
criterion_main!(benches);
