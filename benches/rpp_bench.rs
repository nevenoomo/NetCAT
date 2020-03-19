use criterion::{criterion_group, criterion_main, Criterion};
use netcat::rpp::Rpp;
use netcat::connection::local::*;

pub fn rpp_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("RRIME+PROBE benchmark");

    group.sample_size(100);

    group.bench_function("RPP bench", |b| {
        b.iter(|| {
            let conn = Box::new(LocalMemoryConnector::new());

            let _rpp = Rpp::new(conn);
        })
    });
}

criterion_group!(benches, rpp_bench);
criterion_main!(benches);