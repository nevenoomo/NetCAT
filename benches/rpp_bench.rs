use criterion::{criterion_group, criterion_main, Criterion};
use netcat::rpp::RPP;
use netcat::connection::local::*;

pub fn rpp_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("RPP benchmark");

    group.sample_size(20);

    group.bench_function("RPP bench", |b| {
        b.iter(|| {
            let conn = Box::new(LocalMemoryConnector::new());

            let mut rpp = RPP::new(conn);

            rpp.build_set();
        })
    });
}

criterion_group!(benches, rpp_bench);
criterion_main!(benches);
