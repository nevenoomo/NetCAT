use criterion::{criterion_group, criterion_main, Criterion};
use NetCAT::connection::*;
use NetCAT::rpp::test::NaiveRpp;
use NetCAT::rpp::RPP;

pub fn rpp_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("RPP benchmark");

    group.sample_size(10);

    group.bench_function("Naive RPP", |b| {
        b.iter(|| {
            let conn = Box::new(LocalMemoryConnector::new());

            let mut naive_rpp = NaiveRpp::new(conn);

            naive_rpp.naive_build_set();
        })
    });
}

criterion_group!(benches, rpp_bench);
criterion_main!(benches);
