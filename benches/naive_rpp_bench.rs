use criterion::{criterion_group, criterion_main, Criterion};
use netcat::connection::local::*;
use netcat::rpp::test::NaiveRpp;

pub fn rpp_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("RRIME+PROBE benchmark");

    group.sample_size(100);

    group.bench_function("Naive RRIME+PROBE", |b| {
        b.iter(|| {
            let conn = Box::new(LocalMemoryConnector::new());

            let mut naive_rpp = NaiveRpp::new(conn);

            naive_rpp.naive_build_set().unwrap();
        })
    });
}

criterion_group!(benches, rpp_bench);
criterion_main!(benches);
