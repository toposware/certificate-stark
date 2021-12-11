use certificate_stark::schnorr::get_example;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::Duration;

const SIZES: [usize; 3] = [1, 16, 128];

fn schnorr_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("schnorr");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));

    for &size in SIZES.iter() {
        let schnorr = get_example(size);
        group.bench_function(BenchmarkId::new("prove", size), |bench| {
            bench.iter(|| schnorr.prove());
        });
        let proof = schnorr.prove();

        group.bench_function(BenchmarkId::new("verify", size), |bench| {
            bench.iter(|| schnorr.verify(proof.clone()));
        });
    }
    group.finish();
}

criterion_group!(schnorr_group, schnorr_bench);
criterion_main!(schnorr_group);
