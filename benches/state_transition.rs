use certificate_stark::get_example;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::Duration;

const SIZES: [usize; 3] = [1, 16, 128];

fn state_transition_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("state-transition");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));

    for &size in SIZES.iter() {
        let state_transition = get_example(size);
        group.bench_function(BenchmarkId::new("prove", size), |bench| {
            bench.iter(|| state_transition.prove());
        });
        let proof = state_transition.prove();

        group.bench_function(BenchmarkId::new("verify", size), |bench| {
            bench.iter(|| state_transition.verify(proof.clone()));
        });
    }
    group.finish();
}

criterion_group!(state_transition_group, state_transition_bench);
criterion_main!(state_transition_group);
