// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use certificate_stark::merkle::update::get_example;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::Duration;

const SIZES: [usize; 3] = [1, 16, 128];

fn merkle_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));

    for &size in SIZES.iter() {
        let merkle = get_example(size);
        group.bench_function(BenchmarkId::new("prove", size), |bench| {
            bench.iter(|| merkle.prove());
        });
        let proof = merkle.prove();

        group.bench_function(BenchmarkId::new("verify", size), |bench| {
            bench.iter(|| merkle.verify(proof.clone()));
        });
    }
    group.finish();
}

criterion_group!(merkle_group, merkle_bench);
criterion_main!(merkle_group);
