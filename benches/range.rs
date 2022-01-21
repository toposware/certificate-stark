// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use certificate_stark::range::get_example;
use criterion::{criterion_group, criterion_main, Criterion};
use rand_core::RngCore;
use std::time::Duration;
use winterfell::math::fields::f63::BaseElement;

fn range_bench(c: &mut Criterion) {
    let mut rng = rand_core::OsRng;
    let mut group = c.benchmark_group("range");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));

    let mut bytes = [0u8; 8];
    rng.fill_bytes(&mut bytes);
    let value = u64::from_le_bytes(bytes) % 4719772409484279809;
    let elem = BaseElement::new(value);

    let range = get_example(elem);
    group.bench_function("prove", |bench| {
        bench.iter(|| range.prove());
    });
    let proof = range.prove();

    group.bench_function("verify", |bench| {
        bench.iter(|| range.verify(proof.clone()));
    });

    group.finish();
}

criterion_group!(
    name = range;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_secs(20));
    targets = range_bench
);
criterion_main!(range);
