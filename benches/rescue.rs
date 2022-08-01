// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use log::debug;
use std::time::{Duration, Instant};
use winterfell::{
    crypto::Hasher,
    math::{fields::f63::BaseElement, log2, FieldElement},
    Air, AirContext, Assertion, ByteWriter, EvaluationFrame, FieldExtension, HashFunction,
    ProofOptions, Prover, Serializable, StarkProof, Trace, TraceInfo, TraceTable,
    TransitionConstraintDegree, VerifierError,
};

use certificate_stark::utils::rescue::{HASH_CYCLE_LENGTH, NUM_HASH_ROUNDS, RATE_WIDTH};
use certificate_stark::utils::{are_equal, is_zero, not, rescue, EvaluationResult};

const SIZES: [usize; 4] = [128, 256, 512, 1024];

pub struct RescueExample {
    options: ProofOptions,
    chain_length: usize,
    seed: [BaseElement; 7],
    result: [BaseElement; 7],
}

impl RescueExample {
    fn new(chain_length: usize, options: ProofOptions) -> RescueExample {
        assert!(
            chain_length.is_power_of_two(),
            "chain length must a power of 2"
        );
        let seed = [
            BaseElement::from(42u8),
            BaseElement::from(43u8),
            BaseElement::from(44u8),
            BaseElement::from(45u8),
            BaseElement::from(46u8),
            BaseElement::from(47u8),
            BaseElement::from(48u8),
        ];

        // compute the sequence of hashes using external implementation of Rescue hash
        let now = Instant::now();
        let result = compute_hash_chain(seed, chain_length);
        debug!(
            "Computed a chain of {} Rescue hashes in {} ms",
            chain_length,
            now.elapsed().as_millis(),
        );

        RescueExample {
            options,
            chain_length,
            seed,
            result,
        }
    }

    fn prove(&self) -> StarkProof {
        // generate the execution trace
        debug!(
            "Generating proof for computing a chain of {} Rescue hashes\n\
            ---------------------",
            self.chain_length
        );
        let prover = RescueProver::new(self.options.clone());

        let now = Instant::now();
        let trace = prover.build_trace(self.seed, self.chain_length);
        let trace_length = trace.length();
        debug!(
            "Generated execution trace of {} registers and 2^{} steps in {} ms",
            trace.width(),
            log2(trace_length),
            now.elapsed().as_millis()
        );

        prover.prove(trace).unwrap()
    }

    fn verify(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            seed: self.seed,
            result: self.result,
        };
        winterfell::verify::<RescueAir>(proof, pub_inputs)
    }

    fn _verify_with_wrong_inputs(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            seed: self.seed,
            result: [self.result[0]; RATE_WIDTH],
        };
        winterfell::verify::<RescueAir>(proof, pub_inputs)
    }
}

fn compute_hash_chain(seed: [BaseElement; RATE_WIDTH], length: usize) -> [BaseElement; RATE_WIDTH] {
    let mut values = rescue::Hash::new(
        seed[0], seed[1], seed[2], seed[3], seed[4], seed[5], seed[6],
    );
    let mut result = rescue::Hash::new(
        BaseElement::ZERO,
        BaseElement::ZERO,
        BaseElement::ZERO,
        BaseElement::ZERO,
        BaseElement::ZERO,
        BaseElement::ZERO,
        BaseElement::ZERO,
    );
    for _ in 0..length {
        result = rescue::Rescue63::merge(&[values, result]);
        values = result;
    }

    result.to_elements()
}

// CONSTANTS
// ================================================================================================

const TRACE_WIDTH: usize = 14;

/// Specifies steps on which Rescue transition function is applied.
const CYCLE_MASK: [BaseElement; HASH_CYCLE_LENGTH] = [
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ZERO,
];

// RESCUE AIR
// ================================================================================================

pub struct PublicInputs {
    pub seed: [BaseElement; RATE_WIDTH],
    pub result: [BaseElement; RATE_WIDTH],
}

impl Serializable for PublicInputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(&self.seed[..]);
        target.write(&self.result[..]);
    }
}

pub struct RescueAir {
    context: AirContext<BaseElement>,
    seed: [BaseElement; RATE_WIDTH],
    result: [BaseElement; RATE_WIDTH],
}

impl Air for RescueAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        let degrees = vec![
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LENGTH]),
        ];
        assert_eq!(TRACE_WIDTH, trace_info.width());
        RescueAir {
            context: AirContext::new(trace_info, degrees, options),
            seed: pub_inputs.seed,
            result: pub_inputs.result,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();
        // expected state width is 14 field elements
        debug_assert_eq!(TRACE_WIDTH, current.len());
        debug_assert_eq!(TRACE_WIDTH, next.len());

        // split periodic values into hash_flag and Rescue round constants
        let hash_flag = periodic_values[0];
        let ark = &periodic_values[1..];

        // when hash_flag = 1, constraints for Rescue round are enforced
        rescue::enforce_round(result, current, next, ark, hash_flag);

        // when hash_flag = 0, constraints for copying hash values to the next
        // step are enforced.
        let copy_flag = not(hash_flag);
        enforce_hash_copy(result, current, next, copy_flag);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        // Assert starting and ending values of the hash chain
        let last_step = self.trace_length() - 1;
        vec![
            Assertion::single(0, 0, self.seed[0]),
            Assertion::single(1, 0, self.seed[1]),
            Assertion::single(2, 0, self.seed[2]),
            Assertion::single(3, 0, self.seed[3]),
            Assertion::single(4, 0, self.seed[4]),
            Assertion::single(5, 0, self.seed[5]),
            Assertion::single(6, 0, self.seed[6]),
            Assertion::single(0, last_step, self.result[0]),
            Assertion::single(1, last_step, self.result[1]),
            Assertion::single(2, last_step, self.result[2]),
            Assertion::single(3, last_step, self.result[3]),
            Assertion::single(4, last_step, self.result[4]),
            Assertion::single(5, last_step, self.result[5]),
            Assertion::single(6, last_step, self.result[6]),
        ]
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let mut result = vec![CYCLE_MASK.to_vec()];
        result.append(&mut rescue::get_round_constants());
        result
    }
}

// HELPER EVALUATORS
// ------------------------------------------------------------------------------------------------

/// when flag = 1, enforces that the next state of the computation is defined like so:
/// - the first RATE_WIDTH registers are equal to the values from the previous step
/// - the other RATE_WIDTH registers are equal to 0,
fn enforce_hash_copy<E: FieldElement>(result: &mut [E], current: &[E], next: &[E], flag: E) {
    for i in 0..RATE_WIDTH {
        result.agg_constraint(i, flag, are_equal(current[i], next[i]));
    }

    // resetting the last registers
    for i in 0..RATE_WIDTH {
        result.agg_constraint(RATE_WIDTH + i, flag, is_zero(next[RATE_WIDTH + i]));
    }
}

// RESCUE PROVER
// ================================================================================================

pub struct RescueProver {
    options: ProofOptions,
}

impl RescueProver {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }

    pub fn build_trace(
        &self,
        seed: [BaseElement; RATE_WIDTH],
        iterations: usize,
    ) -> TraceTable<BaseElement> {
        // allocate memory to hold the trace table
        let trace_length = iterations * HASH_CYCLE_LENGTH;
        let mut trace = TraceTable::new(TRACE_WIDTH, trace_length);

        trace.fill(
            |state| {
                // initialize first state of the computation
                state[0] = seed[0];
                state[1] = seed[1];
                state[2] = seed[2];
                state[3] = seed[3];
                state[4] = seed[4];
                state[5] = seed[5];
                state[6] = seed[6];
                state[7] = BaseElement::ZERO;
                state[8] = BaseElement::ZERO;
                state[9] = BaseElement::ZERO;
                state[10] = BaseElement::ZERO;
                state[11] = BaseElement::ZERO;
                state[12] = BaseElement::ZERO;
                state[13] = BaseElement::ZERO;
            },
            |step, state| {
                // execute the transition function for all steps
                if (step % HASH_CYCLE_LENGTH) < NUM_HASH_ROUNDS {
                    rescue::apply_round(state, step);
                } else {
                    state[7] = BaseElement::ZERO;
                    state[8] = BaseElement::ZERO;
                    state[9] = BaseElement::ZERO;
                    state[10] = BaseElement::ZERO;
                    state[11] = BaseElement::ZERO;
                    state[12] = BaseElement::ZERO;
                    state[13] = BaseElement::ZERO;
                }
            },
        );

        trace
    }
}

impl Prover for RescueProver {
    type BaseField = BaseElement;
    type Air = RescueAir;
    type Trace = TraceTable<BaseElement>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> PublicInputs {
        let last_step = trace.length() - 1;

        PublicInputs {
            seed: [
                trace.get(0, 0),
                trace.get(1, 0),
                trace.get(2, 0),
                trace.get(3, 0),
                trace.get(4, 0),
                trace.get(5, 0),
                trace.get(6, 0),
            ],
            result: [
                trace.get(0, last_step),
                trace.get(1, last_step),
                trace.get(2, last_step),
                trace.get(3, last_step),
                trace.get(4, last_step),
                trace.get(5, last_step),
                trace.get(6, last_step),
            ],
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }
}

// RESCUE BENCHMARK
// ================================================================================================

fn rescue_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("rescue");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));

    let options = ProofOptions::new(
        42,
        4,
        0,
        HashFunction::Blake3_256,
        FieldExtension::None,
        4,
        256,
    );

    for &size in SIZES.iter() {
        let rescue = RescueExample::new(size, options.clone());
        group.bench_function(BenchmarkId::new("prove", size), |bench| {
            bench.iter(|| rescue.prove());
        });
        let proof = rescue.prove();

        group.bench_function(BenchmarkId::new("verify", size), |bench| {
            bench.iter(|| rescue.verify(proof.clone()));
        });
    }
    group.finish();
}

criterion_group!(rescue_group, rescue_bench);
criterion_main!(rescue_group);
