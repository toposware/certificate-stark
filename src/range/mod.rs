// Copyright (c) ToposWare and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use log::debug;
use std::time::Instant;
use winterfell::{
    math::{fields::f252::BaseElement, log2},
    FieldExtension, HashFunction, ProofOptions, StarkProof, VerifierError,
};

use super::utils::field;

mod air;
pub use air::{
    build_trace, evaluate_constraints, init_range_verification_state,
    update_range_verification_state, TRACE_WIDTH,
};
use air::{PublicInputs, RangeProofAir};

#[cfg(test)]
mod tests;

pub const RANGE_LOG: usize = 64;

// RANGE PROOF EXAMPLE
// ================================================================================================

pub fn get_example(number: BaseElement) -> RangeProofExample {
    RangeProofExample::new(
        // TODO: make it customizable
        ProofOptions::new(
            42,
            8,
            0,
            HashFunction::Blake3_256,
            FieldExtension::None,
            4,
            256,
        ),
        number,
    )
}

pub struct RangeProofExample {
    options: ProofOptions,
    number: BaseElement,
    range_log: usize,
}

impl RangeProofExample {
    pub fn new(options: ProofOptions, number: BaseElement) -> RangeProofExample {
        RangeProofExample {
            options,
            number,
            range_log: RANGE_LOG,
        }
    }
    pub fn prove(&self) -> StarkProof {
        // generate the execution trace
        debug!(
            "Generating a Range proof for number of {} bits\n\
            ---------------------",
            self.range_log,
        );
        let now = Instant::now();
        let trace = build_trace(self.number, self.range_log);
        let trace_length = trace.length();
        debug!(
            "Generated execution trace of {} registers and 2^{} steps in {} ms",
            trace.width(),
            log2(trace_length),
            now.elapsed().as_millis()
        );

        // generate the proof
        let pub_inputs = PublicInputs {
            number: self.number,
        };
        winterfell::prove::<RangeProofAir>(trace, pub_inputs, self.options.clone()).unwrap()
    }

    pub fn verify(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            number: self.number,
        };
        winterfell::verify::<RangeProofAir>(proof, pub_inputs)
    }

    pub fn verify_with_wrong_inputs(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            number: -self.number,
        };
        winterfell::verify::<RangeProofAir>(proof, pub_inputs)
    }
}
