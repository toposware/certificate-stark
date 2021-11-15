// Copyright (c) ToposWare and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use log::debug;
use std::time::Instant;
use winterfell::{
    math::{fields::f63::BaseElement, log2, FieldElement},
    FieldExtension, HashFunction, ProofOptions, StarkProof, VerifierError,
};

pub mod air;
pub use air::{evaluate_constraints, periodic_columns};
use air::{PreMerkleAir, PublicInputs};

pub mod constants;
use constants::AFFINE_POINT_WIDTH;
mod trace;
pub use trace::{
    build_trace, init_merkle_initialization_state, update_merkle_initialization_state,
};

#[cfg(test)]
mod tests;

// MERKLE TREE UPDATE EXAMPLE
// ================================================================================================
pub fn get_example() -> PreMerkleExample {
    PreMerkleExample::new(
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
    )
}

pub struct PreMerkleExample {
    options: ProofOptions,
    s_inputs: [BaseElement; AFFINE_POINT_WIDTH + 2],
    r_inputs: [BaseElement; AFFINE_POINT_WIDTH + 2],
    delta: BaseElement,
}

impl PreMerkleExample {
    pub fn new(options: ProofOptions) -> PreMerkleExample {
        // Sender and receiver inputs are 4 BaseElement s, namely: 2 for the pk, 1 for the $, and 1 for the nonce
        let s_inputs = [BaseElement::ZERO; AFFINE_POINT_WIDTH + 2];
        let r_inputs = [BaseElement::ZERO; AFFINE_POINT_WIDTH + 2];
        let delta = BaseElement::ONE;

        PreMerkleExample {
            options,
            s_inputs,
            r_inputs,
            delta,
        }
    }
    pub fn prove(&self) -> StarkProof {
        // generate the execution trace
        debug!(
            "Generating proof for Pre-Merkle block\n\
            ---------------------"
        );
        let now = Instant::now();
        let trace = build_trace(self.s_inputs, self.r_inputs, self.delta);
        let trace_length = trace.length();
        debug!(
            "Generated execution trace of {} registers and 2^{} steps in {} ms",
            trace.width(),
            log2(trace_length),
            now.elapsed().as_millis()
        );

        // generate the proof
        let pub_inputs = PublicInputs {
            s_inputs: self.s_inputs,
            r_inputs: self.r_inputs,
            delta: self.delta,
        };
        winterfell::prove::<PreMerkleAir>(trace, pub_inputs, self.options.clone()).unwrap()
    }

    pub fn verify(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            s_inputs: self.s_inputs,
            r_inputs: self.r_inputs,
            delta: self.delta,
        };
        winterfell::verify::<PreMerkleAir>(proof, pub_inputs)
    }

    pub fn verify_with_wrong_inputs(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            s_inputs: self.r_inputs,
            r_inputs: self.r_inputs,
            delta: self.delta.double(),
        };
        winterfell::verify::<PreMerkleAir>(proof, pub_inputs)
    }
}
