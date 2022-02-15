// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use winterfell::{
    math::{fields::f63::BaseElement, FieldElement},
    FieldExtension, HashFunction, ProofOptions, Prover, StarkProof, VerifierError,
};

#[cfg(feature = "std")]
use log::debug;
#[cfg(feature = "std")]
use std::time::Instant;
#[cfg(feature = "std")]
use winterfell::{math::log2, Trace};

mod air;
pub(crate) use air::{evaluate_constraints, periodic_columns};
use air::{PreMerkleAir, PublicInputs};

mod prover;
use prover::PreMerkleProver;

pub(crate) mod constants;
use constants::AFFINE_POINT_WIDTH;
mod trace;

#[cfg(test)]
mod tests;

// MERKLE TREE UPDATE EXAMPLE
// ================================================================================================

/// Outputs a new `PreMerkleExample` for proving correct hashing of leaf values
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

/// A struct to perform leaf hash validity
/// proof among a set of transactions.
#[derive(Clone, Debug)]
pub struct PreMerkleExample {
    options: ProofOptions,
    s_inputs: [BaseElement; AFFINE_POINT_WIDTH + 2],
    r_inputs: [BaseElement; AFFINE_POINT_WIDTH + 2],
    delta: BaseElement,
}

impl PreMerkleExample {
    /// Outputs a new `PreMerkleExample` for proving correct hashing of leaf values
    pub fn new(options: ProofOptions) -> PreMerkleExample {
        // Sender and receiver inputs are AFFINE_POINT_WIDTH + 2 `BaseElement`,
        // namely: AFFINE_POINT_WIDTH for the pk, 1 for the amount, and 1 for the nonce
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

    /// Proves the validity of a Rescue-Prime hash iteration over some leaf inputs
    pub fn prove(&self) -> StarkProof {
        // generate the execution trace
        #[cfg(feature = "std")]
        debug!(
            "Generating proof for Pre-Merkle block\n\
            ---------------------"
        );

        let prover = PreMerkleProver::new(self.options.clone());

        // generate the execution trace
        #[cfg(feature = "std")]
        let now = Instant::now();
        let trace = prover.build_trace(self.s_inputs, self.r_inputs, self.delta);
        #[cfg(feature = "std")]
        debug!(
            "Generated execution trace of {} registers and 2^{} steps in {} ms",
            trace.width(),
            log2(trace.length()),
            now.elapsed().as_millis()
        );

        // generate the proof
        prover.prove(trace).unwrap()
    }

    /// Verifies the validity of a proof of correct Rescue-Prime hash iteration
    pub fn verify(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            s_inputs: self.s_inputs,
            r_inputs: self.r_inputs,
            delta: self.delta,
        };
        winterfell::verify::<PreMerkleAir>(proof, pub_inputs)
    }

    #[cfg(test)]
    fn verify_with_wrong_inputs(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            s_inputs: self.r_inputs,
            r_inputs: self.r_inputs,
            delta: self.delta.double(),
        };
        winterfell::verify::<PreMerkleAir>(proof, pub_inputs)
    }
}
