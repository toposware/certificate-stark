// Copyright (c) ToposWare and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

pub mod merkle;
pub mod range;
pub mod schnorr;
pub mod utils;

mod air;
use air::{PublicInputs, TransactionAir};

pub mod constants;

mod trace;
pub use trace::build_trace;

use log::debug;
use std::time::Instant;
use utils::rescue::Hash;
use winterfell::{
    math::{curve::Scalar, fields::f252::BaseElement, log2},
    FieldExtension, HashFunction, ProofOptions, StarkProof, VerifierError,
};

use constants::merkle_const::MERKLE_TREE_DEPTH;

#[cfg(test)]
mod tests;

// MERKLE TREE MULTIPLE TRANSACTIONS EXAMPLE
// ================================================================================================
pub fn get_example(num_transactions: usize) -> TransactionExample {
    TransactionExample::new(
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
        num_transactions,
    )
}

pub struct TransactionExample {
    options: ProofOptions,
    initial_roots: Vec<Hash>,
    final_root: Hash,
    s_old_values: Vec<[BaseElement; 4]>,
    r_old_values: Vec<[BaseElement; 4]>,
    s_indices: Vec<usize>,
    r_indices: Vec<usize>,
    s_paths: Vec<Vec<Hash>>,
    r_paths: Vec<Vec<Hash>>,
    deltas: Vec<BaseElement>,
    signatures: Vec<(BaseElement, Scalar)>,
}

impl TransactionExample {
    pub fn new(options: ProofOptions, num_transactions: usize) -> TransactionExample {
        assert!(
            (MERKLE_TREE_DEPTH + 1).is_power_of_two(),
            "tree depth must be one less than a power of 2"
        );
        // Create a Merkle tree for which we know all of the values
        let (
            initial_roots,
            final_root,
            s_old_values,
            r_old_values,
            s_indices,
            r_indices,
            s_paths,
            r_paths,
            deltas,
            s_secret_keys,
        ) = merkle::update::build_tree(num_transactions);

        let now = Instant::now();
        let mut signatures = Vec::with_capacity(num_transactions);
        for i in 0..num_transactions {
            // A message consists in sender's pkey, receiver's pkey, amount to be sent and sender's nonce.
            let message = [
                s_old_values[i][0],
                s_old_values[i][1],
                r_old_values[i][0],
                r_old_values[i][1],
                deltas[i],
                s_old_values[i][3],
            ];
            signatures.push(schnorr::sign(message, s_secret_keys[i]));
        }

        debug!(
            "Computed {} Schnorr signatures in {} ms",
            num_transactions,
            now.elapsed().as_millis(),
        );

        TransactionExample {
            options,
            initial_roots,
            final_root,
            s_old_values,
            r_old_values,
            s_indices,
            r_indices,
            s_paths,
            r_paths,
            deltas,
            signatures,
        }
    }
    pub fn prove(&self) -> StarkProof {
        // generate the execution trace
        debug!(
            "Generating proof for proving update in a Merkle tree of depth {}\n\
            ---------------------",
            MERKLE_TREE_DEPTH
        );
        let now = Instant::now();
        let trace = build_trace(
            &self.initial_roots,
            &self.s_old_values,
            &self.r_old_values,
            &self.s_indices,
            &self.r_indices,
            &self.s_paths,
            &self.r_paths,
            &self.deltas,
            &self.signatures,
            self.s_old_values.len(),
        );

        let trace_length = trace.length();
        debug!(
            "Generated execution trace of {} registers and 2^{} steps in {} ms",
            trace.width(),
            log2(trace_length),
            now.elapsed().as_millis()
        );

        // generate the proof
        let pub_inputs = PublicInputs {
            initial_root: self.initial_roots[0].to_elements(),
            final_root: self.final_root.to_elements(),
        };
        winterfell::prove::<TransactionAir>(trace, pub_inputs, self.options.clone()).unwrap()
    }

    pub fn verify(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            initial_root: self.initial_roots[0].to_elements(),
            final_root: self.final_root.to_elements(),
        };
        winterfell::verify::<TransactionAir>(proof, pub_inputs)
    }

    pub fn verify_with_wrong_inputs(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let initial_root = self.initial_roots[0].to_elements();
        let final_root = self.final_root.to_elements();
        let pub_inputs = PublicInputs {
            initial_root,
            final_root: [final_root[1], final_root[0]],
        };
        winterfell::verify::<TransactionAir>(proof, pub_inputs)
    }
}
