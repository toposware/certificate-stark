// Copyright (c) ToposWare and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::TransactionMetadata;
use log::debug;
use std::time::Instant;
use winterfell::{
    math::log2, FieldExtension, HashFunction, ProofOptions, StarkProof, VerifierError,
};

pub mod constants;
use constants::{HASH_RATE_WIDTH, MERKLE_TREE_DEPTH};
mod trace;
pub use trace::{build_trace, init_merkle_update_state, update_merkle_update_state};
mod air;
pub use air::{evaluate_constraints, periodic_columns, transition_constraint_degrees};
use air::{MerkleAir, PublicInputs};

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
    tx_metadata: TransactionMetadata,
}

impl TransactionExample {
    pub fn new(options: ProofOptions, num_transactions: usize) -> TransactionExample {
        assert!(
            (MERKLE_TREE_DEPTH + 1).is_power_of_two(),
            "tree depth must be one less than a power of 2"
        );
        // Create a Merkle tree for which we know all of the values
        let tx_metadata = TransactionMetadata::build_random(num_transactions);

        TransactionExample {
            options,
            tx_metadata,
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
        let trace = build_trace(&self.tx_metadata);
        let trace_length = trace.length();
        debug!(
            "Generated execution trace of {} registers and 2^{} steps in {} ms",
            trace.width(),
            log2(trace_length),
            now.elapsed().as_millis()
        );

        // generate the proof
        let pub_inputs = PublicInputs {
            initial_root: self.tx_metadata.initial_roots[0].to_elements(),
            final_root: self.tx_metadata.final_root.to_elements(),
        };
        winterfell::prove::<MerkleAir>(trace, pub_inputs, self.options.clone()).unwrap()
    }

    pub fn verify(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            initial_root: self.tx_metadata.initial_roots[0].to_elements(),
            final_root: self.tx_metadata.final_root.to_elements(),
        };
        winterfell::verify::<MerkleAir>(proof, pub_inputs)
    }

    pub fn verify_with_wrong_inputs(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let initial_root = self.tx_metadata.initial_roots[0].to_elements();
        let final_root = self.tx_metadata.final_root.to_elements();
        let pub_inputs = PublicInputs {
            initial_root,
            final_root: [final_root[0]; HASH_RATE_WIDTH],
        };
        winterfell::verify::<MerkleAir>(proof, pub_inputs)
    }
}
