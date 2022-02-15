// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::TransactionMetadata;
use winterfell::{FieldExtension, HashFunction, ProofOptions, Prover, StarkProof, VerifierError};

#[cfg(feature = "std")]
use log::debug;
#[cfg(feature = "std")]
use std::time::Instant;
#[cfg(feature = "std")]
use winterfell::{math::log2, Trace};

pub(crate) mod constants;
use constants::MERKLE_TREE_DEPTH;

mod trace;

pub(crate) use trace::{init_merkle_update_state, update_merkle_update_state};
mod air;

mod prover;
use prover::MerkleProver;

pub(crate) use air::{evaluate_constraints, periodic_columns, transition_constraint_degrees};
use air::{MerkleAir, PublicInputs};

#[cfg(test)]
mod tests;

// MERKLE TREE MULTIPLE TRANSACTIONS EXAMPLE
// ================================================================================================

/// Outputs a new `TransactionExample` with `num_transactions` random transactions.
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

/// A struct to perform authentication paths validity
/// proof among a set of transactions.
#[derive(Clone, Debug)]
pub struct TransactionExample {
    options: ProofOptions,
    tx_metadata: TransactionMetadata,
}

impl TransactionExample {
    /// Outputs a new `TransactionExample` with `num_transactions` random transactions.
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

    /// Proves the validity of the authentication paths of a given set of transactions users
    pub fn prove(&self) -> StarkProof {
        // generate the execution trace
        #[cfg(feature = "std")]
        debug!(
            "Generating proof for proving update in a Merkle tree of depth {}\n\
            ---------------------",
            MERKLE_TREE_DEPTH
        );

        let prover = MerkleProver::new(self.options.clone());

        // generate the execution trace
        #[cfg(feature = "std")]
        let now = Instant::now();
        let trace = prover.build_trace(&self.tx_metadata);
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

    /// Verifies the validity of a proof of correct authentication paths computation
    pub fn verify(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            initial_root: self.tx_metadata.initial_roots[0].to_elements(),
            final_root: self.tx_metadata.final_root.to_elements(),
        };
        winterfell::verify::<MerkleAir>(proof, pub_inputs)
    }

    #[cfg(test)]
    fn verify_with_wrong_inputs(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let initial_root = self.tx_metadata.initial_roots[0].to_elements();
        let final_root = self.tx_metadata.final_root.to_elements();
        let pub_inputs = PublicInputs {
            initial_root,
            final_root: [final_root[0]; constants::HASH_RATE_WIDTH],
        };
        winterfell::verify::<MerkleAir>(proof, pub_inputs)
    }
}
