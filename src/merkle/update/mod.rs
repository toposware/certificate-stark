// Copyright (c) ToposWare and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::utils::rescue::{Hash, Rescue252};
use log::debug;
use rand_core::{OsRng, RngCore};
use std::time::Instant;
use winterfell::{
    crypto::{Digest, Hasher, MerkleTree},
    math::{
        curve::{AffinePoint, Scalar},
        fields::f252::BaseElement,
        log2, FieldElement, StarkField,
    },
    FieldExtension, HashFunction, ProofOptions, StarkProof, VerifierError,
};

pub mod constants;
use constants::MERKLE_TREE_DEPTH;
mod trace;
pub use trace::{build_trace, init_merkle_update_state, update_merkle_update_state};
pub mod air;
pub use air::{evaluate_constraints, periodic_columns};
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
    initial_roots: Vec<Hash>,
    final_root: Hash,
    s_old_values: Vec<[BaseElement; 4]>,
    r_old_values: Vec<[BaseElement; 4]>,
    s_indices: Vec<usize>,
    r_indices: Vec<usize>,
    s_paths: Vec<Vec<Hash>>,
    r_paths: Vec<Vec<Hash>>,
    deltas: Vec<BaseElement>,
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
            _,
        ) = build_tree(num_transactions);

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
        winterfell::prove::<MerkleAir>(trace, pub_inputs, self.options.clone()).unwrap()
    }

    pub fn verify(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            initial_root: self.initial_roots[0].to_elements(),
            final_root: self.final_root.to_elements(),
        };
        winterfell::verify::<MerkleAir>(proof, pub_inputs)
    }

    pub fn verify_with_wrong_inputs(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let initial_root = self.initial_roots[0].to_elements();
        let final_root = self.final_root.to_elements();
        let pub_inputs = PublicInputs {
            initial_root,
            final_root: [final_root[1], final_root[0]],
        };
        winterfell::verify::<MerkleAir>(proof, pub_inputs)
    }
}

// BUILDER FUNCTION
// ================================================================================================

/// Creates a set of variables indicating a series of `num_transactions` updates in a Merkle tree,
/// represented as transactions from a sender to a receiver.
/// Each tree leaf is storing the following informations:
/// - account public key's x coordinate
/// - account public key's y coordinate
/// - account balance
/// - account nonce
pub fn build_tree(
    num_transactions: usize,
) -> (
    Vec<Hash>,
    Hash,
    Vec<[BaseElement; 4]>,
    Vec<[BaseElement; 4]>,
    Vec<usize>,
    Vec<usize>,
    Vec<Vec<Hash>>,
    Vec<Vec<Hash>>,
    Vec<BaseElement>,
    Vec<Scalar>,
) {
    let now = Instant::now();

    let mut rng = OsRng;
    let num_values = usize::pow(2, MERKLE_TREE_DEPTH as u32);
    // Ensure values are of appropriate size
    // TODO: Change this and the size bound on delta if RANGE_LOG changes
    let mut value_elements = Vec::with_capacity(num_values * 2);
    let mut secret_keys = Vec::with_capacity(num_values);
    let mut values = Vec::with_capacity(num_values);
    let mut leaves = Vec::with_capacity(num_values);
    for i in 0..num_values {
        value_elements.push(rng.next_u64());
        value_elements.push(rng.next_u64());
        let skey = Scalar::random(&mut rng);
        secret_keys.push(skey);
        let pkey = AffinePoint::from(AffinePoint::generator() * skey);
        let value1 = BaseElement::from(value_elements[i * 2]);
        let value2 = BaseElement::from(value_elements[i * 2 + 1]);
        values.push([pkey.get_x(), pkey.get_y(), value1, value2]);
        leaves.push(Rescue252::merge(&[
            Hash::new(pkey.get_x(), pkey.get_y()),
            Hash::new(value1, value2),
        ]));
    }
    let mut tree = MerkleTree::<Rescue252>::new(leaves.clone()).unwrap();
    debug!(
        "Built Merkle tree of depth {} in {} ms",
        MERKLE_TREE_DEPTH,
        now.elapsed().as_millis(),
    );
    let mut initial_roots = Vec::new();
    // Initialize the vectors
    let mut s_secret_keys = vec![Scalar::zero(); num_transactions];
    let mut s_old_values = vec![[BaseElement::ZERO; 4]; num_transactions];
    let mut r_old_values = vec![[BaseElement::ZERO; 4]; num_transactions];
    let mut s_indices = vec![0; num_transactions];
    let mut r_indices = vec![0; num_transactions];
    const EMPTY_PATH: Vec<Hash> = Vec::new();
    let mut s_paths = vec![EMPTY_PATH; num_transactions];
    let mut r_paths = vec![EMPTY_PATH; num_transactions];
    let mut deltas = vec![BaseElement::ZERO; num_transactions];

    let now = Instant::now();
    // Repeat basic process for every transaction
    for transaction_num in 0..num_transactions {
        // Get random indices and amount to change the accounts by
        let tree_size = u128::pow(2, MERKLE_TREE_DEPTH as u32) as usize;
        let s_index = (BaseElement::random(&mut rng).to_repr().0[0] as usize) % tree_size;
        // Make sure receiver is not the same as sender
        let r_index = (s_index
            + 1
            + ((BaseElement::random(&mut rng).to_repr().0[0] as usize) % (tree_size - 1)))
            % tree_size as usize;
        assert_ne!(s_index, r_index);

        let delta = BaseElement::from(rng.next_u64() % values[s_index][2].to_repr().0[0]);

        // Store the old values, indices, and delta
        initial_roots.push(*tree.root());
        s_secret_keys[transaction_num] = secret_keys[s_index];
        s_old_values[transaction_num] = values[s_index];
        r_old_values[transaction_num] = values[r_index];
        s_indices[transaction_num] = s_index;
        r_indices[transaction_num] = r_index;
        deltas[transaction_num] = delta;

        // Compute Merkle path for the leaf specified by the sender index
        s_paths[transaction_num] = tree.prove(s_index).unwrap();

        // Update the Merkle tree with the new values at the same indices
        values[s_index][2] -= delta;
        values[s_index][3] += BaseElement::ONE;
        values[r_index][2] += delta;
        leaves[s_index] = Rescue252::merge(&[
            Hash::new(values[s_index][0], values[s_index][1]),
            Hash::new(values[s_index][2], values[s_index][3]),
        ]);
        leaves[r_index] = Rescue252::merge(&[
            Hash::new(values[r_index][0], values[r_index][1]),
            Hash::new(values[r_index][2], values[r_index][3]),
        ]);
        tree.update_leaf(s_index, leaves[s_index]);
        tree.update_leaf(r_index, leaves[r_index]);

        // Compute Merkle path for the leaf specified by the receiver index
        r_paths[transaction_num] = tree.prove(r_index).unwrap();
    }
    let final_root = *tree.root();
    debug!(
        "Updated Merkle tree with {} transactions to root {} in {} ms",
        num_transactions,
        hex::encode(<<Rescue252 as Hasher>::Digest>::as_bytes(&final_root)),
        now.elapsed().as_millis(),
    );

    (
        initial_roots,
        final_root,
        s_old_values,
        r_old_values,
        s_indices,
        r_indices,
        s_paths,
        r_paths,
        deltas,
        // Necessary for Schnorr signatures
        s_secret_keys,
    )
}
