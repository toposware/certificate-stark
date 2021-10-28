// Copyright (c) ToposWare and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

pub mod merkle;
pub mod range;
pub mod schnorr;
pub mod utils;
use utils::rescue::Rescue252;

mod air;
use air::{PublicInputs, TransactionAir};

pub mod constants;

mod trace;
pub use trace::build_trace;

use log::debug;
use rand_core::{OsRng, RngCore};
use std::time::Instant;
use utils::rescue::Hash;
use winterfell::{
    crypto::{Digest, Hasher, MerkleTree},
    math::{
        curve::{AffinePoint, Scalar},
        fields::f252::BaseElement,
        log2, FieldElement, StarkField,
    },
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
        winterfell::prove::<TransactionAir>(trace, pub_inputs, self.options.clone()).unwrap()
    }

    pub fn verify(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            initial_root: self.tx_metadata.initial_roots[0].to_elements(),
            final_root: self.tx_metadata.final_root.to_elements(),
        };
        winterfell::verify::<TransactionAir>(proof, pub_inputs)
    }

    pub fn verify_with_wrong_inputs(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let initial_root = self.tx_metadata.initial_roots[0].to_elements();
        let final_root = self.tx_metadata.final_root.to_elements();
        let pub_inputs = PublicInputs {
            initial_root,
            final_root: [final_root[1], final_root[0]],
        };
        winterfell::verify::<TransactionAir>(proof, pub_inputs)
    }
}

// TRANSACTION METADATA
// ================================================================================================

/// A set of variables indicating a series of `num_transactions` updates in a Merkle tree,
/// represented as transactions from a sender to a receiver.
///
/// - `initial_roots`: intermediate Merkle tree roots prior each transaction
/// - `final_root`: final Merkle tree root after applying all transactions
/// - `s_old_values`: sender leaves prior each transaction. Each tree leaf represents:
///   - the account public key's x affine coordinate
///   - the account public key's y affine coordinate
///   - the account balance
///   - the account nonce
/// - `r_old_values` : receiver leaves prior each transaction
/// - `s_paths` : sender's Merkle path prior each transaction
/// - `r_paths` : receiver's Merkle path prior each transaction
/// - `deltas` : amounts to be sent in each transaction
/// - `signatures` : signatures for each transaction
pub struct TransactionMetadata {
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

impl TransactionMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
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
    ) -> Self {
        // Enforce that all vectors are of equal length
        assert_eq!(initial_roots.len(), s_old_values.len());
        assert_eq!(initial_roots.len(), r_old_values.len());
        assert_eq!(initial_roots.len(), s_indices.len());
        assert_eq!(initial_roots.len(), r_indices.len());
        assert_eq!(initial_roots.len(), s_paths.len());
        assert_eq!(initial_roots.len(), deltas.len());
        assert_eq!(initial_roots.len(), signatures.len());

        TransactionMetadata {
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

    pub fn build_random(num_transactions: usize) -> Self {
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

        TransactionMetadata::new(
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
        )
    }
}
