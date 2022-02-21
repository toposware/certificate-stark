// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::constants::*;
use crate::utils::rescue::{self, HASH_CYCLE_MASK};
use crate::utils::{are_equal, is_binary, not, EvaluationResult};
use winterfell::{
    math::{fields::f63::BaseElement, FieldElement},
    Air, AirContext, Assertion, ByteWriter, EvaluationFrame, ProofOptions, Serializable, TraceInfo,
    TransitionConstraintDegree,
};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

// MERKLE PATH VERIFICATION AIR
// ================================================================================================

pub struct PublicInputs {
    pub initial_root: [BaseElement; HASH_RATE_WIDTH],
    pub final_root: [BaseElement; HASH_RATE_WIDTH],
}

impl Serializable for PublicInputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(&self.initial_root[..]);
        target.write(&self.final_root[..]);
    }
}

pub struct MerkleAir {
    context: AirContext<BaseElement>,
    initial_root: [BaseElement; HASH_RATE_WIDTH],
    final_root: [BaseElement; HASH_RATE_WIDTH],
}

impl Air for MerkleAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        let degrees = transition_constraint_degrees(TRANSACTION_CYCLE_LENGTH);

        assert_eq!(TRACE_WIDTH, trace_info.width());
        MerkleAir {
            context: AirContext::new(trace_info, degrees, options),
            initial_root: pub_inputs.initial_root,
            final_root: pub_inputs.final_root,
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
        // expected state width is 4 hashes and 2 bit decompositions
        debug_assert_eq!(TRACE_WIDTH, current.len());
        debug_assert_eq!(TRACE_WIDTH, next.len());

        // split periodic values into masks and Rescue round constants
        let transaction_setup_flag = periodic_values[0];
        let transaction_hash_flag = periodic_values[1];
        let hash_input_flag = periodic_values[2];
        let transaction_finish_flag = periodic_values[3];
        let hash_flag = periodic_values[4];
        let ark = &periodic_values[5..];

        // Enforce no change in registers representing keys
        for i in 0..AFFINE_POINT_WIDTH {
            result.agg_constraint(
                VALUE_CONSTRAINT_RES + i,
                transaction_setup_flag,
                are_equal(
                    current[SENDER_INITIAL_POS + i],
                    current[SENDER_UPDATED_POS + i],
                ),
            );

            result.agg_constraint(
                VALUE_CONSTRAINT_RES + AFFINE_POINT_WIDTH + i,
                transaction_setup_flag,
                are_equal(
                    current[RECEIVER_INITIAL_POS + i],
                    current[RECEIVER_UPDATED_POS + i],
                ),
            );
        }

        // Enforce no change in the receiver's nonce
        result.agg_constraint(
            VALUE_CONSTRAINT_RES + AFFINE_POINT_WIDTH * 2,
            transaction_setup_flag,
            are_equal(
                current[RECEIVER_INITIAL_POS + AFFINE_POINT_WIDTH + 1],
                current[RECEIVER_UPDATED_POS + AFFINE_POINT_WIDTH + 1],
            ),
        );

        // Enforce that the change in balances cancels out
        result.agg_constraint(
            BALANCE_CONSTRAINT_RES,
            transaction_setup_flag,
            are_equal(
                current[SENDER_INITIAL_POS + AFFINE_POINT_WIDTH]
                    - current[SENDER_UPDATED_POS + AFFINE_POINT_WIDTH],
                current[RECEIVER_UPDATED_POS + AFFINE_POINT_WIDTH]
                    - current[RECEIVER_INITIAL_POS + AFFINE_POINT_WIDTH],
            ),
        );

        // Enforce change in the sender's nonce
        result.agg_constraint(
            NONCE_UPDATE_CONSTRAINT_RES,
            transaction_setup_flag,
            are_equal(
                current[SENDER_UPDATED_POS + AFFINE_POINT_WIDTH + 1],
                current[SENDER_INITIAL_POS + AFFINE_POINT_WIDTH + 1] + E::ONE,
            ),
        );

        evaluate_constraints(
            result,
            current,
            next,
            ark,
            transaction_hash_flag,
            hash_input_flag,
            hash_flag,
            transaction_finish_flag,
        );
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        // assert that Merkle path resolves to the tree root, and that hash capacity
        // registers are reset to ZERO every 8 steps
        // Now we must also resolve to the new root and the next registers are also
        // hash capacity registers
        // Additionally, we repeat all of this for the receiver
        let last_step = self.trace_length() - 1;
        let mut vec = Vec::with_capacity(HASH_STATE_WIDTH);
        for i in 0..HASH_RATE_WIDTH {
            vec.push(Assertion::single(
                PREV_TREE_ROOT_POS + i,
                0,
                self.initial_root[i],
            ));
        }
        for i in 0..HASH_RATE_WIDTH {
            vec.push(Assertion::single(
                PREV_TREE_ROOT_POS + i,
                last_step,
                self.final_root[i],
            ));
        }

        vec
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        periodic_columns()
    }
}

// HELPER FUNCTIONS
// ================================================================================================

pub(crate) fn periodic_columns() -> Vec<Vec<BaseElement>> {
    // Mask for anything that must be applied at the beginning of a transaction
    let mut transaction_setup_mask = vec![BaseElement::ZERO; TRANSACTION_CYCLE_LENGTH];
    transaction_setup_mask[0] = BaseElement::ONE;
    // Mask for indicating hashes are still being computs
    let mut transaction_hash_mask = vec![BaseElement::ONE; TRANSACTION_HASH_LENGTH];
    transaction_hash_mask.append(&mut vec![
        BaseElement::ZERO;
        TRANSACTION_CYCLE_LENGTH - TRANSACTION_HASH_LENGTH
    ]);
    // Mask for any setup between levels of the Merkle tree
    let mut hash_input_mask = vec![BaseElement::ZERO; HASH_CYCLE_LENGTH];
    hash_input_mask[HASH_CYCLE_LENGTH - 1] = BaseElement::ONE;
    // Mask for anything that must be applied at the end of the hashes
    let mut transaction_finish_hash_mask = vec![BaseElement::ZERO; TRANSACTION_CYCLE_LENGTH];
    transaction_finish_hash_mask[TRANSACTION_HASH_LENGTH - 1] = BaseElement::ONE;
    // Mask for when to apply hash rounds
    let mut hash_mask = Vec::new();
    for i in 0..TRANSACTION_CYCLE_LENGTH {
        hash_mask.push(transaction_hash_mask[i] * HASH_CYCLE_MASK[i % HASH_CYCLE_LENGTH]);
    }
    let mut result = vec![
        transaction_setup_mask,
        transaction_hash_mask,
        hash_input_mask,
        transaction_finish_hash_mask,
    ];
    result.append(&mut vec![hash_mask]);
    result.append(&mut rescue::get_round_constants());
    result
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn evaluate_constraints<E: FieldElement + From<BaseElement>>(
    result: &mut [E],
    current: &[E],
    next: &[E],
    ark: &[E],
    transaction_hash_flag: E,
    hash_input_flag: E,
    hash_flag: E,
    transaction_finish_flag: E,
) {
    // Compute flags dependent on other flag for convenience
    // Compute the inverse of tre transaction finish flag for convenience
    let not_transaction_finish_flag = not(transaction_finish_flag);

    // Enforce the proper computation of hashes along the Merkle authentication peth
    evaluate_merkle_update_auth(
        &mut result[SENDER_INITIAL_RES..RECEIVER_INITIAL_RES],
        &current[SENDER_INITIAL_POS..RECEIVER_INITIAL_POS],
        &next[SENDER_INITIAL_POS..RECEIVER_INITIAL_POS],
        ark,
        transaction_hash_flag,
        hash_input_flag,
        hash_flag,
    );
    evaluate_merkle_update_auth(
        &mut result[RECEIVER_INITIAL_RES..PREV_TREE_ROOT_RES],
        &current[RECEIVER_INITIAL_POS..PREV_TREE_ROOT_POS],
        &next[RECEIVER_INITIAL_POS..PREV_TREE_ROOT_POS],
        ark,
        transaction_hash_flag,
        hash_input_flag,
        hash_flag,
    );

    // Enforce proper copying of the previous root hash for continuity between one transaction and the next
    for i in 0..HASH_RATE_WIDTH {
        result.agg_constraint(
            PREV_TREE_ROOT_RES + i,
            not_transaction_finish_flag,
            are_equal(
                next[PREV_TREE_ROOT_POS + i],
                current[PREV_TREE_ROOT_POS + i],
            ),
        );
        result.agg_constraint(
            PREV_TREE_ROOT_RES + i,
            transaction_finish_flag,
            are_equal(next[PREV_TREE_ROOT_POS + i], next[RECEIVER_UPDATED_POS + i]),
        );
    }

    // Enforce equality of the intermediate hash for continuity between sender and receiver updates
    for i in 0..HASH_RATE_WIDTH {
        result.agg_constraint(
            INT_ROOT_EQUALITY_RES + i,
            transaction_finish_flag,
            are_equal(
                current[SENDER_UPDATED_POS + i],
                current[RECEIVER_INITIAL_POS + i],
            ),
        );
    }

    // Enforce a match between the previous root after recevier update and the current root before sender update
    for i in 0..HASH_RATE_WIDTH {
        result.agg_constraint(
            PREV_TREE_MATCH_RES + i,
            transaction_finish_flag,
            are_equal(
                next[SENDER_INITIAL_POS + i],
                current[PREV_TREE_ROOT_POS + i],
            ),
        );
    }
}

pub(crate) fn evaluate_merkle_update_auth<E: FieldElement + From<BaseElement>>(
    result: &mut [E],
    current: &[E],
    next: &[E],
    ark: &[E],
    transaction_hash_flag: E,
    hash_input_flag: E,
    hash_flag: E,
) {
    // Compute flags dependent on other flag for conveniences
    // Flag for when to copy results to the next level as hash inputs
    let hash_copy_flag = transaction_hash_flag * not(hash_flag + hash_input_flag);
    // Flag for when to enforce proper positioning of hash inputs
    let hash_init_flag = transaction_hash_flag * hash_input_flag;

    // Get the bit of the index representing location in the tree
    let bit = next[HASH_STATE_WIDTH];
    // Enforce that values in the bit registers must be binary
    result.agg_constraint(HASH_STATE_WIDTH, transaction_hash_flag, is_binary(bit));
    // Compute the inverse of the bit for convenience
    let not_bit = not(bit);

    // Perform these steps for each of the hash register clusters
    for (res_index, reg_index) in [(0, 0), (HASH_STATE_WIDTH + 1, HASH_STATE_WIDTH + 1)] {
        // When transaction_hash_flag = hash_flag = 1, constraints for Rescue round are enforced
        rescue::enforce_round(
            &mut result[res_index..res_index + HASH_STATE_WIDTH],
            &current[reg_index..reg_index + HASH_STATE_WIDTH],
            &next[reg_index..reg_index + HASH_STATE_WIDTH],
            ark,
            hash_flag,
        );

        for i in 0..HASH_RATE_WIDTH {
            // Copy outputs of hashes to next level as inputs
            result.agg_constraint(
                res_index + i,
                hash_copy_flag,
                are_equal(current[reg_index + i], next[reg_index + i]),
            );

            // When hash_flag = 0, make sure accumulated hash is placed in the right place in the hash
            // state for the next round of hashing. Specifically: when index bit = 0, accumulated hash
            // must go into the capacity registers, and when index bit = 1, it must go into the rate registers
            result.agg_constraint(
                res_index + i,
                hash_init_flag,
                not_bit * are_equal(current[reg_index + i], next[reg_index + i]),
            );

            result.agg_constraint(
                res_index + HASH_RATE_WIDTH + i,
                hash_init_flag,
                bit * are_equal(
                    current[reg_index + i],
                    next[reg_index + HASH_RATE_WIDTH + i],
                ),
            );
        }
    }

    // Ensure that the same sibling hashes are fed in for proof of update. Must be in whichever
    // positions were not used above
    for i in 0..HASH_RATE_WIDTH {
        result.agg_constraint(
            i,
            hash_init_flag,
            bit * are_equal(next[HASH_STATE_WIDTH + 1 + i], next[i]),
        );
    }

    for i in HASH_RATE_WIDTH..HASH_STATE_WIDTH {
        result.agg_constraint(
            i,
            hash_init_flag,
            not_bit * are_equal(next[HASH_STATE_WIDTH + 1 + i], next[i]),
        );
    }
}

pub(crate) fn transition_constraint_degrees(
    cycle_length: usize,
) -> Vec<TransitionConstraintDegree> {
    // Constraint degrees for enforcement of Rescue hash rounds
    let mut hash_constraint_degrees =
        vec![TransitionConstraintDegree::with_cycles(3, vec![cycle_length]); HASH_STATE_WIDTH];

    // Constraint degrees of authentication paths for a Merkle tree update
    let mut update_auth_degrees = hash_constraint_degrees.clone();
    // Bits of index into Merkle tree
    update_auth_degrees.push(TransitionConstraintDegree::with_cycles(
        2,
        vec![cycle_length],
    ));

    // Initial value hash constraints
    update_auth_degrees.append(&mut hash_constraint_degrees);

    // Remaining constraints (prev root copy, balance update, intermediate root match, and prev root match)
    let mut remaining_degrees = vec![
        TransitionConstraintDegree::with_cycles(1, vec![cycle_length]);
        PREV_TREE_MATCH_RES + HASH_RATE_WIDTH - PREV_TREE_ROOT_RES
    ];

    // Degrees for all constraints
    let mut degrees = update_auth_degrees.clone();
    degrees.append(&mut update_auth_degrees);
    degrees.append(&mut remaining_degrees);

    degrees
}
