// Copyright (c) ToposWare and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::constants::*;
use crate::utils::rescue::{self, RATE_WIDTH};
use crate::TransactionMetadata;
use winterfell::{
    math::{fields::f63::BaseElement, FieldElement},
    ExecutionTrace,
};

#[cfg(feature = "concurrent")]
use winterfell::iterators::*;

// TRACE GENERATOR
// ================================================================================================

#[allow(clippy::too_many_arguments)]
pub fn build_trace(tx_metadata: &TransactionMetadata) -> ExecutionTrace<BaseElement> {
    let initial_roots = &tx_metadata.initial_roots;
    let s_old_values = &tx_metadata.s_old_values;
    let r_old_values = &tx_metadata.r_old_values;
    let s_indices = &tx_metadata.s_indices;
    let r_indices = &tx_metadata.r_indices;
    let s_paths = &tx_metadata.s_paths;
    let r_paths = &tx_metadata.r_paths;
    let deltas = &tx_metadata.deltas;

    let num_transactions = tx_metadata.initial_roots.len();

    // allocate memory to hold the trace table
    let mut trace = ExecutionTrace::new(TRACE_WIDTH, num_transactions * TRANSACTION_CYCLE_LENGTH);

    // Apply the same init and update steps for each separate transaction
    trace
        .fragments(TRANSACTION_CYCLE_LENGTH)
        .for_each(|mut merkle_trace| {
            let i = merkle_trace.index();

            merkle_trace.fill(
                |state| {
                    init_merkle_update_state(
                        initial_roots[i],
                        s_old_values[i],
                        r_old_values[i],
                        deltas[i],
                        state,
                    );
                },
                |step, state| {
                    update_merkle_update_state(
                        step,
                        s_indices[i],
                        r_indices[i],
                        s_paths[i].clone(),
                        r_paths[i].clone(),
                        state,
                    );
                },
            )
        });

    // set index bit at the second step to one; this still results in a valid execution trace
    // because actual index bits are inserted into the trace after step 7, but it ensures
    // that there are no repeating patterns in the index bit register, and thus the degree
    // of the index bit constraint is stable.
    trace.set(SENDER_BIT_POS, 1, FieldElement::ONE);
    trace.set(RECEIVER_BIT_POS, 1, FieldElement::ONE);

    trace
}

// TRACE INITIALIZATION
// ================================================================================================

pub fn init_merkle_update_state(
    initial_root: rescue::Hash,
    s_old_value: [BaseElement; AFFINE_POINT_WIDTH + 2],
    r_old_value: [BaseElement; AFFINE_POINT_WIDTH + 2],
    delta: BaseElement,
    state: &mut [BaseElement],
) {
    // Initialize the first row of any given transaction
    let init_root = initial_root.to_elements();

    state[SENDER_INITIAL_POS..SENDER_INITIAL_POS + AFFINE_POINT_WIDTH + 2]
        .copy_from_slice(&s_old_value);
    state[SENDER_BIT_POS] = BaseElement::ZERO;
    state[SENDER_UPDATED_POS..SENDER_UPDATED_POS + AFFINE_POINT_WIDTH + 2]
        .copy_from_slice(&s_old_value);
    // Update sender's balance
    state[SENDER_UPDATED_POS + AFFINE_POINT_WIDTH] -= delta;
    // Update sender's nonce
    state[SENDER_UPDATED_POS + AFFINE_POINT_WIDTH + 1] += BaseElement::ONE;

    state[RECEIVER_INITIAL_POS..RECEIVER_INITIAL_POS + AFFINE_POINT_WIDTH + 2]
        .copy_from_slice(&r_old_value);
    state[RECEIVER_BIT_POS] = BaseElement::ZERO;
    state[RECEIVER_UPDATED_POS..RECEIVER_UPDATED_POS + AFFINE_POINT_WIDTH + 2]
        .copy_from_slice(&r_old_value);
    // Update receivers's balance
    state[RECEIVER_UPDATED_POS + AFFINE_POINT_WIDTH] += delta;

    state[PREV_TREE_ROOT_POS..PREV_TREE_ROOT_POS + RATE_WIDTH].copy_from_slice(&init_root);
}

// TRANSITION FUNCTION
// ================================================================================================

pub fn update_merkle_update_state(
    step: usize,
    s_index: usize,
    r_index: usize,
    s_branch: Vec<rescue::Hash>,
    r_branch: Vec<rescue::Hash>,
    state: &mut [BaseElement],
) {
    // Execute the transition function for all steps
    //
    // For the first NUM_HASH_ROUNDS steps of each cycle, compute a single round of Rescue
    // hash in registers [0..HASH_STATE_WIDTH]. On the final step, insert the next branch node
    // into the trace in the positions defined by the next bit of the leaf index. If the bit
    // is ZERO, the next node goes into the rate registers, if it is ONE, the node goes into
    // the capacity registers. On all steps between these, the values are simply copied.

    let transaction_pos = step;

    // Perform steps only if the Merkle tree authetication is still in progress
    if transaction_pos < TRANSACTION_HASH_LENGTH {
        // The hashes for a transaction are being computed, so fill with update authentication path steps
        update_merkle_update_auth_state(
            transaction_pos,
            s_index,
            s_branch,
            &mut state[SENDER_INITIAL_POS..RECEIVER_INITIAL_POS],
        );
        update_merkle_update_auth_state(
            transaction_pos,
            r_index,
            r_branch,
            &mut state[RECEIVER_INITIAL_POS..PREV_TREE_ROOT_POS],
        );
    }
    if transaction_pos == TRANSACTION_HASH_LENGTH - 1 {
        // The hashes for the transaction have completed, so copy
        // the previous root to store until the next cycle
        for i in 0..RATE_WIDTH {
            state[PREV_TREE_ROOT_POS + i] = state[RECEIVER_UPDATED_POS + i];
        }
    }
}

pub fn update_merkle_update_auth_state(
    transaction_pos: usize,
    index: usize,
    branch: Vec<rescue::Hash>,
    state: &mut [BaseElement],
) {
    // Compute the segment of the path we are on and the position in that cycle
    let cycle_num = transaction_pos / HASH_CYCLE_LENGTH;
    let cycle_pos = transaction_pos % HASH_CYCLE_LENGTH;
    // The hashes for a transaction are being computed, so enforce as usual
    if cycle_pos < NUM_HASH_ROUNDS {
        rescue::apply_round(&mut state[0..HASH_STATE_WIDTH], transaction_pos);
        rescue::apply_round(
            &mut state[HASH_STATE_WIDTH + 1..2 * HASH_STATE_WIDTH + 1],
            transaction_pos,
        );
    } else if cycle_pos == HASH_CYCLE_LENGTH - 1 {
        let branch_node = branch[cycle_num + 1].to_elements();
        let index_bit = BaseElement::from(((index >> cycle_num) & 1) as u128);
        if index_bit == BaseElement::ZERO {
            // If index bit is zero, new branch node goes into rate registers; values in
            // capacity registers (the accumulated hash) remain unchanged
            for i in 0..RATE_WIDTH {
                state[RATE_WIDTH + i] = branch_node[i];
                state[HASH_STATE_WIDTH + 1 + RATE_WIDTH + i] = branch_node[i];
            }
        } else {
            // If index bit is one, accumulated hash goes into rate registers,
            // and new branch nodes go into capacity registers
            for i in 0..RATE_WIDTH {
                state[RATE_WIDTH + i] = state[i];
                state[HASH_STATE_WIDTH + 1 + RATE_WIDTH + i] = state[HASH_STATE_WIDTH + 1 + i];
                state[i] = branch_node[i];
                state[HASH_STATE_WIDTH + 1 + i] = branch_node[i];
            }
        }

        // Store the index bit in the "middle lane"
        state[HASH_STATE_WIDTH] = index_bit;
    }
}
