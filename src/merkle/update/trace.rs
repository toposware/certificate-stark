// Copyright (c) ToposWare and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::constants::*;
use crate::utils::rescue;
use winterfell::{
    math::{fields::f252::BaseElement, FieldElement},
    ExecutionTrace,
};

#[cfg(feature = "concurrent")]
use winterfell::iterators::*;

// TRACE GENERATOR
// ================================================================================================

pub fn build_trace(
    initial_roots: &[rescue::Hash],
    s_old_values: &[[BaseElement; 4]],
    r_old_values: &[[BaseElement; 4]],
    s_indices: &[usize],
    r_indices: &[usize],
    s_branches: &[Vec<rescue::Hash>],
    r_branches: &[Vec<rescue::Hash>],
    deltas: &[BaseElement],
    num_transactions: usize,
) -> ExecutionTrace<BaseElement> {
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
                        s_branches[i].clone(),
                        r_branches[i].clone(),
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
    s_old_value: [BaseElement; 4],
    r_old_value: [BaseElement; 4],
    delta: BaseElement,
    state: &mut [BaseElement],
) {
    // Initialize the first row of any given transaction
    let init_root = initial_root.to_elements();

    state[SENDER_INITIAL_POS..SENDER_INITIAL_POS + 4].copy_from_slice(&s_old_value);
    state[SENDER_BIT_POS] = BaseElement::ZERO;
    state[SENDER_UPDATED_POS..SENDER_UPDATED_POS + 4].copy_from_slice(&s_old_value);
    // Update sender's balance
    state[SENDER_UPDATED_POS + 2] -= delta;
    // Update sender's nonce
    state[SENDER_UPDATED_POS + 3] += BaseElement::ONE;

    state[RECEIVER_INITIAL_POS..RECEIVER_INITIAL_POS + 4].copy_from_slice(&r_old_value);
    state[RECEIVER_BIT_POS] = BaseElement::ZERO;
    state[RECEIVER_UPDATED_POS..RECEIVER_UPDATED_POS + 4].copy_from_slice(&r_old_value);
    // Update receivers's balance
    state[RECEIVER_UPDATED_POS + 2] += delta;

    state[PREV_TREE_ROOT_POS] = init_root[0];
    state[PREV_TREE_ROOT_POS + 1] = init_root[1]
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
    // is ZERO, the next node goes into registers [2, 3], if it is ONE, the node goes into
    // registers [0, 1]. On all steps between these, the vlaues are simply copied.

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
        state[PREV_TREE_ROOT_POS] = state[RECEIVER_UPDATED_POS];
        state[PREV_TREE_ROOT_POS + 1] = state[RECEIVER_UPDATED_POS + 1];
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
            // If index bit is zero, new branch node goes into registers [2, 3]; values in
            // registers [0, 1] (the accumulated hash) remain unchanged
            state[2] = branch_node[0];
            state[3] = branch_node[1];
            state[HASH_STATE_WIDTH + 3] = branch_node[0];
            state[HASH_STATE_WIDTH + 4] = branch_node[1];
        } else {
            // If index bit is one, accumulated hash goes into registers [2, 3],
            // and new branch nodes go into registers [0, 1]
            state[2] = state[0];
            state[3] = state[1];
            state[HASH_STATE_WIDTH + 3] = state[HASH_STATE_WIDTH + 1];
            state[HASH_STATE_WIDTH + 4] = state[HASH_STATE_WIDTH + 2];
            state[0] = branch_node[0];
            state[1] = branch_node[1];
            state[HASH_STATE_WIDTH + 1] = branch_node[0];
            state[HASH_STATE_WIDTH + 2] = branch_node[1];
        }
        // reset the capacity registers of the state to ZERO
        // TODO: Remove if there are no extra registers
        for index in [0, HASH_STATE_WIDTH + 1] {
            for offset in 4..HASH_STATE_WIDTH {
                state[index + offset] = BaseElement::ZERO;
            }
        }

        // Store the index bit in the "middle lane"
        state[HASH_STATE_WIDTH] = index_bit;
    }
}
