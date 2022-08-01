// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::constants::*;
use crate::utils::rescue::{self, RATE_WIDTH};
use winterfell::math::{fields::f63::BaseElement, FieldElement};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

// TRACE INITIALIZATION
// ================================================================================================

pub(crate) fn init_merkle_update_state(
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

pub(crate) fn update_merkle_update_state(
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

pub(crate) fn update_merkle_update_auth_state(
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
