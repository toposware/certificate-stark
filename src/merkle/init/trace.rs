// Copyright (c) ToposWare and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::constants::*;
use winterfell::{
    math::{fields::f252::BaseElement, FieldElement},
    ExecutionTrace,
};

use crate::utils::rescue;

// TRACE BUILDER
// ------------------------------------------------------------------------------------------------

pub fn build_trace(
    s_inputs: [BaseElement; 4],
    r_inputs: [BaseElement; 4],
    delta: BaseElement,
) -> ExecutionTrace<BaseElement> {
    // allocate memory to hold the trace table
    let mut trace = ExecutionTrace::new(TRACE_WIDTH, TRANSACTION_CYCLE_LENGTH);

    trace.fill(
        |state| {
            // initialize first state of the computation
            init_merkle_initialization_state(state, s_inputs, r_inputs, delta);
        },
        |step, state| {
            // execute the transition function for all steps
            update_merkle_initialization_state(step, state);
        },
    );

    trace
}

// TRACE INITIALIZATION
// ================================================================================================

pub fn init_merkle_initialization_state(
    state: &mut [BaseElement],
    s_inputs: [BaseElement; 4],
    r_inputs: [BaseElement; 4],
    delta: BaseElement,
) {
    // Sender's initial state in the initial merkle tree.
    // The first 12 registers are the sender's public key...
    state[SENDER_INITIAL_POS..SENDER_INITIAL_POS + 12].copy_from_slice(&s_inputs[0..12]);
    // then the coins...
    state[SENDER_UPDATED_POS + 12] = s_inputs[12];
    // and the nonce.
    state[SENDER_UPDATED_POS + 13] = s_inputs[13];

    // Sender's updated state.
    state[SENDER_UPDATED_POS..SENDER_UPDATED_POS + 12].copy_from_slice(&s_inputs[0..12]);
    state[SENDER_UPDATED_POS + 12] = s_inputs[12] - delta;
    state[SENDER_UPDATED_POS + 13] = s_inputs[13] + BaseElement::ONE;

    // Receiver's intial state is composed by the public key...
    state[RECEIVER_INITIAL_POS..RECEIVER_INITIAL_POS + 12].copy_from_slice(&r_inputs[0..12]);
    // then the coins...
    state[RECEIVER_INITIAL_POS + 12] = r_inputs[12];
    // and the nonce.
    state[RECEIVER_INITIAL_POS + 13] = r_inputs[13];

    // Receiver's final state.
    state[RECEIVER_UPDATED_POS..RECEIVER_UPDATED_POS + 12].copy_from_slice(&r_inputs[0..12]);
    state[RECEIVER_UPDATED_POS + 12] = r_inputs[12] + delta;
    state[RECEIVER_UPDATED_POS + 13] = r_inputs[13];
}

// TRACE TRANSITION FUNCTION
// ================================================================================================

pub fn update_merkle_initialization_state(step: usize, state: &mut [BaseElement]) {
    // Evaluate H(pk||coins||nonce)
    rescue::apply_round(
        &mut state[SENDER_INITIAL_POS..SENDER_INITIAL_POS + HASH_STATE_WIDTH],
        step,
    );
    rescue::apply_round(
        &mut state[SENDER_UPDATED_POS..SENDER_UPDATED_POS + HASH_STATE_WIDTH],
        step,
    );
    rescue::apply_round(
        &mut state[RECEIVER_INITIAL_POS..RECEIVER_INITIAL_POS + HASH_STATE_WIDTH],
        step,
    );
    rescue::apply_round(
        &mut state[RECEIVER_UPDATED_POS..RECEIVER_UPDATED_POS + HASH_STATE_WIDTH],
        step,
    );
}
