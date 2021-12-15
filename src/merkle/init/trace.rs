// Copyright (c) Toposware, Inc. 2021
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::constants::*;
use winterfell::{
    math::{fields::f63::BaseElement, FieldElement},
    ExecutionTrace,
};

use crate::utils::rescue;

// TRACE BUILDER
// ------------------------------------------------------------------------------------------------

pub fn build_trace(
    s_inputs: [BaseElement; AFFINE_POINT_WIDTH + 2],
    r_inputs: [BaseElement; AFFINE_POINT_WIDTH + 2],
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
    s_inputs: [BaseElement; AFFINE_POINT_WIDTH + 2],
    r_inputs: [BaseElement; AFFINE_POINT_WIDTH + 2],
    delta: BaseElement,
) {
    // Sender's initial state in the initial merkle tree.
    // The first AFFINE_POINT_WIDTH registers are the sender's public key...
    state[SENDER_INITIAL_POS..SENDER_INITIAL_POS + AFFINE_POINT_WIDTH]
        .copy_from_slice(&s_inputs[0..AFFINE_POINT_WIDTH]);
    // then the coins...
    state[SENDER_UPDATED_POS + AFFINE_POINT_WIDTH] = s_inputs[AFFINE_POINT_WIDTH];
    // and the nonce.
    state[SENDER_UPDATED_POS + AFFINE_POINT_WIDTH + 1] = s_inputs[AFFINE_POINT_WIDTH + 1];

    // Sender's updated state.
    state[SENDER_UPDATED_POS..SENDER_UPDATED_POS + AFFINE_POINT_WIDTH]
        .copy_from_slice(&s_inputs[0..AFFINE_POINT_WIDTH]);
    state[SENDER_UPDATED_POS + AFFINE_POINT_WIDTH] = s_inputs[AFFINE_POINT_WIDTH] - delta;
    state[SENDER_UPDATED_POS + AFFINE_POINT_WIDTH + 1] =
        s_inputs[AFFINE_POINT_WIDTH + 1] + BaseElement::ONE;

    // Receiver's intial state is composed by the public key...
    state[RECEIVER_INITIAL_POS..RECEIVER_INITIAL_POS + AFFINE_POINT_WIDTH]
        .copy_from_slice(&r_inputs[0..AFFINE_POINT_WIDTH]);
    // then the coins...
    state[RECEIVER_INITIAL_POS + AFFINE_POINT_WIDTH] = r_inputs[AFFINE_POINT_WIDTH];
    // and the nonce.
    state[RECEIVER_INITIAL_POS + AFFINE_POINT_WIDTH + 1] = r_inputs[AFFINE_POINT_WIDTH + 1];

    // Receiver's final state.
    state[RECEIVER_UPDATED_POS..RECEIVER_UPDATED_POS + AFFINE_POINT_WIDTH]
        .copy_from_slice(&r_inputs[0..AFFINE_POINT_WIDTH]);
    state[RECEIVER_UPDATED_POS + AFFINE_POINT_WIDTH] = r_inputs[AFFINE_POINT_WIDTH] + delta;
    state[RECEIVER_UPDATED_POS + AFFINE_POINT_WIDTH + 1] = r_inputs[AFFINE_POINT_WIDTH + 1];
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
