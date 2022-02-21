// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::constants::*;
use winterfell::math::{fields::f63::BaseElement, FieldElement};

use crate::utils::rescue;

// TRACE INITIALIZATION
// ================================================================================================

pub(crate) fn init_merkle_initialization_state(
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

pub(crate) fn update_merkle_initialization_state(step: usize, state: &mut [BaseElement]) {
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
