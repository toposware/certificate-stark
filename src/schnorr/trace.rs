// Copyright (c) ToposWare and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::constants::*;
use super::{ecc, field, rescue};
use bitvec::{order::Lsb0, slice::BitSlice, view::AsBits};
use core::cmp::Ordering;
use winterfell::{
    math::{curve::Scalar, fields::f252::BaseElement, FieldElement},
    ExecutionTrace,
};

#[cfg(feature = "concurrent")]
use winterfell::iterators::*;

// TRACE GENERATOR
// ================================================================================================

pub fn build_trace(
    messages: &[[BaseElement; 6]],
    signatures: &[(BaseElement, Scalar)],
) -> ExecutionTrace<BaseElement> {
    // allocate memory to hold the trace table
    let trace_length = SIG_CYCLE_LENGTH * messages.len();
    let mut trace = ExecutionTrace::new(TRACE_WIDTH, trace_length);

    trace.fragments(SIG_CYCLE_LENGTH).for_each(|mut sig_trace| {
        let i = sig_trace.index();
        let (pkey_point, s_bytes, h_bytes) = build_sig_info(&messages[i], &signatures[i]);
        let s_bits = s_bytes.as_bits::<Lsb0>();
        let h_bits = h_bytes.as_bits::<Lsb0>();

        sig_trace.fill(
            |state| {
                init_sig_verification_state(signatures[i], state);
            },
            |step, state| {
                update_sig_verification_state(step, messages[i], pkey_point, s_bits, h_bits, state);
            },
        );
    });

    trace
}

// TRACE INITIALIZATION
// ================================================================================================

pub fn init_sig_verification_state(signature: (BaseElement, Scalar), state: &mut [BaseElement]) {
    // initialize first state of the computation
    state[0] = BaseElement::ZERO; //  x(S), start from infinity
    state[1] = BaseElement::ONE; //   y(S)
    state[2] = BaseElement::ZERO; //  z(S)
    state[3] = BaseElement::ZERO; //  bin(s)

    state[4] = BaseElement::ZERO; //  x(h.P), start from infinity
    state[5] = BaseElement::ONE; //   y(h.P)
    state[6] = BaseElement::ZERO; //  z(h.P)
    state[7] = BaseElement::ZERO; //  bin(h)
    state[8] = BaseElement::ZERO; //  h, computed from bin(h)

    state[9] = signature.0; //        Rescue[0] = x(R)
    state[10] = BaseElement::ZERO; // Rescue[1] = 0
    state[11] = BaseElement::ZERO; // Rescue[2] = 0
    state[12] = BaseElement::ZERO; // Rescue[3] = 0
}

// TRANSITION FUNCTION
// ================================================================================================

pub fn update_sig_verification_state(
    step: usize,
    message: [BaseElement; 6],
    pkey_point: [BaseElement; 3],
    s_bits: &BitSlice<Lsb0, u8>,
    h_bits: &BitSlice<Lsb0, u8>,
    state: &mut [BaseElement],
) {
    let bit_length = SCALAR_MUL_LENGTH / 2;
    let rescue_flag = step < TOTAL_HASH_LENGTH;
    let rescue_step = step % HASH_CYCLE_LENGTH;

    // enforcing the three kind of rescue operations
    if rescue_flag && (rescue_step < NUM_HASH_ROUNDS) {
        // for the first 14 steps in every cycle, compute a single round of Rescue hash
        rescue::apply_round(&mut state[9..], step);
    } else if rescue_flag && (rescue_step == NUM_HASH_ROUNDS) {
        // for the 15th step, reset the state registers (two last registers of the hash state)
        state[11] = BaseElement::ZERO;
        state[12] = BaseElement::ZERO;
    } else if rescue_flag && (step < (NUM_HASH_ITER - 1) * HASH_CYCLE_LENGTH) {
        // for the 16th step, insert message chunks in the state registers
        let index = step / HASH_CYCLE_LENGTH;
        state[11] = message[2 * index];
        state[12] = message[2 * index + 1];
    } else if rescue_flag {
        // Register cells are by default copied from the previous state if no operation
        // is specified. This would conflict for here, as the "periodic" values for the
        // enforce_hash_copy() internal inputs are set to 0 at almost every step.
        // Hence we manually set them to zero for the final hash iteration, and this will
        // carry over until the end of the trace
        state[11] = BaseElement::ZERO;
        state[12] = BaseElement::ZERO;
    }

    // enforcing scalar multiplications
    match step.cmp(&SCALAR_MUL_LENGTH) {
        Ordering::Less => {
            let real_step = step / 2;
            let is_doubling_step = step % 2 == 0;
            state[POINT_WIDTH] = BaseElement::from(s_bits[bit_length - 1 - real_step] as u8);
            state[2 * POINT_WIDTH + 1] =
                BaseElement::from(h_bits[bit_length - 1 - real_step] as u8);

            if is_doubling_step {
                ecc::apply_point_doubling(&mut state[0..POINT_WIDTH + 1]);
                ecc::apply_point_doubling(&mut state[POINT_WIDTH + 1..2 * POINT_WIDTH + 2]);
                field::apply_double_and_add_step(
                    &mut state[2 * POINT_WIDTH + 1..2 * POINT_WIDTH + 3],
                    1,
                    0,
                );
            } else {
                ecc::apply_point_addition(&mut state[0..POINT_WIDTH + 1], &GENERATOR);
                ecc::apply_point_addition(
                    &mut state[POINT_WIDTH + 1..2 * POINT_WIDTH + 2],
                    &pkey_point,
                );
            }
        }
        Ordering::Equal => {
            let hp_point: [BaseElement; 3] = [
                state[POINT_WIDTH + 1],
                state[POINT_WIDTH + 2],
                state[POINT_WIDTH + 3],
            ];
            state[POINT_WIDTH] = BaseElement::ONE;
            ecc::apply_point_addition(&mut state[..POINT_WIDTH + 1], &hp_point);
            state[0] /= state[2]; // Affine coordinates, hence do X/Z
        }
        _ => {}
    }
}

// HELPER FUNCTIONS
// ================================================================================================

pub fn build_sig_info(
    message: &[BaseElement; 6],
    signature: &(BaseElement, Scalar),
) -> ([BaseElement; 3], [u8; 32], [u8; 32]) {
    let pkey_point = [message[0], message[1], BaseElement::ONE];
    let s_bytes = signature.1.to_bytes();

    let h = super::hash_message([signature.0, BaseElement::ZERO], *message);
    let h_bytes = h[0].to_bytes();

    (pkey_point, s_bytes, h_bytes)
}
