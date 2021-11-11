// Copyright (c) ToposWare and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::constants::*;
use super::{ecc, field, rescue};
use bitvec::{order::Lsb0, slice::BitSlice, view::AsBits};
use core::cmp::Ordering;
use winterfell::{
    math::{curve::Scalar, fields::cheetah::BaseElement, FieldElement},
    ExecutionTrace,
};

#[cfg(feature = "concurrent")]
use winterfell::iterators::*;

// TRACE GENERATOR
// ================================================================================================

pub fn build_trace(
    messages: &[[BaseElement; 28]],
    signatures: &[([BaseElement; 6], Scalar)],
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

pub fn init_sig_verification_state(
    signature: ([BaseElement; 6], Scalar),
    state: &mut [BaseElement],
) {
    // initialize first state of the computation
    state[0..TRACE_WIDTH].copy_from_slice(&[BaseElement::ZERO; TRACE_WIDTH]);
    state[6] = BaseElement::ONE; //   y(S)

    state[25] = BaseElement::ONE; //   y(h.P)

    state[39..45].copy_from_slice(&signature.0[..]); //        Rescue[0] = x(R)
}

// TRANSITION FUNCTION
// ================================================================================================

pub fn update_sig_verification_state(
    step: usize,
    message: [BaseElement; 28],
    pkey_point: [BaseElement; 18],
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
        rescue::apply_round(&mut state[39..], step);
    } else if rescue_flag && (step < (NUM_HASH_ITER - 1) * HASH_CYCLE_LENGTH) {
        // for the 8th step, insert message chunks in the state registers
        let index = step / HASH_CYCLE_LENGTH;
        state[46] = message[7 * index];
        state[47] = message[7 * index + 1];
        state[48] = message[7 * index + 2];
        state[49] = message[7 * index + 3];
        state[50] = message[7 * index + 4];
        state[51] = message[7 * index + 5];
        state[52] = message[7 * index + 6];
    } else if rescue_flag {
        // Register cells are by default copied from the previous state if no operation
        // is specified. This would conflict for here, as the "periodic" values for the
        // enforce_hash_copy() internal inputs are set to 0 at almost every step.
        // Hence we manually set them to zero for the final hash iteration, and this will
        // carry over until the end of the trace
        state[46] = BaseElement::ZERO;
        state[47] = BaseElement::ZERO;
        state[48] = BaseElement::ZERO;
        state[49] = BaseElement::ZERO;
        state[50] = BaseElement::ZERO;
        state[51] = BaseElement::ZERO;
        state[52] = BaseElement::ZERO;
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
            let mut hp_point = [BaseElement::ZERO; 18];
            hp_point.copy_from_slice(&state[POINT_WIDTH + 1..POINT_WIDTH * 2 + 1]);
            state[POINT_WIDTH] = BaseElement::ONE;
            ecc::apply_point_addition(&mut state[..POINT_WIDTH + 1], &hp_point);
            // Affine coordinates, hence do X/Z
            let mut x = [BaseElement::ZERO; 6];
            x.copy_from_slice(&state[0..6]);
            let mut z = [BaseElement::ZERO; 6];
            z.copy_from_slice(&state[12..18]);
            state[0..6].copy_from_slice(&ecc::mul_fp6(&x, &ecc::invert_fp6(&z)));
        }
        _ => {}
    }
}

// HELPER FUNCTIONS
// ================================================================================================

pub fn build_sig_info(
    message: &[BaseElement; 28],
    signature: &([BaseElement; 6], Scalar),
) -> ([BaseElement; 18], [u8; 32], [u8; 32]) {
    let mut pkey_point = [BaseElement::ZERO; 18];
    for i in 0..12 {
        pkey_point[i] = message[i];
    }
    pkey_point[12] = BaseElement::ONE;
    let s_bytes = signature.1.to_bytes();

    let h = super::hash_message(signature.0, *message);
    // TODO: getting only one 64-bit word to not have wrong field arithmetic,
    // but should take 4 at least.
    let mut h_bytes = [0u8; 32];
    h_bytes[0..8].copy_from_slice(&h[0].to_bytes());

    (pkey_point, s_bytes, h_bytes)
}
