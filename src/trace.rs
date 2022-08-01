// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::constants::*;
use super::merkle;
use super::range;
use super::schnorr;
use super::utils::rescue;
use bitvec::{order::Lsb0, slice::BitSlice};
use winterfell::math::{curves::curve_f63::Scalar, fields::f63::BaseElement};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use merkle_const::TRANSACTION_CYCLE_LENGTH as MERKLE_UPDATE_LENGTH;
use schnorr_const::{
    AFFINE_POINT_WIDTH, POINT_COORDINATE_WIDTH, SIG_CYCLE_LENGTH as SCHNORR_LENGTH,
};

// TRACE INITIALIZATION
// ================================================================================================

pub fn init_transaction_state(
    initial_root: rescue::Hash,
    s_old_value: [BaseElement; AFFINE_POINT_WIDTH + 2],
    r_old_value: [BaseElement; AFFINE_POINT_WIDTH + 2],
    delta: BaseElement,
    state: &mut [BaseElement],
) {
    // Initialize leaf values prior to hashing
    merkle::update::init_merkle_update_state(
        initial_root,
        s_old_value,
        r_old_value,
        delta,
        &mut state[..merkle_const::TRACE_WIDTH],
    );

    // Copy public keys, delta, sigma = balance_sender - delta, and nonce
    let start_copy_index = merkle_const::TRACE_WIDTH;
    state[start_copy_index..start_copy_index + AFFINE_POINT_WIDTH]
        .copy_from_slice(&s_old_value[0..AFFINE_POINT_WIDTH]);
    state[start_copy_index + AFFINE_POINT_WIDTH..start_copy_index + AFFINE_POINT_WIDTH * 2]
        .copy_from_slice(&r_old_value[0..AFFINE_POINT_WIDTH]);
    state[start_copy_index + AFFINE_POINT_WIDTH * 2] = delta;
    state[start_copy_index + AFFINE_POINT_WIDTH * 2 + 1] = s_old_value[AFFINE_POINT_WIDTH] - delta;
    state[start_copy_index + AFFINE_POINT_WIDTH * 2 + 2] = s_old_value[AFFINE_POINT_WIDTH + 1];
}

// TRANSITION FUNCTION
// ================================================================================================

#[allow(clippy::too_many_arguments)]
pub fn update_transaction_state(
    step: usize,
    s_index: usize,
    r_index: usize,
    s_branch: Vec<rescue::Hash>,
    r_branch: Vec<rescue::Hash>,
    delta_bits: &BitSlice<Lsb0, u8>,
    sigma_bits: &BitSlice<Lsb0, u8>,
    signature: ([BaseElement; POINT_COORDINATE_WIDTH], Scalar),
    sig_bits: &BitSlice<Lsb0, u8>,
    sig_hash_bits: &BitSlice<Lsb0, u8>,
    message: [BaseElement; AFFINE_POINT_WIDTH * 2 + 4],
    pkey_point: [BaseElement; AFFINE_POINT_WIDTH],
    state: &mut [BaseElement],
) {
    let merkle_update_flag = step < MERKLE_UPDATE_LENGTH - 1;
    let schnorr_init_flag = step == MERKLE_UPDATE_LENGTH - 1;
    let schnorr_update_flag = !schnorr_init_flag && (step < SCHNORR_LENGTH + MERKLE_UPDATE_LENGTH);

    if merkle_update_flag {
        // Proceed to Merkle authentication paths verification
        merkle::update::update_merkle_update_state(
            step,
            s_index,
            r_index,
            s_branch,
            r_branch,
            &mut state[..merkle_const::TRACE_WIDTH],
        );
    // Initialize Schnorr signature verification state
    } else if schnorr_init_flag {
        schnorr::init_sig_verification_state(signature, &mut state[..schnorr_const::TRACE_WIDTH]);
        // We set the 4 registers next to the Schnorr signature sub-trace to zero, for computing
        // the range proofs on delta and sigma = sender_balance - delta
        let start_delta_range_index = schnorr_const::TRACE_WIDTH;
        let start_sigma_range_index = NONCE_COPY_POS + 1;
        range::init_range_verification_state(
            &mut state[start_delta_range_index..start_delta_range_index + 2],
        );
        range::init_range_verification_state(
            &mut state[start_sigma_range_index..start_sigma_range_index + 2],
        );
    } else if schnorr_update_flag {
        // Proceed to Schnorr signature verification
        let schnorr_step = step - MERKLE_UPDATE_LENGTH;
        schnorr::update_sig_verification_state(
            schnorr_step,
            message,
            pkey_point,
            sig_bits,
            sig_hash_bits,
            &mut state[..schnorr_const::TRACE_WIDTH],
        );

        if schnorr_step < range::RANGE_LOG {
            // Compute the range proof on delta and sigma
            let start_delta_range_index = schnorr_const::TRACE_WIDTH;
            let start_sigma_range_index = NONCE_COPY_POS + 1;
            range::update_range_verification_state(
                schnorr_step,
                range_const::RANGE_LOG,
                delta_bits,
                &mut state[start_delta_range_index..start_delta_range_index + 2],
            );
            range::update_range_verification_state(
                schnorr_step,
                range_const::RANGE_LOG,
                sigma_bits,
                &mut state[start_sigma_range_index..start_sigma_range_index + 2],
            );
        } else {
            debug_assert_eq!(
                state[DELTA_ACCUMULATE_POS], state[DELTA_COPY_POS],
                "expected accumulated value for delta of {}, found {}",
                state[DELTA_COPY_POS], state[DELTA_ACCUMULATE_POS],
            );
            debug_assert_eq!(
                state[SIGMA_ACCUMULATE_POS], state[SIGMA_COPY_POS],
                "expected accumulated value for sigma of {}, found {}",
                state[SIGMA_COPY_POS], state[SIGMA_ACCUMULATE_POS],
            );
        }
    }
}
