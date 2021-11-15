// Copyright (c) ToposWare and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::constants::*;
use super::merkle;
use super::range;
use super::schnorr;
use super::utils::rescue;
use super::TransactionMetadata;
use bitvec::{order::Lsb0, slice::BitSlice, view::AsBits};
use winterfell::{
    math::{curve::Scalar, fields::cheetah::BaseElement},
    ExecutionTrace,
};

#[cfg(feature = "concurrent")]
use winterfell::iterators::*;

use merkle_const::TRANSACTION_CYCLE_LENGTH as MERKLE_UPDATE_LENGTH;
use schnorr_const::{
    AFFINE_POINT_WIDTH, POINT_COORDINATE_WIDTH, PROJECTIVE_POINT_WIDTH,
    SIG_CYCLE_LENGTH as SCHNORR_LENGTH,
};

// TRACE GENERATOR
// ================================================================================================

/// Builds the execution trace of the main state transition AIR program.
// The trace is composed as follows:
// (note that sigma here refers to sender_balance - delta)
//
// | 4 * HASH_STATE + 4 |          5          | number of registers
// |    merkle::init    | copy_keys_and_sigma | sub-programs
// |   merkle::update   | copy_keys_and_sigma |
// |   schnorr::init    | copy_keys_and_sigma |
// |   schnorr::verif   |  range_proof_sigma  |
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
    let signatures = &tx_metadata.signatures;

    let num_transactions = tx_metadata.initial_roots.len();

    // allocate memory to hold the trace table
    let mut trace = ExecutionTrace::new(TRACE_WIDTH, num_transactions * TRANSACTION_CYCLE_LENGTH);

    trace
        .fragments(TRANSACTION_CYCLE_LENGTH)
        .for_each(|mut transaction_trace| {
            let i = transaction_trace.index();

            let delta_bytes = deltas[i].to_bytes();
            let delta_bits = delta_bytes.as_bits::<Lsb0>();

            let sigma_bytes = (s_old_values[i][AFFINE_POINT_WIDTH] - deltas[i]).to_bytes();
            let sigma_bits = sigma_bytes.as_bits::<Lsb0>();

            let message = super::build_tx_message(
                &s_old_values[i][0..AFFINE_POINT_WIDTH],
                &r_old_values[i][0..AFFINE_POINT_WIDTH],
                deltas[i],
                s_old_values[i][AFFINE_POINT_WIDTH + 1],
            );

            let (pkey_point, sig_bytes, sig_hash_bytes) =
                schnorr::build_sig_info(&message, &signatures[i]);
            let sig_bits = sig_bytes.as_bits::<Lsb0>();
            let sig_hash_bits = sig_hash_bytes.as_bits::<Lsb0>();

            transaction_trace.fill(
                |state| {
                    init_transaction_state(
                        initial_roots[i],
                        s_old_values[i],
                        r_old_values[i],
                        deltas[i],
                        state,
                    );
                },
                |step, state| {
                    update_transaction_state(
                        step,
                        s_indices[i],
                        r_indices[i],
                        s_paths[i].clone(),
                        r_paths[i].clone(),
                        delta_bits,
                        sigma_bits,
                        signatures[i],
                        sig_bits,
                        sig_hash_bits,
                        message,
                        pkey_point,
                        state,
                    );
                },
            )
        });

    trace
}

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

    // Copy public keys and sigma = balance_sender - delta
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
    pkey_point: [BaseElement; PROJECTIVE_POINT_WIDTH],
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
        let start_range_index = schnorr_const::TRACE_WIDTH;
        range::init_range_verification_state(&mut state[start_range_index..start_range_index + 2]);
        range::init_range_verification_state(
            &mut state[start_range_index + 2..start_range_index + 4],
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
            let start_range_index = schnorr_const::TRACE_WIDTH;
            range::update_range_verification_state(
                schnorr_step,
                range_const::RANGE_LOG,
                delta_bits,
                &mut state[start_range_index..start_range_index + 2],
            );
            range::update_range_verification_state(
                schnorr_step,
                range_const::RANGE_LOG,
                sigma_bits,
                &mut state[start_range_index + 2..start_range_index + 4],
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
