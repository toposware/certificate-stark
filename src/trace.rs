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
    math::{curve::Scalar, fields::f252::BaseElement},
    ExecutionTrace,
};

#[cfg(feature = "concurrent")]
use winterfell::iterators::*;

use merkle_const::PREV_TREE_ROOT_POS;
use merkle_const::TRANSACTION_CYCLE_LENGTH as MERKLE_UPDATE_LENGTH;
use schnorr_const::SIG_CYCLE_LENGTH as SCHNORR_LENGTH;

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

            let sigma_bytes = (s_old_values[i][2] - deltas[i]).to_bytes();
            let sigma_bits = sigma_bytes.as_bits::<Lsb0>();

            let message = [
                s_old_values[i][0],
                s_old_values[i][1],
                r_old_values[i][0],
                r_old_values[i][1],
                deltas[i],
                s_old_values[i][3],
            ];

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
                        signatures[i],
                        state,
                    );
                },
                |step, state| {
                    update_transaction_state(
                        step,
                        initial_roots[i],
                        s_indices[i],
                        r_indices[i],
                        s_old_values[i],
                        r_old_values[i],
                        s_paths[i].clone(),
                        r_paths[i].clone(),
                        deltas[i],
                        delta_bits,
                        sigma_bits,
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
    s_old_value: [BaseElement; 4],
    r_old_value: [BaseElement; 4],
    delta: BaseElement,
    signature: (BaseElement, Scalar),
    state: &mut [BaseElement],
) {
    schnorr::init_sig_verification_state(signature, &mut state[..schnorr_const::TRACE_WIDTH]);
    state[RX_COPY_POS] = signature.0;

    // Set the initial root
    let init_root = initial_root.to_elements();
    state[PREV_TREE_ROOT_POS] = init_root[0];
    state[PREV_TREE_ROOT_POS + 1] = init_root[1];

    // Copy public keys and sigma = balance_sender - delta
    let start_copy_index = merkle_const::TRACE_WIDTH;
    state[start_copy_index] = s_old_value[0];
    state[start_copy_index + 1] = s_old_value[1];
    state[start_copy_index + 2] = r_old_value[0];
    state[start_copy_index + 3] = r_old_value[1];
    state[start_copy_index + 4] = delta;
    state[start_copy_index + 5] = s_old_value[2] - delta;
    state[start_copy_index + 6] = s_old_value[3];
}

// TRANSITION FUNCTION
// ================================================================================================

#[allow(clippy::too_many_arguments)]
pub fn update_transaction_state(
    step: usize,
    initial_root: rescue::Hash,
    s_index: usize,
    r_index: usize,
    s_old_value: [BaseElement; 4],
    r_old_value: [BaseElement; 4],
    s_branch: Vec<rescue::Hash>,
    r_branch: Vec<rescue::Hash>,
    delta: BaseElement,
    delta_bits: &BitSlice<Lsb0, u8>,
    sigma_bits: &BitSlice<Lsb0, u8>,
    sig_bits: &BitSlice<Lsb0, u8>,
    sig_hash_bits: &BitSlice<Lsb0, u8>,
    message: [BaseElement; 6],
    pkey_point: [BaseElement; 3],
    state: &mut [BaseElement],
) {
    let schnorr_update_flag = step < SCHNORR_LENGTH - 1;
    let hash_mask_len = rescue_const::HASH_CYCLE_LENGTH * (schnorr_const::NUM_HASH_ITER - 1) + rescue_const:: NUM_HASH_ROUNDS;
    let range_proof_setup_flag = step == hash_mask_len;
    let range_proof_flag = step > hash_mask_len && step <= hash_mask_len + 2 * (1 + range::RANGE_LOG);
    let merkle_init_flag = step == SCHNORR_LENGTH - 1;
    let merkle_update_flag = step >= SCHNORR_LENGTH && step < SCHNORR_LENGTH + MERKLE_UPDATE_LENGTH;

    // Initialize Schnorr signature verification state
    if schnorr_update_flag {
        // Proceed to Schnorr signature verification
        let schnorr_step = step;
        schnorr::update_sig_verification_state(
            schnorr_step,
            message,
            pkey_point,
            sig_bits,
            sig_hash_bits,
            &mut state[..schnorr_const::TRACE_WIDTH],
        );
    }
    if range_proof_setup_flag {
        // We set the 2 last registers of the Schnorr signature sub-trace to zero after the hash is done, for computing
        // the range proof on delta
        range::init_range_verification_state(&mut state[DELTA_BIT_POS..DELTA_ACCUMULATE_POS + 1]);
    } else if range_proof_flag {
        let range_step = step - hash_mask_len - 1;
        if range_step < range::RANGE_LOG {
            // Compute the range proof on delta
            range::update_range_verification_state(
                range_step,
                range_const::RANGE_LOG,
                delta_bits,
                &mut state[DELTA_BIT_POS..DELTA_ACCUMULATE_POS + 1],
            );
        } else if range_step == range::RANGE_LOG {
            debug_assert_eq!(
                state[DELTA_ACCUMULATE_POS], state[DELTA_COPY_POS],
                "expected accumulated value for delta of {}, found {}",
                state[DELTA_COPY_POS], state[DELTA_ACCUMULATE_POS],
            );
            // We set the 2 last registers of the Schnorr signature sub-trace to zero after the hash is done, for computing
            // the range proof on sigma = sender_balance - delta
            range::init_range_verification_state(&mut state[SIGMA_BIT_POS..SIGMA_ACCUMULATE_POS + 1]);
        } else if range_step < 2 * range::RANGE_LOG + 1 {
            // Compute the range proof on sigma
            range::update_range_verification_state(
                range_step - range::RANGE_LOG - 1,
                range_const::RANGE_LOG,
                sigma_bits,
                &mut state[SIGMA_BIT_POS..SIGMA_ACCUMULATE_POS + 1],
            );
        } else {
            debug_assert_eq!(
                state[SIGMA_ACCUMULATE_POS], state[SIGMA_COPY_POS],
                "expected accumulated value for sigma of {}, found {}",
                state[SIGMA_COPY_POS], state[SIGMA_ACCUMULATE_POS],
            );
        }
    } else if merkle_init_flag {
        // Initialize leaf values prior to hashing
        merkle::update::init_merkle_update_state(
            initial_root,
            s_old_value,
            r_old_value,
            delta,
            &mut state[..merkle_const::TRACE_WIDTH],
        );
    } else if merkle_update_flag {
        let merkle_step = step - SCHNORR_LENGTH;
        // Proceed to Merkle authentication paths verification
        merkle::update::update_merkle_update_state(
            merkle_step,
            s_index,
            r_index,
            s_branch,
            r_branch,
            &mut state[..merkle_const::TRACE_WIDTH],
        );
    }
}
