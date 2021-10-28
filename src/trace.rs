// Copyright (c) ToposWare and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::constants::*;
use super::merkle;
use super::range;
use super::schnorr;
use super::utils::rescue;
use bitvec::{order::Lsb0, slice::BitSlice, view::AsBits};
use winterfell::{
    math::{curve::Scalar, fields::f252::BaseElement},
    ExecutionTrace,
};

#[cfg(feature = "concurrent")]
use winterfell::iterators::*;

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
pub fn build_trace(
    initial_roots: &[rescue::Hash],
    s_old_values: &[[BaseElement; 4]],
    r_old_values: &[[BaseElement; 4]],
    s_indices: &[usize],
    r_indices: &[usize],
    s_branches: &[Vec<rescue::Hash>],
    r_branches: &[Vec<rescue::Hash>],
    deltas: &[BaseElement],
    signatures: &[(BaseElement, Scalar)],
    num_transactions: usize,
) -> ExecutionTrace<BaseElement> {
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
                        state,
                    );
                },
                |step, state| {
                    update_transaction_state(
                        step,
                        s_indices[i],
                        r_indices[i],
                        s_branches[i].clone(),
                        r_branches[i].clone(),
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
    s_old_value: [BaseElement; 4],
    r_old_value: [BaseElement; 4],
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
    s_index: usize,
    r_index: usize,
    s_branch: Vec<rescue::Hash>,
    r_branch: Vec<rescue::Hash>,
    delta_bits: &BitSlice<Lsb0, u8>,
    sigma_bits: &BitSlice<Lsb0, u8>,
    signature: (BaseElement, Scalar),
    sig_bits: &BitSlice<Lsb0, u8>,
    sig_hash_bits: &BitSlice<Lsb0, u8>,
    message: [BaseElement; 6],
    pkey_point: [BaseElement; 3],
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
