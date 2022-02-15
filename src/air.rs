// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::constants::merkle_const::{
    BALANCE_CONSTRAINT_RES, HASH_RATE_WIDTH, HASH_STATE_WIDTH, INT_ROOT_EQUALITY_RES,
    NONCE_UPDATE_CONSTRAINT_RES, PREV_TREE_ROOT_POS, RECEIVER_BIT_POS, RECEIVER_INITIAL_POS,
    RECEIVER_UPDATED_POS, SENDER_INITIAL_POS, SENDER_UPDATED_POS,
    TRANSACTION_CYCLE_LENGTH as MERKLE_UPDATE_LENGTH, TRANSACTION_HASH_LENGTH,
    VALUE_CONSTRAINT_RES,
};
use super::constants::range_const::RANGE_LOG;
use super::constants::rescue_const::HASH_CYCLE_LENGTH;
use super::constants::schnorr_const::{
    AFFINE_POINT_WIDTH, PROJECTIVE_POINT_WIDTH, SIG_CYCLE_LENGTH,
};
use super::constants::{
    ARK_INDEX, DELTA_ACCUMULATE_POS, DELTA_BIT_POS, DELTA_COPY_POS, DELTA_COPY_RES,
    DELTA_RANGE_RES, DOUBLING_MASK_INDEX, FINISH_MASK_INDEX, HASH_INPUT_MASK_INDEX,
    HASH_INTERNAL_INPUT_MASKS_INDEX, HASH_MASK_INDEX, MERKLE_MASK_INDEX, NONCE_COPY_POS,
    NONCE_COPY_RES, RANGE_PROOF_FINISH_MASK_INDEX, RANGE_PROOF_STEP_MASK_INDEX,
    RECEIVER_KEY_POINT_POS, RECEIVER_KEY_POINT_RES, SCALAR_MULT_MASK_INDEX,
    SCHNORR_DIGEST_MASK_INDEX, SCHNORR_HASH_MASK_INDEX, SCHNORR_MASK_INDEX, SCHNORR_REGISTER_WIDTH,
    SENDER_KEY_POINT_POS, SENDER_KEY_POINT_RES, SETUP_MASK_INDEX, SIGMA_ACCUMULATE_POS,
    SIGMA_BIT_POS, SIGMA_COPY_POS, SIGMA_COPY_RES, SIGMA_RANGE_RES, TRACE_WIDTH,
    TRANSACTION_CYCLE_LENGTH, VALUE_COPY_MASK_INDEX,
};
use super::merkle;
use super::schnorr;
//use super::schnorr::constants::SCALAR_MUL_LENGTH;
use super::utils::{
    field::enforce_double_and_add_step,
    periodic_columns::{fill, pad, stitch},
};
use crate::utils::{are_equal, not, EvaluationResult};
use winterfell::{
    math::{fields::f63::BaseElement, FieldElement},
    Air, AirContext, Assertion, ByteWriter, EvaluationFrame, ProofOptions, Serializable, TraceInfo,
    TransitionConstraintDegree,
};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

// MERKLE PATH VERIFICATION AIR
// ================================================================================================

pub struct PublicInputs {
    pub initial_root: [BaseElement; HASH_RATE_WIDTH],
    pub final_root: [BaseElement; HASH_RATE_WIDTH],
}

impl Serializable for PublicInputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(&self.initial_root[..]);
        target.write(&self.final_root[..]);
    }
}

pub struct TransactionAir {
    context: AirContext<BaseElement>,
    initial_root: [BaseElement; HASH_RATE_WIDTH],
    final_root: [BaseElement; HASH_RATE_WIDTH],
}

impl Air for TransactionAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        // Constraint degrees for enforcement of Rescue hash rounds
        let mut degrees = merkle::update::transition_constraint_degrees(TRANSACTION_CYCLE_LENGTH);
        // The constraint at the receiver position has higher degree than in Merkle sub-AIR program
        degrees[RECEIVER_BIT_POS] =
            TransitionConstraintDegree::with_cycles(3, vec![TRANSACTION_CYCLE_LENGTH]);
        degrees[INT_ROOT_EQUALITY_RES] =
            TransitionConstraintDegree::with_cycles(2, vec![TRANSACTION_CYCLE_LENGTH]);

        let schnorr_degrees = schnorr::transition_constraint_degrees(2, TRANSACTION_CYCLE_LENGTH);
        // Update the constraint degrees with the ones for Schnorr
        for index in 0..PROJECTIVE_POINT_WIDTH {
            degrees[index] = schnorr_degrees[index].clone();
            degrees[index + PROJECTIVE_POINT_WIDTH + 1] =
                schnorr_degrees[index + PROJECTIVE_POINT_WIDTH + 1].clone();
        }

        // Append the degrees for the copy columns followed by range proof equalities
        degrees.append(&mut vec![
            TransitionConstraintDegree::with_cycles(
                1,
                vec![TRANSACTION_CYCLE_LENGTH]
            );
            SIGMA_RANGE_RES - SENDER_KEY_POINT_RES + 1
        ]);

        assert_eq!(TRACE_WIDTH, trace_info.width());
        TransactionAir {
            context: AirContext::new(trace_info, degrees, options),
            initial_root: pub_inputs.initial_root,
            final_root: pub_inputs.final_root,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();
        debug_assert_eq!(TRACE_WIDTH, current.len());
        debug_assert_eq!(TRACE_WIDTH, next.len());

        // Split periodic values into masks for Merkle component
        let transaction_setup_flag = periodic_values[SETUP_MASK_INDEX];
        let transaction_hash_flag = periodic_values[MERKLE_MASK_INDEX];
        let hash_input_flag = periodic_values[HASH_INPUT_MASK_INDEX];
        let transaction_finish_flag = periodic_values[FINISH_MASK_INDEX];
        let hash_flag = periodic_values[HASH_MASK_INDEX];

        // Split periodic values for Schnorr component
        let schnorr_mask = periodic_values[SCHNORR_MASK_INDEX];
        let scalar_mult_flag = periodic_values[SCALAR_MULT_MASK_INDEX];
        let doubling_flag = periodic_values[DOUBLING_MASK_INDEX];
        let schnorr_hash_digest_register_flag =
            &periodic_values[SCHNORR_DIGEST_MASK_INDEX..SCHNORR_HASH_MASK_INDEX];
        let schnorr_hash_flag = periodic_values[SCHNORR_HASH_MASK_INDEX];
        let hash_internal_input_flags =
            &periodic_values[HASH_INTERNAL_INPUT_MASKS_INDEX..RANGE_PROOF_STEP_MASK_INDEX];

        let range_proof_flag = periodic_values[RANGE_PROOF_STEP_MASK_INDEX];
        let range_proof_finish_flag = periodic_values[RANGE_PROOF_FINISH_MASK_INDEX];
        let copy_values_flag = periodic_values[VALUE_COPY_MASK_INDEX];
        let ark = &periodic_values[ARK_INDEX..];

        // Generate dependent masks from existing masks
        let copy_hash_flag = not(schnorr_hash_flag) * schnorr_mask;
        let final_point_addition_flag = not(scalar_mult_flag) * schnorr_mask;
        let addition_flag = not(doubling_flag) * scalar_mult_flag;

        evaluate_constraints(
            result,
            current,
            next,
            ark,
            transaction_setup_flag,
            transaction_hash_flag,
            hash_input_flag,
            hash_flag,
            transaction_finish_flag,
            doubling_flag,
            addition_flag,
            schnorr_hash_digest_register_flag,
            final_point_addition_flag,
            schnorr_hash_flag,
            copy_hash_flag,
            hash_internal_input_flags,
            range_proof_flag,
            range_proof_finish_flag,
            copy_values_flag,
        )
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        // Assert the presence of the appropriate initial and final tree roots
        let last_step = self.trace_length() - 1;
        vec![
            Assertion::single(PREV_TREE_ROOT_POS, 0, self.initial_root[0]),
            Assertion::single(PREV_TREE_ROOT_POS + 1, 0, self.initial_root[1]),
            Assertion::single(PREV_TREE_ROOT_POS, last_step, self.final_root[0]),
            Assertion::single(PREV_TREE_ROOT_POS + 1, last_step, self.final_root[1]),
        ]
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        periodic_columns()
    }
}

// HELPER FUNCTIONS
// ================================================================================================

pub fn periodic_columns() -> Vec<Vec<BaseElement>> {
    // Create empty columns to start with
    let mut columns = vec![Vec::new(); ARK_INDEX + HASH_STATE_WIDTH * 2];
    // Initialize the length of the stitched masks
    let mut length = 0;
    // Add the columns for the pre-Merkle component
    let pre_merkle_columns = merkle::init::periodic_columns();
    stitch(
        &mut columns,
        pre_merkle_columns,
        (ARK_INDEX..ARK_INDEX + HASH_STATE_WIDTH * 2)
            .enumerate()
            .collect(),
    );
    // TODO: Change to make use of modified Merkle init component
    //length += NUM_HASH_ROUNDS;
    pad(&mut columns, vec![SETUP_MASK_INDEX], 1, BaseElement::ONE);
    pad(
        &mut columns,
        vec![VALUE_COPY_MASK_INDEX],
        1,
        BaseElement::ZERO,
    );
    pad(
        &mut columns,
        vec![MERKLE_MASK_INDEX, FINISH_MASK_INDEX, HASH_MASK_INDEX],
        length,
        BaseElement::ZERO,
    );

    // Add the columns for the Merkle component
    let merkle_columns = merkle::update::periodic_columns();
    stitch(
        &mut columns,
        merkle_columns.clone(),
        vec![(2, HASH_INPUT_MASK_INDEX)],
    );
    length = TRANSACTION_HASH_LENGTH;
    fill(
        &mut columns,
        merkle_columns,
        vec![
            (1, MERKLE_MASK_INDEX),
            (3, FINISH_MASK_INDEX),
            (4, HASH_MASK_INDEX),
        ],
        length,
    );

    // Pad the columns up to the transition to Schnorr
    length = MERKLE_UPDATE_LENGTH;
    pad(
        &mut columns,
        vec![
            SETUP_MASK_INDEX,
            MERKLE_MASK_INDEX,
            FINISH_MASK_INDEX,
            HASH_MASK_INDEX,
            SCHNORR_MASK_INDEX,
            SCALAR_MULT_MASK_INDEX,
            DOUBLING_MASK_INDEX,
            SCHNORR_HASH_MASK_INDEX,
            RANGE_PROOF_STEP_MASK_INDEX,
            RANGE_PROOF_FINISH_MASK_INDEX,
        ],
        length,
        BaseElement::ZERO,
    );
    pad(
        &mut columns,
        (SCHNORR_DIGEST_MASK_INDEX..SCHNORR_HASH_MASK_INDEX).collect(),
        length,
        BaseElement::ZERO,
    );
    pad(
        &mut columns,
        vec![VALUE_COPY_MASK_INDEX],
        length,
        BaseElement::ONE,
    );

    // Add the columns for the Schnorr component
    let schnorr_columns = schnorr::periodic_columns();
    stitch(
        &mut columns,
        schnorr_columns,
        vec![
            SCHNORR_MASK_INDEX,
            SCALAR_MULT_MASK_INDEX,
            DOUBLING_MASK_INDEX,
            SCHNORR_DIGEST_MASK_INDEX,
            SCHNORR_DIGEST_MASK_INDEX + 1,
            SCHNORR_DIGEST_MASK_INDEX + 2,
            SCHNORR_DIGEST_MASK_INDEX + 3,
            SCHNORR_HASH_MASK_INDEX,
        ]
        .into_iter()
        .enumerate()
        .collect(),
    );
    // Create columns for the input copy masks
    pad(
        &mut columns,
        (HASH_INTERNAL_INPUT_MASKS_INDEX..RANGE_PROOF_STEP_MASK_INDEX).collect(),
        length,
        BaseElement::ZERO,
    );
    let mut input_masks = vec![
        vec![BaseElement::ZERO; SIG_CYCLE_LENGTH];
        RANGE_PROOF_STEP_MASK_INDEX - HASH_INTERNAL_INPUT_MASKS_INDEX
    ];
    for (input_num, mask) in input_masks
        .iter_mut()
        .enumerate()
        .take(RANGE_PROOF_STEP_MASK_INDEX - HASH_INTERNAL_INPUT_MASKS_INDEX)
    {
        mask[(input_num + 1) * HASH_CYCLE_LENGTH - 1] = BaseElement::ONE;
    }
    stitch(
        &mut columns,
        input_masks,
        (HASH_INTERNAL_INPUT_MASKS_INDEX..RANGE_PROOF_STEP_MASK_INDEX)
            .enumerate()
            .collect(),
    );

    // Add the columns for the range proof component
    let range_proof_mask = vec![BaseElement::ONE; RANGE_LOG];
    let mut range_proof_finish_mask = vec![BaseElement::ZERO; RANGE_LOG];
    range_proof_finish_mask[RANGE_LOG - 1] = BaseElement::ONE;
    stitch(
        &mut columns,
        vec![range_proof_mask, range_proof_finish_mask],
        vec![RANGE_PROOF_STEP_MASK_INDEX, RANGE_PROOF_FINISH_MASK_INDEX]
            .into_iter()
            .enumerate()
            .collect(),
    );

    // Pad out the copy constraints
    let hash_input_length = 3 * HASH_CYCLE_LENGTH - 1;
    length += if hash_input_length > RANGE_LOG {
        hash_input_length
    } else {
        RANGE_LOG
    };
    pad(
        &mut columns,
        vec![VALUE_COPY_MASK_INDEX],
        length,
        BaseElement::ONE,
    );

    // Pad to finish the cycle length
    length = TRANSACTION_CYCLE_LENGTH;
    pad(
        &mut columns,
        vec![
            SETUP_MASK_INDEX,
            MERKLE_MASK_INDEX,
            FINISH_MASK_INDEX,
            HASH_MASK_INDEX,
            SCHNORR_MASK_INDEX,
            SCALAR_MULT_MASK_INDEX,
            DOUBLING_MASK_INDEX,
            SCHNORR_HASH_MASK_INDEX,
            RANGE_PROOF_STEP_MASK_INDEX,
            RANGE_PROOF_FINISH_MASK_INDEX,
            VALUE_COPY_MASK_INDEX,
        ],
        length,
        BaseElement::ZERO,
    );
    pad(
        &mut columns,
        (SCHNORR_DIGEST_MASK_INDEX..SCHNORR_DIGEST_MASK_INDEX + 4).collect(),
        length,
        BaseElement::ZERO,
    );
    pad(
        &mut columns,
        (HASH_INTERNAL_INPUT_MASKS_INDEX..HASH_INTERNAL_INPUT_MASKS_INDEX + 3).collect(),
        length,
        BaseElement::ZERO,
    );
    columns
}

#[allow(clippy::too_many_arguments)]
pub fn evaluate_constraints<E: FieldElement + From<BaseElement>>(
    result: &mut [E],
    current: &[E],
    next: &[E],
    ark: &[E],
    transaction_setup_flag: E,
    transaction_hash_flag: E,
    hash_input_flag: E,
    hash_flag: E,
    transaction_finish_flag: E,
    doubling_flag: E,
    addition_flag: E,
    schnorr_hash_digest_register_flag: &[E],
    final_point_addition_flag: E,
    schnorr_hash_flag: E,
    copy_hash_flag: E,
    hash_internal_input_flags: &[E],
    range_proof_flag: E,
    range_proof_finish_flag: E,
    copy_values_flag: E,
) {
    merkle::init::evaluate_constraints(result, current, next, ark, transaction_setup_flag);
    // Enforce no change in registers representing keys
    for i in 0..AFFINE_POINT_WIDTH {
        result.agg_constraint(
            VALUE_CONSTRAINT_RES + i,
            transaction_setup_flag,
            are_equal(
                current[SENDER_INITIAL_POS + i],
                current[SENDER_UPDATED_POS + i],
            ),
        );

        result.agg_constraint(
            VALUE_CONSTRAINT_RES + AFFINE_POINT_WIDTH + i,
            transaction_setup_flag,
            are_equal(
                current[RECEIVER_INITIAL_POS + i],
                current[RECEIVER_UPDATED_POS + i],
            ),
        );
    }
    // Enforce no change in the receiver's nonce
    result.agg_constraint(
        VALUE_CONSTRAINT_RES + AFFINE_POINT_WIDTH * 2,
        transaction_setup_flag,
        are_equal(
            current[RECEIVER_INITIAL_POS + AFFINE_POINT_WIDTH + 1],
            current[RECEIVER_UPDATED_POS + AFFINE_POINT_WIDTH + 1],
        ),
    );
    // Enforce that the change in balances cancels out
    result.agg_constraint(
        BALANCE_CONSTRAINT_RES,
        transaction_setup_flag,
        are_equal(
            current[SENDER_INITIAL_POS + AFFINE_POINT_WIDTH]
                - current[SENDER_UPDATED_POS + AFFINE_POINT_WIDTH],
            current[RECEIVER_UPDATED_POS + AFFINE_POINT_WIDTH]
                - current[RECEIVER_INITIAL_POS + AFFINE_POINT_WIDTH],
        ),
    );
    // Enforce change in the sender's nonce
    result.agg_constraint(
        NONCE_UPDATE_CONSTRAINT_RES,
        transaction_setup_flag,
        are_equal(
            current[SENDER_UPDATED_POS + AFFINE_POINT_WIDTH + 1],
            current[SENDER_INITIAL_POS + AFFINE_POINT_WIDTH + 1] + E::ONE,
        ),
    );

    // Enforce proper copying of keys at the beginning of the transaction
    for (res_index, origin_index, copy_index) in [
        (
            SENDER_KEY_POINT_RES,
            SENDER_INITIAL_POS,
            SENDER_KEY_POINT_POS,
        ),
        (
            RECEIVER_KEY_POINT_RES,
            RECEIVER_INITIAL_POS,
            RECEIVER_KEY_POINT_POS,
        ),
    ] {
        for offset in 0..AFFINE_POINT_WIDTH {
            result.agg_constraint(
                res_index + offset,
                transaction_setup_flag,
                are_equal(next[copy_index + offset], current[origin_index + offset]),
            );
        }
    }
    // Enforce proper computation of delta at the beginning of the transaction
    result.agg_constraint(
        DELTA_COPY_RES,
        transaction_setup_flag,
        are_equal(
            next[DELTA_COPY_POS],
            current[SENDER_INITIAL_POS + AFFINE_POINT_WIDTH]
                - current[SENDER_UPDATED_POS + AFFINE_POINT_WIDTH],
        ),
    );
    // Enforce proper copying of sigma and the nonce
    for (res_index, origin_index, copy_index) in [
        (
            SIGMA_COPY_RES,
            SENDER_UPDATED_POS + AFFINE_POINT_WIDTH,
            SIGMA_COPY_POS,
        ),
        (
            NONCE_COPY_RES,
            SENDER_INITIAL_POS + AFFINE_POINT_WIDTH + 1,
            NONCE_COPY_POS,
        ),
    ] {
        result.agg_constraint(
            res_index,
            transaction_setup_flag,
            are_equal(next[copy_index], current[origin_index]),
        );
    }

    // Enforce proper copying of keys, delta, and nonce for the remainder of the transaction
    for (res_index, copy_index) in [
        (SENDER_KEY_POINT_RES, SENDER_KEY_POINT_POS),
        (RECEIVER_KEY_POINT_RES, RECEIVER_KEY_POINT_POS),
    ] {
        for offset in 0..AFFINE_POINT_WIDTH {
            result.agg_constraint(
                res_index + offset,
                copy_values_flag,
                are_equal(next[copy_index + offset], current[copy_index + offset]),
            );
        }
    }
    for (res_index, copy_index) in [
        (DELTA_COPY_RES, DELTA_COPY_POS),
        (SIGMA_COPY_RES, SIGMA_COPY_POS),
        (NONCE_COPY_RES, NONCE_COPY_POS),
    ] {
        result.agg_constraint(
            res_index,
            copy_values_flag,
            are_equal(next[copy_index], current[copy_index]),
        );
    }

    merkle::update::evaluate_constraints(
        result,
        current,
        next,
        ark,
        transaction_hash_flag,
        hash_input_flag,
        hash_flag,
        transaction_finish_flag,
    );

    // Set up the internal inputs
    let mut hash_internal_inputs = [E::ZERO; HASH_RATE_WIDTH];
    for k in 0..schnorr::constants::NUM_HASH_ITER - 1 {
        for i in 0..HASH_RATE_WIDTH {
            let from_sender = k * HASH_RATE_WIDTH + i < AFFINE_POINT_WIDTH;
            let from_receiver = !from_sender && (k * HASH_RATE_WIDTH + i < AFFINE_POINT_WIDTH * 2);
            let from_delta = k * HASH_RATE_WIDTH + i == AFFINE_POINT_WIDTH * 2;
            let from_nonce = k * HASH_RATE_WIDTH + i == AFFINE_POINT_WIDTH * 2 + 1;

            let cell = if from_sender {
                next[SENDER_KEY_POINT_POS + k * HASH_RATE_WIDTH + i]
            } else if from_receiver {
                next[RECEIVER_KEY_POINT_POS + k * HASH_RATE_WIDTH + i - AFFINE_POINT_WIDTH]
            } else if from_delta {
                next[DELTA_COPY_POS]
            } else if from_nonce {
                next[NONCE_COPY_POS]
            } else {
                E::ZERO
            };

            hash_internal_inputs[i] += hash_internal_input_flags[k] * cell;
        }
    }

    schnorr::evaluate_constraints(
        &mut result[0..SCHNORR_REGISTER_WIDTH],
        &current[0..SCHNORR_REGISTER_WIDTH],
        &next[0..SCHNORR_REGISTER_WIDTH],
        ark,
        doubling_flag,
        addition_flag,
        schnorr_hash_digest_register_flag,
        &next[SENDER_KEY_POINT_POS..SENDER_KEY_POINT_POS + AFFINE_POINT_WIDTH],
        final_point_addition_flag,
        schnorr_hash_flag,
        copy_hash_flag,
        &hash_internal_inputs,
    );

    // Enforce constraints for the range proofs
    enforce_double_and_add_step(
        result,
        current,
        next,
        DELTA_ACCUMULATE_POS,
        DELTA_BIT_POS,
        range_proof_flag,
    );
    enforce_double_and_add_step(
        result,
        current,
        next,
        SIGMA_ACCUMULATE_POS,
        SIGMA_BIT_POS,
        range_proof_flag,
    );
    // Enforce that the values at the ends of the range proofs are actually the values promised
    result.agg_constraint(
        DELTA_RANGE_RES,
        range_proof_finish_flag,
        are_equal(next[DELTA_ACCUMULATE_POS], next[DELTA_COPY_POS]),
    );
    result.agg_constraint(
        SIGMA_RANGE_RES,
        range_proof_finish_flag,
        are_equal(next[DELTA_ACCUMULATE_POS], next[DELTA_COPY_POS]),
    );
}
