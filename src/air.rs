// Copyright (c) ToposWare and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::constants::merkle_const::{
    BALANCE_CONSTRAINT_RES, HASH_STATE_WIDTH, NONCE_UPDATE_CONSTRAINT_RES, PREV_TREE_MATCH_RES,
    PREV_TREE_ROOT_POS, PREV_TREE_ROOT_RES, RECEIVER_INITIAL_POS, RECEIVER_UPDATED_POS,
    SENDER_INITIAL_POS, SENDER_UPDATED_POS, TRANSACTION_CYCLE_LENGTH as MERKLE_UPDATE_LENGTH,
    VALUE_CONSTRAINT_RES,
};
use super::constants::range_const::RANGE_LOG;
use super::constants::rescue_const::HASH_CYCLE_LENGTH;
use super::constants::schnorr_const::{
    HP_POINT_POS, H_FIELD_POS, POINT_WIDTH, SIG_CYCLE_LENGTH, SIG_HASH_POS, S_POINT_POS,
};
use super::constants::{
    ARK_INDEX, DELTA_ACCUMULATE_POS, DELTA_BIT_POS, DELTA_COPY_POS, DELTA_COPY_RES,
    DELTA_RANGE_RES, DELTA_SETUP_RES, DOUBLING_MASK_INDEX, FINISH_MASK_INDEX,
    HASH_INPUT_MASK_INDEX, HASH_INTERNAL_INPUT_MASKS_INDEX, HASH_MASK_INDEX, HP_POINT_SETUP_RES,
    H_FIELD_SETUP_RES, MERKLE_MASK_INDEX, NONCE_COPY_POS, NONCE_COPY_RES,
    RANGE_PROOF_FINISH_MASK_INDEX, RANGE_PROOF_STEP_MASK_INDEX, RECEIVER_KEY_POINT_POS,
    RECEIVER_KEY_POINT_RES, RX_COPY_POS, RX_COPY_RES, SCALAR_MULT_MASK_INDEX,
    SCHNORR_HASH_MASK_INDEX, SCHNORR_HASH_POS, SCHNORR_MASK_INDEX, SCHNORR_REGISTER_WIDTH,
    SCHNORR_SETUP_MASK_INDEX, SENDER_KEY_POINT_POS, SENDER_KEY_POINT_RES, SETUP_MASK_INDEX,
    SIGMA_ACCUMULATE_POS, SIGMA_BIT_POS, SIGMA_COPY_POS, SIGMA_COPY_RES, SIGMA_RANGE_RES,
    SIGMA_SETUP_RES, SIG_HASH_SETUP_RES, S_POINT_SETUP_RES, TRACE_WIDTH, TRANSACTION_CYCLE_LENGTH,
    VALUE_COPY_MASK_INDEX,
};
use super::merkle;
use super::schnorr;
//use super::schnorr::constants::SCALAR_MUL_LENGTH;
use super::utils::{
    field::enforce_double_and_add_step,
    periodic_columns::{pad, stitch},
};
use crate::utils::{are_equal, not, EvaluationResult};
use winterfell::{
    math::{fields::f252::BaseElement, FieldElement},
    Air, AirContext, Assertion, ByteWriter, EvaluationFrame, ProofOptions, Serializable, TraceInfo,
    TransitionConstraintDegree,
};

// MERKLE PATH VERIFICATION AIR
// ================================================================================================

pub struct PublicInputs {
    pub initial_root: [BaseElement; 2],
    pub final_root: [BaseElement; 2],
}

impl Serializable for PublicInputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(&self.initial_root[..]);
        target.write(&self.final_root[..]);
    }
}

pub struct TransactionAir {
    context: AirContext<BaseElement>,
    initial_root: [BaseElement; 2],
    final_root: [BaseElement; 2],
}

impl Air for TransactionAir {
    type BaseElement = BaseElement;
    type PublicInputs = PublicInputs;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        // Constraint degrees for enforcement of Rescue hash rounds
        let mut hash_constraint_degrees =
            vec![
                TransitionConstraintDegree::with_cycles(3, vec![TRANSACTION_CYCLE_LENGTH]);
                HASH_STATE_WIDTH
            ];

        // Constraint degrees of authentication paths for a Merkle tree update
        let mut update_auth_degrees = Vec::new();
        // Initial value hash constraints
        update_auth_degrees.append(&mut hash_constraint_degrees.clone());
        // Bits of index into Merkle tree
        update_auth_degrees.push(TransitionConstraintDegree::with_cycles(
            2,
            vec![TRANSACTION_CYCLE_LENGTH],
        ));
        // Initial value hash constraints
        update_auth_degrees.append(&mut hash_constraint_degrees);

        // Degrees for all constraints
        let mut degrees = Vec::new();
        // Authentication paths for updating sender and receiver
        degrees.append(&mut update_auth_degrees.clone());
        degrees.append(&mut update_auth_degrees);
        // Remaining constraints (prev root copy, balance update, intermediate root match, and prev root match)
        let mut remaining_degrees =
            vec![
                TransitionConstraintDegree::with_cycles(1, vec![TRANSACTION_CYCLE_LENGTH]);
                PREV_TREE_MATCH_RES + 2 - PREV_TREE_ROOT_RES
            ];
        degrees.append(&mut remaining_degrees);
        let bit_degree = 5; //if NUM_TRANSACTIONS == 1 {
                            //     3
                            // } else {
                            //     5
                            // };
        let schnorr_degrees = vec![
            // First scalar multiplication
            TransitionConstraintDegree::with_cycles(
                5,
                vec![TRANSACTION_CYCLE_LENGTH, TRANSACTION_CYCLE_LENGTH],
            ),
            TransitionConstraintDegree::with_cycles(
                4,
                vec![TRANSACTION_CYCLE_LENGTH, TRANSACTION_CYCLE_LENGTH],
            ),
            TransitionConstraintDegree::with_cycles(
                4,
                vec![TRANSACTION_CYCLE_LENGTH, TRANSACTION_CYCLE_LENGTH],
            ),
            TransitionConstraintDegree::with_cycles(2, vec![TRANSACTION_CYCLE_LENGTH]),
            // Second scalar multiplication
            TransitionConstraintDegree::with_cycles(
                bit_degree,
                vec![TRANSACTION_CYCLE_LENGTH, TRANSACTION_CYCLE_LENGTH],
            ),
            TransitionConstraintDegree::with_cycles(
                bit_degree,
                vec![TRANSACTION_CYCLE_LENGTH, TRANSACTION_CYCLE_LENGTH],
            ),
            TransitionConstraintDegree::with_cycles(
                bit_degree,
                vec![TRANSACTION_CYCLE_LENGTH, TRANSACTION_CYCLE_LENGTH],
            ),
            TransitionConstraintDegree::with_cycles(2, vec![TRANSACTION_CYCLE_LENGTH]),
            // Rescue hash
            TransitionConstraintDegree::with_cycles(
                1,
                vec![TRANSACTION_CYCLE_LENGTH, TRANSACTION_CYCLE_LENGTH],
            ),
            TransitionConstraintDegree::with_cycles(3, vec![TRANSACTION_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(3, vec![TRANSACTION_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(3, vec![TRANSACTION_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(3, vec![TRANSACTION_CYCLE_LENGTH]),
        ];

        // Update the constraint degrees with the ones for Schnorr
        for index in 0..POINT_WIDTH {
            degrees[index] = schnorr_degrees[index].clone();
            degrees[index + POINT_WIDTH + 1] = schnorr_degrees[index + POINT_WIDTH + 1].clone();
        }

        // Append the degrees for the copy columns followed by range proof equalities and Schnorr setup results
        degrees.append(&mut vec![
            TransitionConstraintDegree::with_cycles(
                1,
                vec![TRANSACTION_CYCLE_LENGTH]
            );
            SIGMA_SETUP_RES - SENDER_KEY_POINT_RES + 1
        ]);

        assert_eq!(TRACE_WIDTH, trace_info.width());
        TransactionAir {
            context: AirContext::new(trace_info, degrees, options),
            initial_root: pub_inputs.initial_root,
            final_root: pub_inputs.final_root,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseElement> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseElement>>(
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
        let schnorr_setup_flag = periodic_values[SCHNORR_SETUP_MASK_INDEX];
        let schnorr_mask = periodic_values[SCHNORR_MASK_INDEX];
        let scalar_mult_flag = periodic_values[SCALAR_MULT_MASK_INDEX];
        let doubling_flag = periodic_values[DOUBLING_MASK_INDEX];
        let schnorr_hash_flag = periodic_values[SCHNORR_HASH_MASK_INDEX];
        let hash_internal_input_flags =
            &periodic_values[HASH_INTERNAL_INPUT_MASKS_INDEX..HASH_INTERNAL_INPUT_MASKS_INDEX + 3];
        let range_proof_flag = periodic_values[RANGE_PROOF_STEP_MASK_INDEX];
        let range_proof_finish_flag = periodic_values[RANGE_PROOF_FINISH_MASK_INDEX];
        let copy_values_flag = periodic_values[VALUE_COPY_MASK_INDEX];
        let ark = &periodic_values[ARK_INDEX..];

        // Generate dependent masks from existing masks
        let copy_hash_flag = not(schnorr_hash_flag) * schnorr_mask;
        let final_point_addition_flag = not(scalar_mult_flag) * schnorr_mask;
        let addition_flag = not(doubling_flag) * scalar_mult_flag;
        let copy_rx_flag = not(schnorr_setup_flag + final_point_addition_flag) * schnorr_mask;

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
            schnorr_setup_flag,
            doubling_flag,
            addition_flag,
            final_point_addition_flag,
            copy_hash_flag,
            hash_internal_input_flags,
            copy_rx_flag,
            range_proof_flag,
            range_proof_finish_flag,
            copy_values_flag,
        )
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseElement>> {
        // Assert the presence of the appropriate initial and final tree roots
        let last_step = self.trace_length() - 1;
        vec![
            Assertion::single(PREV_TREE_ROOT_POS, 0, self.initial_root[0]),
            Assertion::single(PREV_TREE_ROOT_POS + 1, 0, self.initial_root[1]),
            Assertion::single(PREV_TREE_ROOT_POS, last_step, self.final_root[0]),
            Assertion::single(PREV_TREE_ROOT_POS + 1, last_step, self.final_root[1]),
        ]
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseElement>> {
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

    // Add the common columns for ARK round constants
    let pre_merkle_columns = merkle::init::periodic_columns();
    stitch(
        &mut columns,
        pre_merkle_columns,
        (ARK_INDEX..ARK_INDEX + HASH_STATE_WIDTH * 2)
            .enumerate()
            .collect(),
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
            SCHNORR_HASH_MASK_INDEX,
        ]
        .into_iter()
        .enumerate()
        .collect(),
    );
    // Create a column for the Schnorr setup mask
    let mut schnorr_setup_mask = vec![BaseElement::ZERO; SIG_CYCLE_LENGTH];
    schnorr_setup_mask[0] = BaseElement::ONE;
    stitch(
        &mut columns,
        vec![schnorr_setup_mask],
        vec![(0, SCHNORR_SETUP_MASK_INDEX)],
    );
    // Create columns for the input copy masks
    let mut input_masks = vec![vec![BaseElement::ZERO; SIG_CYCLE_LENGTH]; 3];
    for (input_num, mask) in input_masks.iter_mut().enumerate().take(3) {
        mask[(input_num + 1) * HASH_CYCLE_LENGTH - 1] = BaseElement::ONE;
    }
    stitch(
        &mut columns,
        input_masks,
        (HASH_INTERNAL_INPUT_MASKS_INDEX..HASH_INTERNAL_INPUT_MASKS_INDEX + 3)
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

    length += SIG_CYCLE_LENGTH - 1;
    // Pad out the copy constraints
    pad(
        &mut columns,
        vec![VALUE_COPY_MASK_INDEX],
        length,
        BaseElement::ONE,
    );

    pad(
        &mut columns,
        vec![MERKLE_MASK_INDEX, FINISH_MASK_INDEX, HASH_MASK_INDEX],
        length,
        BaseElement::ZERO,
    );
    // Pad to finish the cycle length
    length += 1;
    pad(
        &mut columns,
        vec![
            SETUP_MASK_INDEX,
            MERKLE_MASK_INDEX,
            FINISH_MASK_INDEX,
            HASH_MASK_INDEX,
            SCHNORR_SETUP_MASK_INDEX,
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
        (HASH_INTERNAL_INPUT_MASKS_INDEX..HASH_INTERNAL_INPUT_MASKS_INDEX + 3).collect(),
        length,
        BaseElement::ZERO,
    );

    // Add the columns for the Merkle component
    let merkle_columns = merkle::update::periodic_columns();
    stitch(&mut columns, merkle_columns.clone(), vec![]);

    stitch(
        &mut columns,
        merkle_columns,
        vec![
            (0, SETUP_MASK_INDEX),
            (1, MERKLE_MASK_INDEX),
            (2, HASH_INPUT_MASK_INDEX),
            (3, FINISH_MASK_INDEX),
            (4, HASH_MASK_INDEX),
        ],
    );

    // Pad to finish the cycle length
    length += MERKLE_UPDATE_LENGTH;
    pad(
        &mut columns,
        vec![
            SETUP_MASK_INDEX,
            MERKLE_MASK_INDEX,
            FINISH_MASK_INDEX,
            HASH_MASK_INDEX,
            SCHNORR_SETUP_MASK_INDEX,
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
    schnorr_setup_flag: E,
    doubling_flag: E,
    addition_flag: E,
    final_point_addition_flag: E,
    copy_hash_flag: E,
    hash_internal_input_flags: &[E],
    copy_rx_flag: E,
    range_proof_flag: E,
    range_proof_finish_flag: E,
    copy_values_flag: E,
) {
    // Enforce no change in registers representing keys
    result.agg_constraint(
        VALUE_CONSTRAINT_RES,
        transaction_setup_flag,
        are_equal(current[SENDER_INITIAL_POS], current[SENDER_UPDATED_POS]),
    );
    result.agg_constraint(
        VALUE_CONSTRAINT_RES + 1,
        transaction_setup_flag,
        are_equal(
            current[SENDER_INITIAL_POS + 1],
            current[SENDER_UPDATED_POS + 1],
        ),
    );
    result.agg_constraint(
        VALUE_CONSTRAINT_RES + 2,
        transaction_setup_flag,
        are_equal(current[RECEIVER_INITIAL_POS], current[RECEIVER_UPDATED_POS]),
    );
    result.agg_constraint(
        VALUE_CONSTRAINT_RES + 3,
        transaction_setup_flag,
        are_equal(
            current[RECEIVER_INITIAL_POS + 1],
            current[RECEIVER_UPDATED_POS + 1],
        ),
    );
    // Enforce no change in the receiver's nonce
    result.agg_constraint(
        VALUE_CONSTRAINT_RES + 4,
        transaction_setup_flag,
        are_equal(
            current[RECEIVER_INITIAL_POS + 3],
            current[RECEIVER_UPDATED_POS + 3],
        ),
    );
    // Enforce that the change in balances cancels out
    result.agg_constraint(
        BALANCE_CONSTRAINT_RES,
        transaction_setup_flag,
        are_equal(
            current[SENDER_INITIAL_POS + 2] - current[SENDER_UPDATED_POS + 2],
            current[RECEIVER_UPDATED_POS + 2] - current[RECEIVER_INITIAL_POS + 2],
        ),
    );
    // Enforce change in the sender's nonce
    result.agg_constraint(
        NONCE_UPDATE_CONSTRAINT_RES,
        transaction_setup_flag,
        are_equal(
            current[SENDER_UPDATED_POS + 3],
            current[SENDER_INITIAL_POS + 3] + E::ONE,
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
        for offset in 0..2 {
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
            current[SENDER_INITIAL_POS + 2] - current[SENDER_UPDATED_POS + 2],
        ),
    );
    // Enforce proper copying of sigma and the nonce
    for (res_index, origin_index, copy_index) in [
        (SIGMA_COPY_RES, SENDER_UPDATED_POS + 2, SIGMA_COPY_POS),
        (NONCE_COPY_RES, SENDER_INITIAL_POS + 3, NONCE_COPY_POS),
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
        for offset in 0..2 {
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
    let mut hash_internal_inputs = [E::ZERO; 2];
    for i in 0..2 {
        hash_internal_inputs[i] += hash_internal_input_flags[0] * next[SENDER_KEY_POINT_POS + i];
        hash_internal_inputs[i] += hash_internal_input_flags[1] * next[RECEIVER_KEY_POINT_POS + i];
    }
    hash_internal_inputs[0] += hash_internal_input_flags[2] * next[DELTA_COPY_POS];
    hash_internal_inputs[1] += hash_internal_input_flags[2] * next[NONCE_COPY_POS];

    // Enforce proper setup of the inouts for the Schnorr component
    // Enforce that the first and second points start at infinity
    for (point_setup_res, point_pos) in [
        (S_POINT_SETUP_RES, S_POINT_POS),
        (HP_POINT_SETUP_RES, HP_POINT_POS),
    ] {
        for (offset, coordinate) in vec![E::ZERO, E::ONE, E::ZERO].into_iter().enumerate() {
            result.agg_constraint(
                point_setup_res + offset,
                schnorr_setup_flag,
                are_equal(current[point_pos + offset], coordinate),
            );
        }
    }
    // Enforce that the vomputation of h in the field starts with 0
    result.agg_constraint(
        H_FIELD_SETUP_RES,
        schnorr_setup_flag,
        are_equal(current[H_FIELD_POS], E::ZERO),
    );
    // Enforce that all but the first hash state register are initialized with zeros
    for offset in 1..HASH_STATE_WIDTH {
        result.agg_constraint(
            SIG_HASH_SETUP_RES + offset - 1,
            schnorr_setup_flag,
            are_equal(current[SIG_HASH_POS + offset], E::ZERO),
        );
    }
    // Enforce copying of the purported x component of R into its copy position
    result.agg_constraint(
        RX_COPY_RES,
        schnorr_setup_flag,
        are_equal(next[RX_COPY_POS], current[SCHNORR_HASH_POS]),
    );

    schnorr::evaluate_constraints(
        &mut result[0..SCHNORR_REGISTER_WIDTH],
        &current[0..SCHNORR_REGISTER_WIDTH],
        &next[0..SCHNORR_REGISTER_WIDTH],
        ark,
        doubling_flag,
        addition_flag,
        &next[SENDER_KEY_POINT_POS..SENDER_KEY_POINT_POS + 2],
        final_point_addition_flag,
        hash_flag,
        copy_hash_flag,
        &hash_internal_inputs,
    );

    // Enforce proper copying of the x component of R "around" the hash/range proof component
    result.agg_constraint(
        RX_COPY_RES,
        copy_rx_flag,
        are_equal(next[RX_COPY_POS], current[RX_COPY_POS]),
    );

    // Enforce proper setup of the range proofs
    result.agg_constraint(
        DELTA_SETUP_RES,
        schnorr_setup_flag,
        are_equal(current[DELTA_ACCUMULATE_POS], E::ZERO),
    );
    result.agg_constraint(
        SIGMA_SETUP_RES,
        schnorr_setup_flag,
        are_equal(current[SIGMA_ACCUMULATE_POS], E::ZERO),
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
        are_equal(next[SIGMA_ACCUMULATE_POS], next[SIGMA_COPY_POS]),
    );
    // Enforce that the purported x component of T matches the computed one
    result.agg_constraint(
        RX_COPY_RES,
        final_point_addition_flag,
        are_equal(next[0], current[RX_COPY_POS]),
    );
}
