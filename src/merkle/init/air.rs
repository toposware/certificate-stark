// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::utils::rescue;

use super::constants::*;

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
    pub s_inputs: [BaseElement; AFFINE_POINT_WIDTH + 2],
    pub r_inputs: [BaseElement; AFFINE_POINT_WIDTH + 2],
    pub delta: BaseElement,
}

impl Serializable for PublicInputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        Serializable::write_batch_into(&self.s_inputs, target);
        Serializable::write_batch_into(&self.r_inputs, target);
        target.write(self.delta);
    }
}

pub struct PreMerkleAir {
    context: AirContext<BaseElement>,
    s_inputs: [BaseElement; AFFINE_POINT_WIDTH + 2],
    r_inputs: [BaseElement; AFFINE_POINT_WIDTH + 2],
    delta: BaseElement,
}

impl Air for PreMerkleAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        let degrees = transition_constraint_degrees();

        assert_eq!(TRACE_WIDTH, trace_info.width());
        PreMerkleAir {
            context: AirContext::new(trace_info, degrees, options),
            s_inputs: pub_inputs.s_inputs,
            r_inputs: pub_inputs.r_inputs,
            delta: pub_inputs.delta,
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
        // expected state width is 4 hashes and 2 bit decompositions
        debug_assert_eq!(TRACE_WIDTH, current.len());
        debug_assert_eq!(TRACE_WIDTH, next.len());

        // split periodic values into masks and Rescue round constants
        let ark = &periodic_values;

        evaluate_constraints(result, current, next, ark, FieldElement::ONE);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = vec![];
        //check initial sender values against public inputs
        for i in 0..AFFINE_POINT_WIDTH + 2 {
            assertions.push(Assertion::single(
                SENDER_INITIAL_POS + i,
                0,
                self.s_inputs[i],
            ));
        }

        //check updated sender values against public inputs
        for i in 0..AFFINE_POINT_WIDTH {
            assertions.push(Assertion::single(
                SENDER_UPDATED_POS + i,
                0,
                self.s_inputs[i],
            ));
        }
        assertions.push(Assertion::single(
            SENDER_UPDATED_POS + AFFINE_POINT_WIDTH,
            0,
            self.s_inputs[AFFINE_POINT_WIDTH] - self.delta,
        ));
        assertions.push(Assertion::single(
            SENDER_UPDATED_POS + AFFINE_POINT_WIDTH + 1,
            0,
            self.s_inputs[AFFINE_POINT_WIDTH + 1] + BaseElement::ONE,
        ));

        //check initial receiver values against public inputs
        for i in 0..AFFINE_POINT_WIDTH + 2 {
            assertions.push(Assertion::single(
                RECEIVER_INITIAL_POS + i,
                0,
                self.r_inputs[i],
            ));
        }

        //check updated receiver values against public inputs
        for i in 0..AFFINE_POINT_WIDTH {
            assertions.push(Assertion::single(
                RECEIVER_UPDATED_POS + i,
                0,
                self.r_inputs[i],
            ));
        }
        assertions.push(Assertion::single(
            RECEIVER_UPDATED_POS + AFFINE_POINT_WIDTH,
            0,
            self.r_inputs[AFFINE_POINT_WIDTH] + self.delta,
        ));
        assertions.push(Assertion::single(
            RECEIVER_UPDATED_POS + AFFINE_POINT_WIDTH + 1,
            0,
            self.r_inputs[AFFINE_POINT_WIDTH + 1],
        ));

        assertions
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        periodic_columns()
    }
}

// HELPER FUNCTIONS
// ------------------------------------------------------------------------------------------------

pub(crate) fn periodic_columns() -> Vec<Vec<BaseElement>> {
    rescue::get_round_constants()
}

pub(crate) fn evaluate_constraints<E: FieldElement + From<BaseElement>>(
    result: &mut [E],
    current: &[E],
    next: &[E],
    ark: &[E],
    transaction_setup_flag: E,
) {
    // The result array is smaller than the trace width, to keep registers consistent
    // with merkle::update module. Hence, we shift the indexing in the result array,
    // to ignore unused binary decompositions of the sender and receiver paths.

    // Always check correct evaluation of the hash round
    rescue::enforce_round(
        &mut result[SENDER_INITIAL_POS..SENDER_INITIAL_POS + HASH_STATE_WIDTH],
        &current[SENDER_INITIAL_POS..SENDER_INITIAL_POS + HASH_STATE_WIDTH],
        &next[SENDER_INITIAL_POS..SENDER_INITIAL_POS + HASH_STATE_WIDTH],
        ark,
        transaction_setup_flag,
    );
    // Also enforce contraints for Rescue on new path
    rescue::enforce_round(
        &mut result[SENDER_UPDATED_POS - 1..SENDER_UPDATED_POS - 1 + HASH_STATE_WIDTH],
        &current[SENDER_UPDATED_POS..SENDER_UPDATED_POS + HASH_STATE_WIDTH],
        &next[SENDER_UPDATED_POS..SENDER_UPDATED_POS + HASH_STATE_WIDTH],
        ark,
        transaction_setup_flag,
    );

    // Repeat for the receiver
    rescue::enforce_round(
        &mut result[RECEIVER_INITIAL_POS - 1..RECEIVER_INITIAL_POS - 1 + HASH_STATE_WIDTH],
        &current[RECEIVER_INITIAL_POS..RECEIVER_INITIAL_POS + HASH_STATE_WIDTH],
        &next[RECEIVER_INITIAL_POS..RECEIVER_INITIAL_POS + HASH_STATE_WIDTH],
        ark,
        transaction_setup_flag,
    );
    rescue::enforce_round(
        &mut result[RECEIVER_UPDATED_POS - 2..RECEIVER_UPDATED_POS - 2 + HASH_STATE_WIDTH],
        &current[RECEIVER_UPDATED_POS..RECEIVER_UPDATED_POS + HASH_STATE_WIDTH],
        &next[RECEIVER_UPDATED_POS..RECEIVER_UPDATED_POS + HASH_STATE_WIDTH],
        ark,
        transaction_setup_flag,
    );
}

pub(crate) fn transition_constraint_degrees() -> Vec<TransitionConstraintDegree> {
    let mut degrees = Vec::with_capacity(HASH_STATE_WIDTH * 4);
    for _ in 0..HASH_STATE_WIDTH * 4 {
        degrees.push(TransitionConstraintDegree::new(3));
    }

    degrees
}
