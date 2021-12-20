// Copyright (c) 2021 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::field;
use bitvec::{order::Lsb0, slice::BitSlice, view::AsBits};
use winterfell::{
    math::{fields::f63::BaseElement, FieldElement},
    Air, AirContext, Assertion, ByteWriter, EvaluationFrame, ExecutionTrace, ProofOptions,
    Serializable, TraceInfo, TransitionConstraintDegree,
};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

// CONSTANTS
// ================================================================================================

/// Total number of registers in the trace
pub const TRACE_WIDTH: usize = 2;

// RESCUE AIR
// ================================================================================================

pub struct PublicInputs {
    pub number: BaseElement,
}

impl Serializable for PublicInputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(self.number);
    }
}

pub struct RangeProofAir {
    context: AirContext<BaseElement>,
    number: BaseElement,
}

impl Air for RangeProofAir {
    type BaseElement = BaseElement;
    type PublicInputs = PublicInputs;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        let degrees = transition_constraint_degrees();
        assert_eq!(TRACE_WIDTH, trace_info.width());
        RangeProofAir {
            context: AirContext::new(trace_info, degrees, options),
            number: pub_inputs.number,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseElement> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseElement>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        // Expected state width is TRACE_WIDTH field elements
        debug_assert_eq!(TRACE_WIDTH, current.len());
        debug_assert_eq!(TRACE_WIDTH, next.len());

        evaluate_constraints(result, current, next);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseElement>> {
        // Assert starting and ending values
        vec![
            // Starting values (see initialization in build_trace())
            Assertion::single(1, 0, BaseElement::ZERO),
            Assertion::single(1, self.trace_length() - 1, self.number),
        ]
    }
}

// HELPER EVALUATORS
// ------------------------------------------------------------------------------------------------

pub(crate) fn evaluate_constraints<E: FieldElement + From<BaseElement>>(
    result: &mut [E],
    current: &[E],
    next: &[E],
) {
    // Enforce a step of double-and-add in the field
    field::enforce_double_and_add_step(result, current, next, 1, 0, FieldElement::ONE);
}

pub(crate) fn transition_constraint_degrees() -> Vec<TransitionConstraintDegree> {
    vec![
        TransitionConstraintDegree::new(2),
        TransitionConstraintDegree::new(1),
    ]
}

// TRACE BUILDER
// ------------------------------------------------------------------------------------------------

pub(crate) fn build_trace(number: BaseElement, range_log: usize) -> ExecutionTrace<BaseElement> {
    // allocate memory to hold the trace table
    let trace_length = range_log;
    let mut trace = ExecutionTrace::new(TRACE_WIDTH, trace_length);

    let number_bytes = number.to_bytes();
    let number_bits = number_bytes.as_bits::<Lsb0>();

    trace.fill(
        |state| {
            init_range_verification_state(state);
        },
        |step, state| {
            // execute the transition function for all steps
            update_range_verification_state(step, range_log - 1, number_bits, state);
        },
    );

    trace
}

// TRACE INITIALIZATION
// ================================================================================================

pub(crate) fn init_range_verification_state(state: &mut [BaseElement]) {
    // initialize first state of the computation
    state[0] = BaseElement::ZERO; // bit
    state[1] = BaseElement::ZERO; // accumulated value
}

// TRACE TRANSITION FUNCTION
// ================================================================================================

pub(crate) fn update_range_verification_state(
    step: usize,
    range_log: usize,
    bits: &BitSlice<Lsb0, u8>,
    state: &mut [BaseElement],
) {
    if step < range_log {
        state[0] = BaseElement::from(bits[range_log - 1 - step] as u8);
        field::apply_double_and_add_step(state, 1, 0);
    }
}
