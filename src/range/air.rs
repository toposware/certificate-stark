// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::field;
use winterfell::{
    math::{fields::f63::BaseElement, FieldElement},
    Air, AirContext, Assertion, ByteWriter, EvaluationFrame, ProofOptions, Serializable, TraceInfo,
    TransitionConstraintDegree,
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
    type BaseField = BaseElement;
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

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
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

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
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
