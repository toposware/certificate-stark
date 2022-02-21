use bitvec::{order::Lsb0, slice::BitSlice, view::AsBits};
use winterfell::{
    math::{fields::f63::BaseElement, FieldElement},
    ProofOptions, Prover, Trace, TraceTable,
};

use super::air::TRACE_WIDTH;
use super::field;
use super::PublicInputs;
use super::RangeProofAir;

// RANGE PROVER
// ================================================================================================

pub struct RangeProver {
    options: ProofOptions,
}

impl RangeProver {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }

    pub fn build_trace(&self, number: BaseElement, range_log: usize) -> TraceTable<BaseElement> {
        // allocate memory to hold the trace table
        let trace_length = range_log;
        let mut trace = TraceTable::new(TRACE_WIDTH, trace_length);

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
}

impl Prover for RangeProver {
    type BaseField = BaseElement;
    type Air = RangeProofAir;
    type Trace = TraceTable<BaseElement>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> PublicInputs {
        PublicInputs {
            number: trace.get(1, trace.length() - 1),
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }
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
