use super::constants::*;
use winterfell::{math::fields::f63::BaseElement, ProofOptions, Prover, Trace, TraceTable};

use super::trace::*;
use super::PreMerkleAir;
use super::PublicInputs;

// MERKLE INIT PROVER
// ================================================================================================

pub struct PreMerkleProver {
    options: ProofOptions,
}

impl PreMerkleProver {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }

    pub fn build_trace(
        &self,
        s_inputs: [BaseElement; AFFINE_POINT_WIDTH + 2],
        r_inputs: [BaseElement; AFFINE_POINT_WIDTH + 2],
        delta: BaseElement,
    ) -> TraceTable<BaseElement> {
        // allocate memory to hold the trace table
        let mut trace = TraceTable::new(TRACE_WIDTH, TRANSACTION_CYCLE_LENGTH);

        trace.fill(
            |state| {
                // initialize first state of the computation
                init_merkle_initialization_state(state, s_inputs, r_inputs, delta);
            },
            |step, state| {
                // execute the transition function for all steps
                update_merkle_initialization_state(step, state);
            },
        );

        trace
    }
}

impl Prover for PreMerkleProver {
    type BaseField = BaseElement;
    type Air = PreMerkleAir;
    type Trace = TraceTable<BaseElement>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> PublicInputs {
        PublicInputs {
            s_inputs: [
                trace.get(SENDER_INITIAL_POS, 0),
                trace.get(SENDER_INITIAL_POS + 1, 0),
                trace.get(SENDER_INITIAL_POS + 2, 0),
                trace.get(SENDER_INITIAL_POS + 3, 0),
                trace.get(SENDER_INITIAL_POS + 4, 0),
                trace.get(SENDER_INITIAL_POS + 5, 0),
                trace.get(SENDER_INITIAL_POS + 6, 0),
                trace.get(SENDER_INITIAL_POS + 7, 0),
                trace.get(SENDER_INITIAL_POS + 8, 0),
                trace.get(SENDER_INITIAL_POS + 9, 0),
                trace.get(SENDER_INITIAL_POS + 10, 0),
                trace.get(SENDER_INITIAL_POS + 11, 0),
                trace.get(SENDER_INITIAL_POS + 12, 0),
                trace.get(SENDER_INITIAL_POS + 13, 0),
            ],
            r_inputs: [
                trace.get(RECEIVER_INITIAL_POS, 0),
                trace.get(RECEIVER_INITIAL_POS + 1, 0),
                trace.get(RECEIVER_INITIAL_POS + 2, 0),
                trace.get(RECEIVER_INITIAL_POS + 3, 0),
                trace.get(RECEIVER_INITIAL_POS + 4, 0),
                trace.get(RECEIVER_INITIAL_POS + 5, 0),
                trace.get(RECEIVER_INITIAL_POS + 6, 0),
                trace.get(RECEIVER_INITIAL_POS + 7, 0),
                trace.get(RECEIVER_INITIAL_POS + 8, 0),
                trace.get(RECEIVER_INITIAL_POS + 9, 0),
                trace.get(RECEIVER_INITIAL_POS + 10, 0),
                trace.get(RECEIVER_INITIAL_POS + 11, 0),
                trace.get(RECEIVER_INITIAL_POS + 12, 0),
                trace.get(RECEIVER_INITIAL_POS + 13, 0),
            ],
            delta: trace.get(RECEIVER_UPDATED_POS + AFFINE_POINT_WIDTH, 0)
                - trace.get(RECEIVER_INITIAL_POS + AFFINE_POINT_WIDTH, 0),
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }
}
