use super::constants::*;
use bitvec::{order::Lsb0, view::AsBits};
use winterfell::{
    math::{curves::curve_f63::Scalar, fields::f63::BaseElement},
    ProofOptions, Prover, TraceTable,
};

#[cfg(feature = "concurrent")]
use winterfell::iterators::*;

use super::trace::*;
use super::PublicInputs;
use super::SchnorrAir;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

// SCHNORR PROVER
// ================================================================================================

pub struct SchnorrProver {
    options: ProofOptions,
    messages: Vec<[BaseElement; AFFINE_POINT_WIDTH * 2 + 4]>,
    signatures: Vec<([BaseElement; POINT_COORDINATE_WIDTH], Scalar)>,
}

impl SchnorrProver {
    pub fn new(
        options: ProofOptions,
        messages: Vec<[BaseElement; AFFINE_POINT_WIDTH * 2 + 4]>,
        signatures: Vec<([BaseElement; POINT_COORDINATE_WIDTH], Scalar)>,
    ) -> Self {
        Self {
            options,
            messages,
            signatures,
        }
    }

    pub fn build_trace(&self) -> TraceTable<BaseElement> {
        // allocate memory to hold the trace table
        let trace_length = SIG_CYCLE_LENGTH * self.messages.len();
        let mut trace = TraceTable::new(TRACE_WIDTH, trace_length);
        trace.fragments(SIG_CYCLE_LENGTH).for_each(|mut sig_trace| {
            let i = sig_trace.index();
            let (pkey_point, s_bytes, h_bytes) =
                build_sig_info(&self.messages[i], &self.signatures[i]);
            let s_bits = s_bytes.as_bits::<Lsb0>();
            let h_bits = h_bytes.as_bits::<Lsb0>();
            sig_trace.fill(
                |state| {
                    init_sig_verification_state(self.signatures[i], state);
                },
                |step, state| {
                    update_sig_verification_state(
                        step,
                        self.messages[i],
                        pkey_point,
                        s_bits,
                        h_bits,
                        state,
                    );
                },
            );
        });
        trace
    }
}

impl Prover for SchnorrProver {
    type BaseField = BaseElement;
    type Air = SchnorrAir;
    type Trace = TraceTable<BaseElement>;

    // This method should use the existing trace to extract the public inputs to be given
    // to the verifier. As the Schnorr sub-AIR program is not intended to be used as a
    // standalone AIR program, we bypass this here by storing directly the messages and signatures
    // in the SchnorrProver struct. This is not used in the complete state transition Air program
    // where only initial and final Merkle roots are provided to the verifier.
    fn get_pub_inputs(&self, _trace: &Self::Trace) -> PublicInputs {
        PublicInputs {
            messages: self.messages.clone(),
            signatures: self.signatures.clone(),
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }
}
