// Copyright (c) Toposware, Inc. 2021
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use winterfell::{
    math::fields::f63::BaseElement, FieldExtension, HashFunction, ProofOptions, StarkProof,
    VerifierError,
};

#[cfg(feature = "std")]
use log::debug;
#[cfg(feature = "std")]
use std::time::Instant;
#[cfg(feature = "std")]
use winterfell::math::log2;

use super::utils::field;

mod air;
pub(crate) use air::{build_trace, init_range_verification_state, update_range_verification_state};
use air::{PublicInputs, RangeProofAir};

#[cfg(test)]
mod tests;

pub(crate) const RANGE_LOG: usize = 64;

// RANGE PROOF EXAMPLE
// ================================================================================================

/// Outputs a new `RangeProofExample` of a given number
pub fn get_example(number: BaseElement) -> RangeProofExample {
    RangeProofExample::new(
        // TODO: make it customizable
        ProofOptions::new(
            42,
            8,
            0,
            HashFunction::Blake3_256,
            FieldExtension::None,
            4,
            256,
        ),
        number,
    )
}

/// A struct to perform proofs of valid range of a number
#[derive(Clone, Debug)]
pub struct RangeProofExample {
    options: ProofOptions,
    number: BaseElement,
    range_log: usize,
}

impl RangeProofExample {
    /// Outputs a new `RangeProofExample` of a given number
    pub fn new(options: ProofOptions, number: BaseElement) -> RangeProofExample {
        RangeProofExample {
            options,
            number,
            range_log: RANGE_LOG,
        }
    }

    /// Proves that a number is in a valid range
    pub fn prove(&self) -> StarkProof {
        // generate the execution trace
        #[cfg(feature = "std")]
        debug!(
            "Generating a Range proof for number of {} bits\n\
            ---------------------",
            self.range_log,
        );
        #[cfg(feature = "std")]
        let now = Instant::now();
        let trace = build_trace(self.number, self.range_log);
        #[cfg(feature = "std")]
        debug!(
            "Generated execution trace of {} registers and 2^{} steps in {} ms",
            trace.width(),
            log2(trace.length()),
            now.elapsed().as_millis()
        );

        // generate the proof
        let pub_inputs = PublicInputs {
            number: self.number,
        };
        winterfell::prove::<RangeProofAir>(trace, pub_inputs, self.options.clone()).unwrap()
    }

    /// Verifies the validity of a proof of correct range of a given number
    pub fn verify(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            number: self.number,
        };
        winterfell::verify::<RangeProofAir>(proof, pub_inputs)
    }

    #[cfg(test)]
    fn verify_with_wrong_inputs(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            number: -self.number,
        };
        winterfell::verify::<RangeProofAir>(proof, pub_inputs)
    }
}
