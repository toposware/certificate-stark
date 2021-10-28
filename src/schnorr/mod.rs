// Copyright (c) ToposWare and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use bitvec::{order::Lsb0, view::AsBits};
use log::debug;
use rand_core::OsRng;
use std::time::Instant;
use winterfell::{
    crypto::Hasher,
    math::{
        curve::{AffinePoint, Scalar},
        fields::f252::BaseElement,
        log2, FieldElement,
    },
    FieldExtension, HashFunction, ProofOptions, StarkProof, VerifierError,
};

use super::utils::{
    ecc, field,
    rescue::{self, Rescue252},
};

pub mod constants;
mod trace;
pub use trace::{
    build_sig_info, build_trace, init_sig_verification_state, update_sig_verification_state,
};

mod air;
pub use air::{evaluate_constraints, periodic_columns};
use air::{PublicInputs, SchnorrAir};

#[cfg(test)]
mod tests;

// SCHNORR SIGNATURE EXAMPLE
// ================================================================================================

pub fn get_example(num_signatures: usize) -> SchnorrExample {
    SchnorrExample::new(
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
        num_signatures,
    )
}

pub struct SchnorrExample {
    options: ProofOptions,
    messages: Vec<[BaseElement; 6]>,
    signatures: Vec<(BaseElement, Scalar)>,
}

impl SchnorrExample {
    pub fn new(options: ProofOptions, num_signatures: usize) -> SchnorrExample {
        let mut rng = OsRng;
        let mut skeys = Vec::with_capacity(num_signatures);
        let mut messages = Vec::with_capacity(num_signatures);
        let mut signatures = Vec::with_capacity(num_signatures);

        for _ in 0..num_signatures {
            let skey = Scalar::random(&mut rng);
            let pkey = AffinePoint::from(AffinePoint::generator() * skey);

            let mut message = [BaseElement::ZERO; 6];
            message[0] = pkey.get_x();
            message[1] = pkey.get_y();
            for i in 2..6 {
                message[i] = BaseElement::random(&mut rng);
            }

            skeys.push(skey);
            messages.push(message);
        }

        // compute the Schnorr signatures
        let now = Instant::now();

        for i in 0..num_signatures {
            signatures.push(sign(messages[i], skeys[i]));
        }

        debug!(
            "Computed {} Schnorr signatures in {} ms",
            num_signatures,
            now.elapsed().as_millis(),
        );

        // verify the Schnorr signatures
        let now = Instant::now();

        for i in 0..num_signatures {
            assert!(verify_signature(messages[i], signatures[i]));
        }

        debug!(
            "Verified {} Schnorr signatures in {} ms",
            num_signatures,
            now.elapsed().as_millis(),
        );

        SchnorrExample {
            options,
            messages,
            signatures,
        }
    }
    pub fn prove(&self) -> StarkProof {
        // generate the execution trace
        debug!(
            "Generating proof for verifying {} Schnorr signatures\n\
            ---------------------",
            self.messages.len(),
        );
        let now = Instant::now();
        let trace = build_trace(&self.messages, &self.signatures);
        let trace_length = trace.length();
        debug!(
            "Generated execution trace of {} registers and 2^{} steps in {} ms",
            trace.width(),
            log2(trace_length),
            now.elapsed().as_millis()
        );

        // generate the proof
        let pub_inputs = PublicInputs {
            messages: self.messages.clone(),
            signatures: self.signatures.clone(),
        };
        winterfell::prove::<SchnorrAir>(trace, pub_inputs, self.options.clone()).unwrap()
    }

    pub fn verify(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            messages: self.messages.clone(),
            signatures: self.signatures.clone(),
        };
        winterfell::verify::<SchnorrAir>(proof, pub_inputs)
    }

    pub fn verify_with_wrong_inputs(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            messages: vec![self.messages[0]; self.signatures.len()],
            signatures: self.signatures.clone(),
        };
        winterfell::verify::<SchnorrAir>(proof, pub_inputs)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Computes a Schnorr signature
pub fn sign(message: [BaseElement; 6], skey: Scalar) -> (BaseElement, Scalar) {
    let mut rng = OsRng;
    let r = Scalar::random(&mut rng);
    let r_point = AffinePoint::from(AffinePoint::generator() * r);

    let h = hash_message([r_point.get_x(), BaseElement::ZERO], message);
    let h_bytes = h[0].to_bytes();
    let h_bits = h_bytes.as_bits::<Lsb0>();

    // Reconstruct a scalar from the binary sequence of h
    let h_scalar = Scalar::from_bits(h_bits);

    let s = r - skey * h_scalar;
    (r_point.get_x(), s)
}

/// Verifies a Schnorr signature
pub fn verify_signature(message: [BaseElement; 6], signature: (BaseElement, Scalar)) -> bool {
    let s_point = AffinePoint::generator() * signature.1;
    let pkey = AffinePoint::from_raw_coordinates([message[0], message[1]]);
    assert!(pkey.is_on_curve());

    let h = hash_message([signature.0, BaseElement::ZERO], message);
    let h_bytes = h[0].to_bytes();
    let h_bits = h_bytes.as_bits::<Lsb0>();

    // Reconstruct a scalar from the binary sequence of h
    let h_scalar = Scalar::from_bits(h_bits);

    let h_pubkey_point = pkey * h_scalar;

    let r_point = AffinePoint::from(s_point + h_pubkey_point);

    r_point.get_x() == signature.0
}

fn hash_message(input: [BaseElement; 2], message: [BaseElement; 6]) -> [BaseElement; 2] {
    let mut h = Rescue252::digest(&input);
    let mut message_chunk = rescue::Hash::new(message[0], message[1]);

    h = Rescue252::merge(&[h, message_chunk]);
    message_chunk = rescue::Hash::new(message[2], message[3]);
    h = Rescue252::merge(&[h, message_chunk]);
    message_chunk = rescue::Hash::new(message[4], message[5]);
    h = Rescue252::merge(&[h, message_chunk]);

    h.to_elements()
}
