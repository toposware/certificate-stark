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
        curves::curve_f63::{AffinePoint, Scalar},
        fields::f63::BaseElement,
        log2, FieldElement,
    },
    FieldExtension, HashFunction, ProofOptions, StarkProof, VerifierError,
};

use super::utils::{
    ecc::{self, AFFINE_POINT_WIDTH, POINT_COORDINATE_WIDTH},
    field,
    rescue::{self, Rescue63, RATE_WIDTH as HASH_RATE_WIDTH},
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
    messages: Vec<[BaseElement; AFFINE_POINT_WIDTH * 2 + 4]>,
    signatures: Vec<([BaseElement; POINT_COORDINATE_WIDTH], Scalar)>,
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

            let mut message = [BaseElement::ZERO; AFFINE_POINT_WIDTH * 2 + 4];
            message[0..POINT_COORDINATE_WIDTH].copy_from_slice(&pkey.get_x());
            message[POINT_COORDINATE_WIDTH..AFFINE_POINT_WIDTH].copy_from_slice(&pkey.get_y());
            for msg in message.iter_mut().skip(AFFINE_POINT_WIDTH) {
                *msg = BaseElement::random(&mut rng);
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
pub fn sign(
    message: [BaseElement; AFFINE_POINT_WIDTH * 2 + 4],
    skey: Scalar,
) -> ([BaseElement; POINT_COORDINATE_WIDTH], Scalar) {
    let mut rng = OsRng;
    let r = Scalar::random(&mut rng);
    let r_point = AffinePoint::from(AffinePoint::generator() * r);

    let h = hash_message(r_point.get_x(), message);
    let mut h_bytes = [0u8; 32];
    for (i, h_word) in h.iter().enumerate().take(4) {
        h_bytes[8 * i..8 * i + 8].copy_from_slice(&h_word.to_bytes());
    }
    let h_bits = h_bytes.as_bits::<Lsb0>();

    // Reconstruct a scalar from the binary sequence of h
    let h_scalar = Scalar::from_bits(h_bits);

    let s = r - skey * h_scalar;
    (r_point.get_x(), s)
}

/// Verifies a Schnorr signature
pub fn verify_signature(
    message: [BaseElement; AFFINE_POINT_WIDTH * 2 + 4],
    signature: ([BaseElement; POINT_COORDINATE_WIDTH], Scalar),
) -> bool {
    let s_point = AffinePoint::generator() * signature.1;
    let mut pkey_coords = [BaseElement::ZERO; AFFINE_POINT_WIDTH];
    pkey_coords[..AFFINE_POINT_WIDTH].clone_from_slice(&message[..AFFINE_POINT_WIDTH]);
    let pkey = AffinePoint::from_raw_coordinates(pkey_coords);
    assert!(pkey.is_on_curve());

    let h = hash_message(signature.0, message);
    let mut h_bytes = [0u8; 32];
    for (i, h_word) in h.iter().enumerate().take(4) {
        h_bytes[8 * i..8 * i + 8].copy_from_slice(&h_word.to_bytes());
    }
    let h_bits = h_bytes.as_bits::<Lsb0>();

    // Reconstruct a scalar from the binary sequence of h
    let h_scalar = Scalar::from_bits(h_bits);

    let h_pubkey_point = pkey * h_scalar;

    let r_point = AffinePoint::from(s_point + h_pubkey_point);

    r_point.get_x() == signature.0
}

fn hash_message(
    input: [BaseElement; POINT_COORDINATE_WIDTH],
    message: [BaseElement; AFFINE_POINT_WIDTH * 2 + 4],
) -> [BaseElement; HASH_RATE_WIDTH] {
    let mut h = Rescue63::digest(&input);
    let mut message_chunk = rescue::Hash::new(
        message[0], message[1], message[2], message[3], message[4], message[5], message[6],
    );
    h = Rescue63::merge(&[h, message_chunk]);
    message_chunk = rescue::Hash::new(
        message[7],
        message[8],
        message[9],
        message[10],
        message[11],
        message[12],
        message[13],
    );
    h = Rescue63::merge(&[h, message_chunk]);
    message_chunk = rescue::Hash::new(
        message[14],
        message[15],
        message[16],
        message[17],
        message[18],
        message[19],
        message[20],
    );
    h = Rescue63::merge(&[h, message_chunk]);
    message_chunk = rescue::Hash::new(
        message[21],
        message[22],
        message[23],
        message[24],
        message[25],
        message[26],
        message[27],
    );
    h = Rescue63::merge(&[h, message_chunk]);

    h.to_elements()
}
