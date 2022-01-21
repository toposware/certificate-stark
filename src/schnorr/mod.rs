// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use bitvec::{order::Lsb0, view::AsBits};
use rand_core::OsRng;
use winterfell::{
    crypto::Hasher,
    math::{
        curves::curve_f63::{AffinePoint, Scalar},
        fields::f63::BaseElement,
        FieldElement,
    },
    FieldExtension, HashFunction, ProofOptions, StarkProof, VerifierError,
};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use log::debug;
#[cfg(feature = "std")]
use std::time::Instant;
#[cfg(feature = "std")]
use winterfell::math::log2;

use super::utils::{
    ecc::{self, AFFINE_POINT_WIDTH, POINT_COORDINATE_WIDTH},
    field,
    rescue::{self, Rescue63, RATE_WIDTH as HASH_RATE_WIDTH},
};

pub(crate) mod constants;
mod trace;
pub(crate) use trace::{
    build_sig_info, build_trace, init_sig_verification_state, update_sig_verification_state,
};

mod air;
pub(crate) use air::{evaluate_constraints, periodic_columns, transition_constraint_degrees};
use air::{PublicInputs, SchnorrAir};

#[cfg(test)]
mod tests;

// SCHNORR SIGNATURE EXAMPLE
// ================================================================================================

/// Outputs a new `SchnorrExample` with `num_signatures` signatures on random messages.
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

/// A struct to perform Schnorr signature valid
/// verification proof among a set of signed messages.
#[derive(Clone, Debug)]
pub struct SchnorrExample {
    options: ProofOptions,
    messages: Vec<[BaseElement; AFFINE_POINT_WIDTH * 2 + 4]>,
    signatures: Vec<([BaseElement; POINT_COORDINATE_WIDTH], Scalar)>,
}

impl SchnorrExample {
    /// Outputs a new `SchnorrExample` with `num_signatures` signatures on random messages.
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
        #[cfg(feature = "std")]
        let now = Instant::now();

        for i in 0..num_signatures {
            signatures.push(sign(messages[i], skeys[i]));
        }

        #[cfg(feature = "std")]
        debug!(
            "Computed {} Schnorr signatures in {} ms",
            num_signatures,
            now.elapsed().as_millis(),
        );

        // verify the Schnorr signatures
        #[cfg(feature = "std")]
        let now = Instant::now();

        for i in 0..num_signatures {
            assert!(verify_signature(messages[i], signatures[i]));
        }

        #[cfg(feature = "std")]
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

    /// Proves the validity of a sequence of Schnorr signatures
    pub fn prove(&self) -> StarkProof {
        // generate the execution trace
        #[cfg(feature = "std")]
        debug!(
            "Generating proof for verifying {} Schnorr signatures\n\
            ---------------------",
            self.messages.len(),
        );
        #[cfg(feature = "std")]
        let now = Instant::now();
        let trace = build_trace(&self.messages, &self.signatures);
        #[cfg(feature = "std")]
        debug!(
            "Generated execution trace of {} registers and 2^{} steps in {} ms",
            trace.width(),
            log2(trace.length()),
            now.elapsed().as_millis()
        );

        // generate the proof
        let pub_inputs = PublicInputs {
            messages: self.messages.clone(),
            signatures: self.signatures.clone(),
        };
        winterfell::prove::<SchnorrAir>(trace, pub_inputs, self.options.clone()).unwrap()
    }

    /// Verifies the validity of a proof of correct Schnorr signature verification
    pub fn verify(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            messages: self.messages.clone(),
            signatures: self.signatures.clone(),
        };
        winterfell::verify::<SchnorrAir>(proof, pub_inputs)
    }

    #[cfg(test)]
    fn verify_with_wrong_inputs(&self, proof: StarkProof) -> Result<(), VerifierError> {
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
pub(crate) fn sign(
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
pub(crate) fn verify_signature(
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
