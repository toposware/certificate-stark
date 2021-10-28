// Copyright (c) ToposWare and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use winterfell::{FieldExtension, HashFunction, ProofOptions};

#[test]
fn schnorr_test_basic_proof_verification() {
    let schnorr = super::SchnorrExample::new(build_options(), 2);
    let proof = schnorr.prove();
    assert!(schnorr.verify(proof).is_ok());
}

#[test]
fn schnorr_test_basic_proof_verification_fail() {
    let schnorr = super::SchnorrExample::new(build_options(), 2);
    let proof = schnorr.prove();
    let verified = schnorr.verify_with_wrong_inputs(proof);
    assert!(verified.is_err());
}

fn build_options() -> ProofOptions {
    ProofOptions::new(
        42,
        8,
        0,
        HashFunction::Blake3_256,
        FieldExtension::None,
        4,
        256,
    )
}
