// Copyright (c) ToposWare and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use winterfell::{FieldExtension, HashFunction, ProofOptions};

#[test]
fn pre_merkle_test_basic_proof_verification() {
    let pre_merkle = Box::new(super::PreMerkleExample::new(build_options()));
    let proof = pre_merkle.prove();
    assert!(pre_merkle.verify(proof).is_ok());
}

#[test]
fn pre_merkle_test_basic_proof_verification_fail() {
    let pre_merkle = Box::new(super::PreMerkleExample::new(build_options()));
    let proof = pre_merkle.prove();
    let verified = pre_merkle.verify_with_wrong_inputs(proof);
    assert!(verified.is_err());
}

fn build_options() -> ProofOptions {
    ProofOptions::new(
        42,
        4,
        0,
        HashFunction::Blake3_256,
        FieldExtension::None,
        4,
        256,
    )
}
