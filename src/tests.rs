// Copyright (c) ToposWare and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use winterfell::{FieldExtension, HashFunction, ProofOptions};

#[test]
fn transaction_test_basic_proof_verification() {
    let transaction = Box::new(super::TransactionExample::new(build_options(), 2));
    let proof = transaction.prove();
    assert!(transaction.verify(proof).is_ok());
}

#[test]
fn transaction_test_basic_proof_verification_fail() {
    let transaction = Box::new(super::TransactionExample::new(build_options(), 2));
    let proof = transaction.prove();
    let verified = transaction.verify_with_wrong_inputs(proof);
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
