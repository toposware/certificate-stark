// Copyright (c) ToposWare and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use winterfell::{FieldExtension, HashFunction, ProofOptions};

#[test]
fn transaction_test_basic_proof_verification() {
    let transaction = Box::new(super::TransactionExample::new(build_options(1), 2));
    let proof = transaction.prove();
    assert!(transaction.verify(proof).is_ok());
}

#[test]
fn transaction_test_basic_proof_verification_quadratic_extension() {
    let transaction = Box::new(super::TransactionExample::new(build_options(2), 2));
    let proof = transaction.prove();
    assert!(transaction.verify(proof).is_ok());
}

#[test]
fn transaction_test_basic_proof_verification_cubic_extension() {
    let transaction = Box::new(super::TransactionExample::new(build_options(3), 2));
    let proof = transaction.prove();
    assert!(transaction.verify(proof).is_ok());
}

#[test]
fn transaction_test_basic_proof_verification_fail() {
    let transaction = Box::new(super::TransactionExample::new(build_options(1), 2));
    let proof = transaction.prove();
    let verified = transaction.verify_with_wrong_inputs(proof);
    assert!(verified.is_err());
}

fn build_options(extension: u8) -> ProofOptions {
    ProofOptions::new(
        42,
        4,
        0,
        HashFunction::Blake3_256,
        match extension {
            2 => FieldExtension::Quadratic,
            3 => FieldExtension::Cubic,
            _ => FieldExtension::None,
        },
        4,
        256,
    )
}
