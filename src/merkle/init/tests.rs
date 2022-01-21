// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use winterfell::{FieldExtension, HashFunction, ProofOptions};

#[test]
fn pre_merkle_test_basic_proof_verification() {
    let pre_merkle = Box::new(super::PreMerkleExample::new(build_options(1)));
    let proof = pre_merkle.prove();
    assert!(pre_merkle.verify(proof).is_ok());
}

#[test]
fn pre_merkle_test_basic_proof_verification_quadratic_extension() {
    let pre_merkle = Box::new(super::PreMerkleExample::new(build_options(2)));
    let proof = pre_merkle.prove();
    assert!(pre_merkle.verify(proof).is_ok());
}

#[test]
fn pre_merkle_test_basic_proof_verification_cubic_extension() {
    let pre_merkle = Box::new(super::PreMerkleExample::new(build_options(3)));
    let proof = pre_merkle.prove();
    assert!(pre_merkle.verify(proof).is_ok());
}

#[test]
fn pre_merkle_test_basic_proof_verification_fail() {
    let pre_merkle = Box::new(super::PreMerkleExample::new(build_options(1)));
    let proof = pre_merkle.prove();
    let verified = pre_merkle.verify_with_wrong_inputs(proof);
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
