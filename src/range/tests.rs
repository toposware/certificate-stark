// Copyright (c) ToposWare and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use winterfell::{
    math::{fields::f63::BaseElement, FieldElement},
    FieldExtension, HashFunction, ProofOptions,
};

#[test]
fn range_proof_basic_proof_verification() {
    let range = Box::new(super::RangeProofExample::new(
        build_options(1),
        BaseElement::from(17u32),
    ));
    let proof = range.prove();
    assert!(range.verify(proof).is_ok());
}

#[test]
fn range_proof_test_basic_proof_verification_quadratic_extension() {
    let range = Box::new(super::RangeProofExample::new(
        build_options(2),
        BaseElement::from(42u32),
    ));
    let proof = range.prove();
    assert!(range.verify(proof).is_ok());
}

#[test]
fn range_proof_test_basic_proof_verification_cubic_extension() {
    let range = Box::new(super::RangeProofExample::new(
        build_options(3),
        BaseElement::from(42u32),
    ));
    let proof = range.prove();
    assert!(range.verify(proof).is_ok());
}

#[test]
fn range_proof_max_input() {
    let range = Box::new(super::RangeProofExample::new(
        build_options(1),
        BaseElement::from(1u128 << 63) - BaseElement::ONE,
    ));
    let proof = range.prove();
    assert!(range.verify(proof).is_ok());
}

#[test]
#[should_panic]
fn range_proof_input_too_large() {
    let range = Box::new(super::RangeProofExample::new(
        build_options(1),
        BaseElement::from_raw_unchecked(4719772409484279809), // M
    ));
    range.prove();
}

#[cfg(debug)]
#[test]
#[should_panic]
fn range_proof_input_negative() {
    let range = Box::new(super::RangeProofExample::new(
        build_options(1),
        -BaseElement::from(3u32),
    ));
    range.prove();
}

#[test]
fn range_test_basic_proof_verification_fail() {
    let range = Box::new(super::RangeProofExample::new(
        build_options(1),
        BaseElement::ONE,
    ));
    let proof = range.prove();
    let verified = range.verify_with_wrong_inputs(proof);
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
