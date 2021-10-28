// Copyright (c) ToposWare and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use winterfell::math::FieldElement;

pub mod ecc;
pub mod field;
pub mod periodic_columns;
pub mod rescue;

// CONSTRAINT EVALUATION HELPERS
// ================================================================================================

/// Returns zero only when a == b.
pub fn are_equal<E: FieldElement>(a: E, b: E) -> E {
    a - b
}

/// Returns zero only when a == zero.
pub fn is_zero<E: FieldElement>(a: E) -> E {
    a
}

/// Returns zero only when a = zero || a == one.
pub fn is_binary<E: FieldElement>(a: E) -> E {
    a * a - a
}

/// Return zero when a == one, and one when a == zero;
/// assumes that a is a binary value.
pub fn not<E: FieldElement>(a: E) -> E {
    E::ONE - a
}

// TRAIT TO SIMPLIFY CONSTRAINT AGGREGATION
// ================================================================================================

pub trait EvaluationResult<E> {
    fn agg_constraint(&mut self, index: usize, flag: E, value: E);
}

impl<E: FieldElement> EvaluationResult<E> for [E] {
    fn agg_constraint(&mut self, index: usize, flag: E, value: E) {
        self[index] += flag * value;
    }
}

impl<E: FieldElement> EvaluationResult<E> for Vec<E> {
    fn agg_constraint(&mut self, index: usize, flag: E, value: E) {
        self[index] += flag * value;
    }
}
