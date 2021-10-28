// Copyright (c) ToposWare and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{are_equal, is_binary, not, EvaluationResult};
use winterfell::math::{curve::B, fields::f252::BaseElement, FieldElement};

// CONSTANTS
// ================================================================================================

const TWO: BaseElement = BaseElement::new([2, 0, 0, 0]);
const THREE: BaseElement = BaseElement::new([3, 0, 0, 0]);
const SIX: BaseElement = BaseElement::new([6, 0, 0, 0]);
const EIGHT: BaseElement = BaseElement::new([8, 0, 0, 0]);

/// Curve arithmetic operations are done in projective coordinates
pub const POINT_WIDTH: usize = 3;

/// Specifies the projective coordinates of the curve generator G.
pub const GENERATOR: [BaseElement; 3] = [
    BaseElement::from_raw_unchecked([
        0xc9019623cf0273dd,
        0x51a9bf65d4403dea,
        0x0429bf5184041c7b,
        0x033840300bf6cec1,
    ]),
    BaseElement::from_raw_unchecked([
        0x569d0da34235308a,
        0x0939e3442869bbe7,
        0xfbd89a97cf4b33ad,
        0x05a0e71610f55329,
    ]),
    BaseElement::ONE,
];

// TRACE
// ================================================================================================

/// Apply a point doubling.
pub fn apply_point_doubling(state: &mut [BaseElement]) {
    compute_double(state);
}

/// Apply a point addition between the current `state` registers with a given point.
pub fn apply_point_addition(state: &mut [BaseElement], point: &[BaseElement]) {
    if state[POINT_WIDTH] == BaseElement::ONE {
        compute_add(state, point)
    };
}

// CONSTRAINTS
// ================================================================================================

/// When flag = 1, enforces constraints for performing a point doubling.
pub fn enforce_point_doubling<E: FieldElement + From<BaseElement>>(
    result: &mut [E],
    current: &[E],
    next: &[E],
    flag: E,
) {
    let mut step1 = [E::ZERO; POINT_WIDTH];
    step1.copy_from_slice(&current[0..POINT_WIDTH]);

    let mut step2 = [E::ZERO; POINT_WIDTH];
    step2.copy_from_slice(&next[0..POINT_WIDTH]);

    compute_double(&mut step1);

    // Make sure that the results are equal
    for i in 0..POINT_WIDTH {
        result.agg_constraint(i, flag, are_equal(step2[i], step1[i]));
    }

    // Enforce that the last register for conditional addition is indeed binary
    result.agg_constraint(POINT_WIDTH, flag, is_binary(current[POINT_WIDTH]));
}

/// When flag = 1, enforces constraints for performing a point addition
/// between current and point.
pub fn enforce_point_addition<E: FieldElement + From<BaseElement>>(
    result: &mut [E],
    current: &[E],
    next: &[E],
    point: &[E],
    flag: E,
) {
    let mut step1 = [E::ZERO; POINT_WIDTH];
    step1.copy_from_slice(&current[0..POINT_WIDTH]);

    let mut step2 = [E::ZERO; POINT_WIDTH];
    step2.copy_from_slice(&next[0..POINT_WIDTH]);

    compute_add(&mut step1, point);
    let adding_bit = current[POINT_WIDTH];

    for i in 0..POINT_WIDTH {
        result.agg_constraint(
            i,
            flag,
            are_equal(
                step2[i],
                adding_bit * step1[i] + not(adding_bit) * current[i],
            ),
        );
    }

    // Ensure proper duplication of the binary decomposition
    result.agg_constraint(
        POINT_WIDTH,
        flag,
        are_equal(current[POINT_WIDTH], next[POINT_WIDTH]),
    );
}

/// When flag = 1, enforces constraints for performing a point addition
/// between current and point.
///
/// In the current implementation, this is being used only once, at the final step,
/// so we add a division of register 0 by register 2 to obtain the final affine
/// x coordinate (computations are being done internally in projective coordinates)
pub fn enforce_point_addition_reduce_x<E: FieldElement + From<BaseElement>>(
    result: &mut [E],
    current: &[E],
    next: &[E],
    point: &[E],
    flag: E,
) {
    let mut step1 = [E::ZERO; POINT_WIDTH];
    step1.copy_from_slice(&current[0..POINT_WIDTH]);

    let mut step2 = [E::ZERO; POINT_WIDTH];
    step2.copy_from_slice(&next[0..POINT_WIDTH]);

    compute_add(&mut step1, point);

    result.agg_constraint(0, flag, are_equal(step2[0] * step1[2], step1[0]));
    result.agg_constraint(1, flag, are_equal(step2[1], step1[1]));
    result.agg_constraint(2, flag, are_equal(step2[2], step1[2]));
}

// HELPER FUNCTIONS
// ================================================================================================

/// Compute the double of the current point, stored as [X,Y,Z].
/// Doubling is computed as:
///
/// `X2 = 2XY(Y^2 - 2XZ - 3BZ^2) - 2YZ(X^2 + 6BXZ - Z^2)`
///
/// `Y2 = (Y^2 + 2XZ + 3BZ^2) (Y^2 - 2XZ - 3BZ^2) + (3X^2 + Z^2) (X^2 + 6BXZ - Z^2)`
///
/// `Z2 = 8Y^3.Z`
#[inline(always)]
fn compute_double<E: FieldElement + From<BaseElement>>(state: &mut [E]) {
    let x_squared = state[0] * state[0];
    let xy = state[0] * state[1];
    let xz = state[0] * state[2];

    let y_squared = state[1] * state[1];
    let yz = state[1] * state[2];

    let z_squared = state[2] * state[2];

    let b3 = E::from(THREE * B);
    let two = E::from(TWO);
    let three = E::from(THREE);
    let b6 = E::from(SIX * B);
    let eight = E::from(EIGHT);

    let x = two * xy * (y_squared - two * xz - b3 * z_squared)
        - two * yz * (x_squared + b6 * xz - z_squared);

    let y = (y_squared + two * xz + b3 * z_squared) * (y_squared - two * xz - b3 * z_squared)
        + (three * x_squared + z_squared) * (x_squared + b6 * xz - z_squared);

    let z = eight * y_squared * yz;

    state[0] = x;
    state[1] = y;
    state[2] = z;
}

/// Compute the addition of the current point, stored as [X,Y,Z], with a given one.
/// Addition is computed as:
///
/// `X3 = (X1.Y2 + X2.Y1) (Y1.Y2 −(X1.Z2 + X2.Z1) − 3B.Z1.Z2)
///         − (Y1.Z2 + Y2.Z1) (X1.X2 + 3B(X1.Z2 + X2.Z1) − Z1.Z2)`
///
/// `Y3 = (3X1.X2 + Z1.Z2) (X1.X2 + 3B(X1.Z2 + X2.Z1) − Z1.Z2)
///         + (Y1.Y2 + (X1.Z2 + X2.Z1) + 3B.Z1.Z2) (Y1.Y2 −(X1.Z2 + X2.Z1) − 3B.Z1.Z2)`
///
/// `Z3 = (Y1.Z2 + Y2.Z1) (Y1.Y2 + (X1.Z2 + X2.Z1) + 3B.Z1.Z2)
///         + (X1.Y2 + X2.Y1) (3X1.X2 + Z1.Z2)`
#[inline(always)]
fn compute_add<E: FieldElement + From<BaseElement>>(state: &mut [E], point: &[E]) {
    let x1x2 = state[0] * point[0];
    let x1y2 = state[0] * point[1];
    let x1z2 = state[0] * point[2];

    let y1x2 = state[1] * point[0];
    let y1y2 = state[1] * point[1];
    let y1z2 = state[1] * point[2];

    let z1x2 = state[2] * point[0];
    let z1y2 = state[2] * point[1];
    let z1z2 = state[2] * point[2];

    let b3 = E::from(THREE * B);
    let three = E::from(THREE);

    let x = (x1y2 + y1x2) * (y1y2 - (x1z2 + z1x2) - b3 * z1z2)
        - (y1z2 + z1y2) * (x1x2 + b3 * (x1z2 + z1x2) - z1z2);

    let y = (three * x1x2 + z1z2) * (x1x2 + b3 * (x1z2 + z1x2) - z1z2)
        + (y1y2 + (x1z2 + z1x2) + b3 * z1z2) * (y1y2 - (x1z2 + z1x2) - b3 * z1z2);

    let z =
        (y1z2 + z1y2) * (y1y2 + (x1z2 + z1x2) + b3 * z1z2) + (x1y2 + y1x2) * (three * x1x2 + z1z2);

    state[0] = x;
    state[1] = y;
    state[2] = z;
}
