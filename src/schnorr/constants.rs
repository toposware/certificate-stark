// Copyright (c) ToposWare and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

pub use super::ecc::{
    AFFINE_POINT_WIDTH, GENERATOR, POINT_COORDINATE_WIDTH, PROJECTIVE_POINT_WIDTH,
};
pub use super::rescue::{HASH_CYCLE_LENGTH, HASH_CYCLE_MASK, NUM_HASH_ROUNDS, STATE_WIDTH};

// CONSTANTS
// ================================================================================================

// Rescue constants

/// Number of hash iterations for hashing the message
pub const NUM_HASH_ITER: usize = 5;
/// Total number of steps for the iterated hash of the message to be signed
pub const TOTAL_HASH_LENGTH: usize = HASH_CYCLE_LENGTH * NUM_HASH_ITER;

// Scalar multiplication constants

/// Number of steps during the scalar multiplication
pub const SCALAR_MUL_LENGTH: usize = 508; // two times 254, as double/add steps are decoupled

// Periodic trace length

/// Total number of registers in the trace
// 2 points in projective coordinates, 2 binary decompositions, 1 field element, 1 hash state
pub const TRACE_WIDTH: usize = 2 * PROJECTIVE_POINT_WIDTH + 2 + 1 + STATE_WIDTH;
/// Total number of steps in the trace for a single signature
pub const SIG_CYCLE_LENGTH: usize = 512;
