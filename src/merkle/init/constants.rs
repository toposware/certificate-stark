// Copyright (c) ToposWare and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

pub use crate::merkle::constants::{
    AFFINE_POINT_WIDTH, HASH_CYCLE_LENGTH, HASH_STATE_WIDTH, MERKLE_TREE_DEPTH,
    RECEIVER_INITIAL_POS, RECEIVER_UPDATED_POS, SENDER_INITIAL_POS, SENDER_UPDATED_POS,
    TRANSACTION_HASH_LENGTH,
};

// CONSTANTS
// ================================================================================================

/// Total number of registers in the trace
pub const TRACE_WIDTH: usize = 4 * HASH_STATE_WIDTH + 2;
/// The number of steps require for a single transaction
pub const TRANSACTION_CYCLE_LENGTH: usize = if HASH_CYCLE_LENGTH >= 16 {
    HASH_CYCLE_LENGTH
} else {
    16
};
