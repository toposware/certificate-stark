// Copyright (c) ToposWare and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

pub use crate::utils::ecc::AFFINE_POINT_WIDTH;
pub use crate::utils::rescue::{
    HASH_CYCLE_LENGTH, NUM_HASH_ROUNDS, RATE_WIDTH as HASH_RATE_WIDTH,
    STATE_WIDTH as HASH_STATE_WIDTH,
};

// CONSTANTS USED IN MERKLE INITIALIZATION AND AUTHENTICATION
// ================================================================================================

/// Total number of registers in the trace
pub const TRACE_WIDTH: usize = PREV_TREE_ROOT_POS + HASH_RATE_WIDTH;
/// The depth to a leaf in the Merkle tree to be used when testing
#[cfg(test)]
pub const MERKLE_TREE_DEPTH: usize = 3;
/// The depth to a leaf in the Merkle tree
#[cfg(not(test))]
pub const MERKLE_TREE_DEPTH: usize = 15;
/// The number of steps required for hashes in a transaction
pub const TRANSACTION_HASH_LENGTH: usize = HASH_CYCLE_LENGTH * MERKLE_TREE_DEPTH + NUM_HASH_ROUNDS;
/// The number of steps required for a single transaction
pub const TRANSACTION_CYCLE_LENGTH: usize = 512;

//  Indices of the beginning state registers for the main components
/// Beginning position of the hash states for the sender's initial value
pub const SENDER_INITIAL_POS: usize = 0;
/// Position of the state register for the sender index bit representation
pub const SENDER_BIT_POS: usize = HASH_STATE_WIDTH;
/// Beginning position of the hash states for the sender's updated value
pub const SENDER_UPDATED_POS: usize = HASH_STATE_WIDTH + 1;
/// Beginning position of the hash states for the receiver's initial value
pub const RECEIVER_INITIAL_POS: usize = 2 * HASH_STATE_WIDTH + 1;
/// Position of the state register for the receiver index bit representation
pub const RECEIVER_BIT_POS: usize = 3 * HASH_STATE_WIDTH + 1;
/// Beginning position of the hash states for the receiver's updated value
pub const RECEIVER_UPDATED_POS: usize = 3 * HASH_STATE_WIDTH + 2;
/// Beginning position of the previous tree root carrying state
pub const PREV_TREE_ROOT_POS: usize = 4 * HASH_STATE_WIDTH + 2;

//  Indices for the constraint results for various components
/// Beginning index of constraints for the sender's initial value
pub const SENDER_INITIAL_RES: usize = 0;
/// Beginning index of constraints for the receiver's initial value
pub const RECEIVER_INITIAL_RES: usize = 2 * HASH_STATE_WIDTH + 1;
/// Beginning index of constraints for previous tree root carry
pub const PREV_TREE_ROOT_RES: usize = 4 * HASH_STATE_WIDTH + 2;
/// Beginning index of constraints for unchanged values
pub const VALUE_CONSTRAINT_RES: usize = TRACE_WIDTH;
/// Index of constraint for balance update equality
pub const BALANCE_CONSTRAINT_RES: usize = TRACE_WIDTH + AFFINE_POINT_WIDTH * 2 + 1;
/// Index of constraint for updating the sender's nonce
pub const NONCE_UPDATE_CONSTRAINT_RES: usize = TRACE_WIDTH + AFFINE_POINT_WIDTH * 2 + 2;
/// Beginning index of intermediate tree root equality constraints
pub const INT_ROOT_EQUALITY_RES: usize = TRACE_WIDTH + AFFINE_POINT_WIDTH * 2 + 3;
/// Beginning index of constraints for previous tree root matching
pub const PREV_TREE_MATCH_RES: usize = TRACE_WIDTH + 34;
