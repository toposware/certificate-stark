// Copyright (c) ToposWare and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// CONSTANTS
// ================================================================================================

pub mod merkle_init_const {
    pub use crate::merkle::init::constants::*;
}

pub mod merkle_const {
    pub use crate::merkle::update::constants::*;
}

pub mod range_const {
    pub use crate::range::{RANGE_LOG, TRACE_WIDTH};
}

pub mod rescue_const {
    pub use crate::utils::rescue::{HASH_CYCLE_LENGTH, NUM_HASH_ROUNDS};
}

pub mod schnorr_const {
    pub use crate::schnorr::constants::*;
}

/// Total trace width for the state transition AIR program
// The extra registers are for copying the public keys, delta and the new sender balance
pub const TRACE_WIDTH: usize = NONCE_COPY_POS + 3;

/// The width of the trace used for Merkle registers
pub const MERKLE_REGISTER_WIDTH: usize = merkle_const::TRACE_WIDTH;
/// Beginning position of the copy of the sender's public key
pub const SENDER_KEY_POINT_POS: usize = MERKLE_REGISTER_WIDTH;
/// Beginning position of the copy of the receiver's public key
pub const RECEIVER_KEY_POINT_POS: usize = MERKLE_REGISTER_WIDTH + schnorr_const::AFFINE_POINT_WIDTH;
/// Position of the register copying delta
pub const DELTA_COPY_POS: usize = MERKLE_REGISTER_WIDTH + schnorr_const::AFFINE_POINT_WIDTH * 2;
/// Position of the register copying the sender's updated balance
pub const SIGMA_COPY_POS: usize = MERKLE_REGISTER_WIDTH + schnorr_const::AFFINE_POINT_WIDTH * 2 + 1;
/// Position of the register copying the sender's updated nonce
pub const NONCE_COPY_POS: usize = MERKLE_REGISTER_WIDTH + schnorr_const::AFFINE_POINT_WIDTH * 2 + 2;

//  Indices for the constraint results for various components
/// Beginning index of constraints for the copy of the sender's public key
pub const SENDER_KEY_POINT_RES: usize = merkle_const::PREV_TREE_MATCH_RES + 2;
/// Beginning index of constraints for the copy of the receiver's public key
pub const RECEIVER_KEY_POINT_RES: usize = SENDER_KEY_POINT_RES + 2;
/// Index of constraint for copying delta
pub const DELTA_COPY_RES: usize = RECEIVER_KEY_POINT_RES + 2;
/// Index of constraint for copying the sender's updated balance
pub const SIGMA_COPY_RES: usize = DELTA_COPY_RES + 1;
/// Index of constraint for copying the sender's updated nonce
pub const NONCE_COPY_RES: usize = SIGMA_COPY_RES + 1;
/// Index of constraint for enforcing equality fo accumulated delta
pub const DELTA_RANGE_RES: usize = NONCE_COPY_RES + 1;
/// Index of constraint for enforcing equality fo accumulated sigma
pub const SIGMA_RANGE_RES: usize = DELTA_RANGE_RES + 1;

/// The width of the trace used for Schnorr registers
pub const SCHNORR_REGISTER_WIDTH: usize = schnorr_const::TRACE_WIDTH;
/// Position of the bit decomposition of delta
pub const DELTA_BIT_POS: usize = SCHNORR_REGISTER_WIDTH;
/// Position of the accumulated value for delta
pub const DELTA_ACCUMULATE_POS: usize = SCHNORR_REGISTER_WIDTH + 1;
/// Position of the bit decomposition of sigma
pub const SIGMA_BIT_POS: usize = NONCE_COPY_POS + 1;
/// Position of the accumulated value for delta
pub const SIGMA_ACCUMULATE_POS: usize = NONCE_COPY_POS + 2;

/// Total length for verifying a transaction
// Dominated by the Merkle authentication paths and the Schnorr signature verification
pub const TRANSACTION_CYCLE_LENGTH: usize = merkle_const::TRANSACTION_CYCLE_LENGTH * 2;

// Indices for various periodic columns
/// The index for the transaction setup mask
pub const SETUP_MASK_INDEX: usize = 0;
/// The index for the transaction hash mask
pub const MERKLE_MASK_INDEX: usize = SETUP_MASK_INDEX + 1;
/// The index for the hash input mask
pub const HASH_INPUT_MASK_INDEX: usize = MERKLE_MASK_INDEX + 1;
/// The index for the transaction finish mask
pub const FINISH_MASK_INDEX: usize = HASH_INPUT_MASK_INDEX + 1;
/// The index for the general hash mask
pub const HASH_MASK_INDEX: usize = FINISH_MASK_INDEX + 1;
/// The index for the overall Schnorr mask
pub const SCHNORR_MASK_INDEX: usize = HASH_MASK_INDEX + 1;
/// The index for the scalar multiplication mask
pub const SCALAR_MULT_MASK_INDEX: usize = SCHNORR_MASK_INDEX + 1;
/// The index for the point doubling mask
pub const DOUBLING_MASK_INDEX: usize = SCALAR_MULT_MASK_INDEX + 1;
/// The index for the hash digest registers mask
pub const SCHNORR_DIGEST_MASK_INDEX: usize = DOUBLING_MASK_INDEX + 1;
/// The index for the Schnorr hash mask
pub const SCHNORR_HASH_MASK_INDEX: usize = SCHNORR_DIGEST_MASK_INDEX + 4;
/// The starting index for the flags for copying parts to the hash internal inputs
pub const HASH_INTERNAL_INPUT_MASKS_INDEX: usize = SCHNORR_HASH_MASK_INDEX + 1;
/// The index for the mask specifying range proof computations
pub const RANGE_PROOF_STEP_MASK_INDEX: usize =
    HASH_INTERNAL_INPUT_MASKS_INDEX + schnorr_const::NUM_HASH_ITER - 1;
/// The index for the mask checking final range proof equality
pub const RANGE_PROOF_FINISH_MASK_INDEX: usize = RANGE_PROOF_STEP_MASK_INDEX + 1;
/// The index for the mask checking carry-over of values from Merkle to Schnorr
pub const VALUE_COPY_MASK_INDEX: usize = RANGE_PROOF_FINISH_MASK_INDEX + 1;
/// The starting index for the Rescue round constants
pub const ARK_INDEX: usize = VALUE_COPY_MASK_INDEX + 1;
