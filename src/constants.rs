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
// The 6 extra registers are for copying the public keys, delta and the new sender balance
pub const TRACE_WIDTH: usize = merkle_const::TRACE_WIDTH + 7;

/// The width of the trace used for Merkle registers
pub const MERKLE_REGISTER_WIDTH: usize = merkle_const::TRACE_WIDTH;
/// Beginning position of the copy of the sender's public key
pub const SENDER_KEY_POINT_POS: usize = MERKLE_REGISTER_WIDTH;
/// Beginning position of the copy of the receiver's public key
pub const RECEIVER_KEY_POINT_POS: usize = MERKLE_REGISTER_WIDTH + 2;
/// Position of the register copying delta
pub const DELTA_COPY_POS: usize = MERKLE_REGISTER_WIDTH + 4;
/// Position of the register copying the sender's updated balance
pub const SIGMA_COPY_POS: usize = MERKLE_REGISTER_WIDTH + 5;
/// Position of the register copying the sender's updated nonce
pub const NONCE_COPY_POS: usize = MERKLE_REGISTER_WIDTH + 6;
/// Position of the register copying the x component of R
pub const RX_COPY_POS: usize = schnorr_const::TRACE_WIDTH + 4;

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
/// Beginning index of constraints for the first (S) point setup
pub const S_POINT_SETUP_RES: usize = SIGMA_RANGE_RES + 1;
/// Beginning index of constraints for the second (h.P) point setup
pub const HP_POINT_SETUP_RES: usize = S_POINT_SETUP_RES + 3;
/// Index of constraint for the setup of computation for h in the field
pub const H_FIELD_SETUP_RES: usize = HP_POINT_SETUP_RES + 3;
/// Beginning Index of constraints for setting up the schnorr hash input
pub const SIG_HASH_SETUP_RES: usize = H_FIELD_SETUP_RES + 1;
/// Index of constraint for setup of first (delta) range proof
pub const DELTA_SETUP_RES: usize = SIG_HASH_SETUP_RES + 3;
/// Index of constraint for setup of second (sigma) range proof
pub const SIGMA_SETUP_RES: usize = DELTA_SETUP_RES + 1;
/// Index of constraint for enforcing copying of the x component of R
pub const RX_COPY_RES: usize = schnorr_const::TRACE_WIDTH + 4;

/// The width of the trace used for Schnorr registers
pub const SCHNORR_REGISTER_WIDTH: usize = schnorr_const::TRACE_WIDTH;
/// Poaition of the beginning of the hash state for Schnorr signature
pub const SCHNORR_HASH_POS: usize = 2 * schnorr_const::POINT_WIDTH + 3;
/// Position of the bit decomposition of delta
pub const DELTA_BIT_POS: usize = SCHNORR_REGISTER_WIDTH - 2;
/// Position of the accumulated value for delta
pub const DELTA_ACCUMULATE_POS: usize = SCHNORR_REGISTER_WIDTH - 1;
/// Position of the bit decomposition of sigma
pub const SIGMA_BIT_POS: usize = SCHNORR_REGISTER_WIDTH - 2;
/// Position of the accumulated value for sigma
pub const SIGMA_ACCUMULATE_POS: usize = SCHNORR_REGISTER_WIDTH - 1;

/// Total length for verifying a transaction
// Dominated by the Merkle authentication paths and the Schnorr signature verification
pub const TRANSACTION_CYCLE_LENGTH: usize = merkle_const::TRANSACTION_CYCLE_LENGTH * 2;

// Indices for various periodic columns
/// The index for the transaction setup mask
pub const SETUP_MASK_INDEX: usize = 0;
/// The index for the transaction hash mask
pub const MERKLE_MASK_INDEX: usize = 1;
/// The index for the hash input mask
pub const HASH_INPUT_MASK_INDEX: usize = 2;
/// The index for the transaction finish mask
pub const FINISH_MASK_INDEX: usize = 3;
/// The index for the general hash mask
pub const HASH_MASK_INDEX: usize = 4;
/// The index for the overall Schnorr mask
pub const SCHNORR_MASK_INDEX: usize = 5;
/// The index for the scalar multiplication mask
pub const SCALAR_MULT_MASK_INDEX: usize = 6;
/// The index for the point doubling mask
pub const DOUBLING_MASK_INDEX: usize = 7;
/// The index for the overall Schnorr hash mask
pub const SCHNORR_HASH_MASK_INDEX: usize = 8;
/// The index for the Schnorr hash round mask
pub const SCHNORR_HASH_ROUND_MASK_INDEX: usize = 9;
/// The starting index for the flags for copying parts to the hash internal inputs
pub const HASH_INTERNAL_INPUT_MASKS_INDEX: usize = 10;
/// The index for the mask specifying range proof initilization
pub const RANGE_PROOF_SETUP_MASK_INDEX: usize = 13;
/// The index for the mask specifying range proof computations
pub const RANGE_PROOF_STEP_MASK_INDEX: usize = 14;
/// The index for the mask checking final range proof equality
pub const DELTA_RANGE_FINISH_MASK_INDEX: usize = 15;
/// The index for the mask checking final range proof equality
pub const SIGMA_RANGE_FINISH_MASK_INDEX: usize = 16;
/// The index for the mask checking carry-over of values from Merkle to Schnorr
pub const VALUE_COPY_MASK_INDEX: usize = 17;
/// The index for the mask enforcing proper setup of the Schnorr component
pub const SCHNORR_SETUP_MASK_INDEX: usize = 18;
/// The starting index for the Rescue round constants
pub const ARK_INDEX: usize = 19;
