// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// CONSTANTS
// ================================================================================================

pub(crate) mod merkle_init_const {
    #[allow(unused)]
    pub(crate) use crate::merkle::init::constants::*;
}

pub(crate) mod merkle_const {
    pub(crate) use crate::merkle::update::constants::*;
}

pub(crate) mod range_const {
    pub(crate) use crate::range::RANGE_LOG;
}

pub(crate) mod rescue_const {
    pub(crate) use crate::utils::rescue::HASH_CYCLE_LENGTH;
}

pub(crate) mod schnorr_const {
    pub(crate) use crate::schnorr::constants::*;
}

/// Total trace width for the state transition AIR program
// The extra registers are for copying the public keys, delta and the new sender balance
pub(crate) const TRACE_WIDTH: usize = NONCE_COPY_POS + 3;

/// The width of the trace used for Merkle registers
pub(crate) const MERKLE_REGISTER_WIDTH: usize = merkle_const::TRACE_WIDTH;
/// Beginning position of the copy of the sender's public key
pub(crate) const SENDER_KEY_POINT_POS: usize = MERKLE_REGISTER_WIDTH;
/// Beginning position of the copy of the receiver's public key
pub(crate) const RECEIVER_KEY_POINT_POS: usize =
    MERKLE_REGISTER_WIDTH + schnorr_const::AFFINE_POINT_WIDTH;
/// Position of the register copying delta
pub(crate) const DELTA_COPY_POS: usize =
    MERKLE_REGISTER_WIDTH + schnorr_const::AFFINE_POINT_WIDTH * 2;
/// Position of the register copying the sender's updated balance
pub(crate) const SIGMA_COPY_POS: usize =
    MERKLE_REGISTER_WIDTH + schnorr_const::AFFINE_POINT_WIDTH * 2 + 1;
/// Position of the register copying the sender's updated nonce
pub(crate) const NONCE_COPY_POS: usize =
    MERKLE_REGISTER_WIDTH + schnorr_const::AFFINE_POINT_WIDTH * 2 + 2;

//  Indices for the constraint results for various components
/// Beginning index of constraints for the copy of the sender's public key
pub(crate) const SENDER_KEY_POINT_RES: usize = merkle_const::PREV_TREE_MATCH_RES + 2;
/// Beginning index of constraints for the copy of the receiver's public key
pub(crate) const RECEIVER_KEY_POINT_RES: usize = SENDER_KEY_POINT_RES + 2;
/// Index of constraint for copying delta
pub(crate) const DELTA_COPY_RES: usize = RECEIVER_KEY_POINT_RES + 2;
/// Index of constraint for copying the sender's updated balance
pub(crate) const SIGMA_COPY_RES: usize = DELTA_COPY_RES + 1;
/// Index of constraint for copying the sender's updated nonce
pub(crate) const NONCE_COPY_RES: usize = SIGMA_COPY_RES + 1;
/// Index of constraint for enforcing equality fo accumulated delta
pub(crate) const DELTA_RANGE_RES: usize = NONCE_COPY_RES + 1;
/// Index of constraint for enforcing equality fo accumulated sigma
pub(crate) const SIGMA_RANGE_RES: usize = DELTA_RANGE_RES + 1;

/// The width of the trace used for Schnorr registers
pub(crate) const SCHNORR_REGISTER_WIDTH: usize = schnorr_const::TRACE_WIDTH;
/// Position of the bit decomposition of delta
pub(crate) const DELTA_BIT_POS: usize = SCHNORR_REGISTER_WIDTH;
/// Position of the accumulated value for delta
pub(crate) const DELTA_ACCUMULATE_POS: usize = SCHNORR_REGISTER_WIDTH + 1;
/// Position of the bit decomposition of sigma
pub(crate) const SIGMA_BIT_POS: usize = NONCE_COPY_POS + 1;
/// Position of the accumulated value for delta
pub(crate) const SIGMA_ACCUMULATE_POS: usize = NONCE_COPY_POS + 2;

/// Total length for verifying a transaction
// Dominated by the Merkle authentication paths and the Schnorr signature verification
pub(crate) const TRANSACTION_CYCLE_LENGTH: usize = merkle_const::TRANSACTION_CYCLE_LENGTH * 2;

// Indices for various periodic columns
/// The index for the transaction setup mask
pub(crate) const SETUP_MASK_INDEX: usize = 0;
/// The index for the transaction hash mask
pub(crate) const MERKLE_MASK_INDEX: usize = SETUP_MASK_INDEX + 1;
/// The index for the hash input mask
pub(crate) const HASH_INPUT_MASK_INDEX: usize = MERKLE_MASK_INDEX + 1;
/// The index for the transaction finish mask
pub(crate) const FINISH_MASK_INDEX: usize = HASH_INPUT_MASK_INDEX + 1;
/// The index for the general hash mask
pub(crate) const HASH_MASK_INDEX: usize = FINISH_MASK_INDEX + 1;
/// The index for the overall Schnorr mask
pub(crate) const SCHNORR_MASK_INDEX: usize = HASH_MASK_INDEX + 1;
/// The index for the scalar multiplication mask
pub(crate) const SCALAR_MULT_MASK_INDEX: usize = SCHNORR_MASK_INDEX + 1;
/// The index for the point doubling mask
pub(crate) const DOUBLING_MASK_INDEX: usize = SCALAR_MULT_MASK_INDEX + 1;
/// The index for the hash digest registers mask
pub(crate) const SCHNORR_DIGEST_MASK_INDEX: usize = DOUBLING_MASK_INDEX + 1;
/// The index for the Schnorr hash mask
pub(crate) const SCHNORR_HASH_MASK_INDEX: usize = SCHNORR_DIGEST_MASK_INDEX + 4;
/// The starting index for the flags for copying parts to the hash internal inputs
pub(crate) const HASH_INTERNAL_INPUT_MASKS_INDEX: usize = SCHNORR_HASH_MASK_INDEX + 1;
/// The index for the mask specifying range proof computations
pub(crate) const RANGE_PROOF_STEP_MASK_INDEX: usize =
    HASH_INTERNAL_INPUT_MASKS_INDEX + schnorr_const::NUM_HASH_ITER - 1;
/// The index for the mask checking final range proof equality
pub(crate) const RANGE_PROOF_FINISH_MASK_INDEX: usize = RANGE_PROOF_STEP_MASK_INDEX + 1;
/// The index for the mask checking carry-over of values from Merkle to Schnorr
pub(crate) const VALUE_COPY_MASK_INDEX: usize = RANGE_PROOF_FINISH_MASK_INDEX + 1;
/// The starting index for the Rescue round constants
pub(crate) const ARK_INDEX: usize = VALUE_COPY_MASK_INDEX + 1;
