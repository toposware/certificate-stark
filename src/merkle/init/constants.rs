// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

pub(crate) use crate::merkle::constants::{
    AFFINE_POINT_WIDTH, HASH_CYCLE_LENGTH, HASH_STATE_WIDTH, RECEIVER_INITIAL_POS,
    RECEIVER_UPDATED_POS, SENDER_INITIAL_POS, SENDER_UPDATED_POS,
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
