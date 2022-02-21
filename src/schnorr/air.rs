// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::super::utils::periodic_columns::stitch;
use super::constants::*;
use super::rescue::{RATE_WIDTH as HASH_RATE_WIDTH, STATE_WIDTH as HASH_STATE_WIDTH};
use super::{ecc, field, rescue};
use crate::utils::{are_equal, is_zero, not, EvaluationResult};
use winterfell::{
    math::{curves::curve_f63::Scalar, fields::f63::BaseElement, FieldElement},
    Air, AirContext, Assertion, ByteWriter, EvaluationFrame, ProofOptions, Serializable, TraceInfo,
    TransitionConstraintDegree,
};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

// SCHNORR AIR
// ================================================================================================

pub struct PublicInputs {
    pub messages: Vec<[BaseElement; AFFINE_POINT_WIDTH * 2 + 4]>,
    pub signatures: Vec<([BaseElement; POINT_COORDINATE_WIDTH], Scalar)>,
}

impl Serializable for PublicInputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        for i in 0..self.messages.len() {
            Serializable::write_batch_into(&self.messages[i], target);
            Serializable::write_batch_into(&self.signatures[i].0, target);
            target.write(self.signatures[i].1);
        }
    }
}

pub struct SchnorrAir {
    context: AirContext<BaseElement>,
    messages: Vec<[BaseElement; AFFINE_POINT_WIDTH * 2 + 4]>,
    signatures: Vec<([BaseElement; POINT_COORDINATE_WIDTH], Scalar)>,
}

impl Air for SchnorrAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        let degrees = transition_constraint_degrees(pub_inputs.signatures.len(), SIG_CYCLE_LENGTH);
        assert_eq!(TRACE_WIDTH, trace_info.width());
        SchnorrAir {
            context: AirContext::new(trace_info, degrees, options),
            messages: pub_inputs.messages,
            signatures: pub_inputs.signatures,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        // Expected state width is TRACE_WIDTH field elements
        debug_assert_eq!(TRACE_WIDTH, current.len());
        debug_assert_eq!(TRACE_WIDTH, next.len());

        // Split periodic values
        let global_mask = periodic_values[0];
        let scalar_mult_flag = periodic_values[1];
        let doubling_flag = periodic_values[2];
        let hash_digest_register_flag = &periodic_values[3..7];
        let pkey_point = &periodic_values[7..AFFINE_POINT_WIDTH + 7];
        let hash_flag = periodic_values[AFFINE_POINT_WIDTH + 7];
        let hash_internal_inputs =
            &periodic_values[AFFINE_POINT_WIDTH + 8..AFFINE_POINT_WIDTH + 15];
        let ark = &periodic_values[AFFINE_POINT_WIDTH + 15..];

        let copy_hash_flag = not(hash_flag) * global_mask;
        let final_point_addition_flag = not(scalar_mult_flag) * global_mask;
        let addition_flag = not(doubling_flag) * scalar_mult_flag;

        evaluate_constraints(
            result,
            current,
            next,
            ark,
            doubling_flag,
            addition_flag,
            hash_digest_register_flag,
            pkey_point,
            final_point_addition_flag,
            hash_flag,
            copy_hash_flag,
            hash_internal_inputs,
        );
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let signatures = transpose_signatures(&self.signatures);
        // Assert starting and ending values
        let mut assertions = vec![];
        // First projective points
        for i in 0..PROJECTIVE_POINT_WIDTH {
            if i == POINT_COORDINATE_WIDTH {
                assertions.push(Assertion::periodic(
                    i,
                    0,
                    SIG_CYCLE_LENGTH,
                    BaseElement::ONE,
                ));
            } else {
                assertions.push(Assertion::periodic(
                    i,
                    0,
                    SIG_CYCLE_LENGTH,
                    BaseElement::ZERO,
                ));
            }
        }
        assertions.push(Assertion::periodic(
            PROJECTIVE_POINT_WIDTH,
            0,
            SIG_CYCLE_LENGTH,
            BaseElement::ZERO,
        ));
        // Second projective points
        for i in 0..PROJECTIVE_POINT_WIDTH {
            if i == POINT_COORDINATE_WIDTH {
                assertions.push(Assertion::periodic(
                    i + PROJECTIVE_POINT_WIDTH + 1,
                    0,
                    SIG_CYCLE_LENGTH,
                    BaseElement::ONE,
                ));
            } else {
                assertions.push(Assertion::periodic(
                    i + PROJECTIVE_POINT_WIDTH + 1,
                    0,
                    SIG_CYCLE_LENGTH,
                    BaseElement::ZERO,
                ));
            }
        }
        for i in 0..5 {
            assertions.push(Assertion::periodic(
                i + 2 * PROJECTIVE_POINT_WIDTH + 1,
                0,
                SIG_CYCLE_LENGTH,
                BaseElement::ZERO,
            ));
        }

        // TODO: find a way to do this better with indexing
        assertions.append(&mut vec![
            Assertion::sequence(
                2 * PROJECTIVE_POINT_WIDTH + 6,
                0,
                SIG_CYCLE_LENGTH,
                signatures.0.clone(),
            ),
            Assertion::sequence(
                2 * PROJECTIVE_POINT_WIDTH + 7,
                0,
                SIG_CYCLE_LENGTH,
                signatures.1.clone(),
            ),
            Assertion::sequence(
                2 * PROJECTIVE_POINT_WIDTH + 8,
                0,
                SIG_CYCLE_LENGTH,
                signatures.2.clone(),
            ),
            Assertion::sequence(
                2 * PROJECTIVE_POINT_WIDTH + 9,
                0,
                SIG_CYCLE_LENGTH,
                signatures.3.clone(),
            ),
            Assertion::sequence(
                2 * PROJECTIVE_POINT_WIDTH + 10,
                0,
                SIG_CYCLE_LENGTH,
                signatures.4.clone(),
            ),
            Assertion::sequence(
                2 * PROJECTIVE_POINT_WIDTH + 11,
                0,
                SIG_CYCLE_LENGTH,
                signatures.5.clone(),
            ),
        ]);
        for i in 0..HASH_RATE_WIDTH {
            assertions.push(Assertion::periodic(
                i + 2 * PROJECTIVE_POINT_WIDTH + POINT_COORDINATE_WIDTH + 6,
                0,
                SIG_CYCLE_LENGTH,
                BaseElement::ZERO,
            ));
        }
        // Ending values
        // We can compute R = S + h.P in the registers of S directly,
        // hence checking the x_coord of R in the first registers (i.e. x(S))
        // TODO: find a way to do this better with indexing
        assertions.append(&mut vec![
            Assertion::sequence(0, SCALAR_MUL_LENGTH + 1, SIG_CYCLE_LENGTH, signatures.0),
            Assertion::sequence(1, SCALAR_MUL_LENGTH + 1, SIG_CYCLE_LENGTH, signatures.1),
            Assertion::sequence(2, SCALAR_MUL_LENGTH + 1, SIG_CYCLE_LENGTH, signatures.2),
            Assertion::sequence(3, SCALAR_MUL_LENGTH + 1, SIG_CYCLE_LENGTH, signatures.3),
            Assertion::sequence(4, SCALAR_MUL_LENGTH + 1, SIG_CYCLE_LENGTH, signatures.4),
            Assertion::sequence(5, SCALAR_MUL_LENGTH + 1, SIG_CYCLE_LENGTH, signatures.5),
        ]);

        assertions
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        // Start with empty periodic columns
        let mut columns = vec![Vec::new(); POINT_COORDINATE_WIDTH + PROJECTIVE_POINT_WIDTH + 3];
        // Stitch in the periodic columns applicable to all uses of Schnorr
        stitch(
            &mut columns,
            periodic_columns(),
            vec![
                (0, 0),
                (1, 1),
                (2, 2),
                (3, 3),
                (4, 4),
                (5, 5),
                (6, 6),
                (7, 7 + AFFINE_POINT_WIDTH),
            ],
        );
        // Values to feed to the last registers of the hash state at the end of a cycle.
        // Always zero (i.e. resetting the rate) or equal to the chunks of the message.
        let mut hash_intermediate_inputs =
            vec![
                vec![BaseElement::ZERO; SIG_CYCLE_LENGTH * self.signatures.len()];
                HASH_RATE_WIDTH
            ];

        // Public key coordinates extracted from the signed messages and to be used during scalar multiplications
        let mut pub_keys = vec![
            vec![BaseElement::ZERO; SIG_CYCLE_LENGTH * self.signatures.len()];
            AFFINE_POINT_WIDTH
        ];

        for message_index in 0..self.signatures.len() {
            for i in 0..SIG_CYCLE_LENGTH {
                for (j, input) in hash_intermediate_inputs
                    .iter_mut()
                    .enumerate()
                    .take(HASH_RATE_WIDTH)
                {
                    if i < NUM_HASH_ITER - 1 {
                        input[i * HASH_CYCLE_LENGTH
                            + NUM_HASH_ROUNDS
                            + message_index * SIG_CYCLE_LENGTH] =
                            self.messages[message_index][j + i * HASH_RATE_WIDTH];
                    }
                }
                for (j, key) in pub_keys.iter_mut().enumerate().take(AFFINE_POINT_WIDTH) {
                    key[i + message_index * SIG_CYCLE_LENGTH] = self.messages[message_index][j];
                }
            }
        }

        // Stitch in the above columns in the appropriate places
        stitch(
            &mut columns,
            pub_keys,
            (7..7 + AFFINE_POINT_WIDTH).enumerate().collect(),
        );
        stitch(
            &mut columns,
            hash_intermediate_inputs,
            (8 + AFFINE_POINT_WIDTH..8 + AFFINE_POINT_WIDTH + HASH_RATE_WIDTH)
                .enumerate()
                .collect(),
        );

        // Append the rescue round constants
        columns.append(&mut rescue::get_round_constants());

        columns
    }
}

// HELPER EVALUATORS
// ------------------------------------------------------------------------------------------------

/// when flag = 1, enforces that the next state of the computation is defined like so:
/// - the first HASH_RATE_WIDTH registers are equal to the values from the previous step
/// - the other HASH_RATE_WIDTH registers are equal to 0,
///   and add the values of internal_inputs for hash merging if any (only at last round)
fn enforce_hash_copy<E: FieldElement>(
    result: &mut [E],
    current: &[E],
    next: &[E],
    flag: E,
    internal_inputs: &[E],
) {
    for i in 0..HASH_RATE_WIDTH {
        result.agg_constraint(i, flag, are_equal(current[i], next[i]));
    }

    // internal_inputs are either zero (no difference with original hash chain) when resetting the
    // last registers or equal to the message elements, to be fed to the hash in an iterated way.
    // See build_trace() for more info
    for i in 0..HASH_RATE_WIDTH {
        result.agg_constraint(
            HASH_RATE_WIDTH + i,
            flag,
            is_zero(next[HASH_RATE_WIDTH + i] - internal_inputs[i]),
        );
    }
}

// HELPER FUNCTIONS
// ------------------------------------------------------------------------------------------------

pub(crate) fn periodic_columns() -> Vec<Vec<BaseElement>> {
    // We are computing the values for one whole Schnorr trace, i.e.
    // having only 1 global period of length SIG_CYCLE_LENGTH.

    // Flag for performing hash operations
    let mut hash_flag = HASH_CYCLE_MASK.to_vec();
    for _ in 1..NUM_HASH_ITER {
        hash_flag.append(&mut HASH_CYCLE_MASK.to_vec())
    }
    hash_flag.append(&mut vec![
        BaseElement::ZERO;
        SIG_CYCLE_LENGTH - hash_flag.len()
    ]);

    // Flag for performing double-and-add steps in the group and in the field
    let mut scalar_mult_flag = vec![BaseElement::ONE; SCALAR_MUL_LENGTH];
    scalar_mult_flag.append(&mut vec![
        BaseElement::ZERO;
        SIG_CYCLE_LENGTH - scalar_mult_flag.len()
    ]);

    // Flag for performing doubling step in the group
    // When ZERO, compute a conditional addition step instead
    let mut point_doubling_flag = Vec::with_capacity(SCALAR_MUL_LENGTH / 2);
    for _ in 0..SCALAR_MUL_LENGTH / 2 {
        point_doubling_flag.append(&mut vec![BaseElement::ONE, BaseElement::ZERO]);
    }
    point_doubling_flag.append(&mut vec![
        BaseElement::ZERO;
        SIG_CYCLE_LENGTH - point_doubling_flag.len()
    ]);

    // Flag for selecting the limb of the hash digest
    let mut hash_digest_register_flag = vec![vec![BaseElement::ZERO; SIG_CYCLE_LENGTH]; 4];
    hash_digest_register_flag[0][0..126].copy_from_slice(&[BaseElement::ONE; 126]);
    hash_digest_register_flag[1][126..254].copy_from_slice(&[BaseElement::ONE; 128]);
    hash_digest_register_flag[2][254..382].copy_from_slice(&[BaseElement::ONE; 128]);
    hash_digest_register_flag[3][382..510].copy_from_slice(&[BaseElement::ONE; 128]);

    let mut global_mask = vec![BaseElement::ONE; SCALAR_MUL_LENGTH + 1];
    global_mask.append(&mut vec![
        BaseElement::ZERO;
        SIG_CYCLE_LENGTH - global_mask.len()
    ]);

    // ARK constant values for the Rescue hash rounds
    let mut rescue_constants = rescue::get_round_constants();

    let mut result = vec![global_mask];
    result.append(&mut vec![scalar_mult_flag]);
    result.append(&mut vec![point_doubling_flag]);
    result.append(&mut hash_digest_register_flag);
    result.append(&mut vec![hash_flag]);
    result.append(&mut rescue_constants);

    result
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn evaluate_constraints<E: FieldElement + From<BaseElement>>(
    result: &mut [E],
    current: &[E],
    next: &[E],
    ark: &[E],
    doubling_flag: E,
    addition_flag: E,
    hash_digest_register_flag: &[E],
    pkey_point: &[E],
    final_point_addition_flag: E,
    hash_flag: E,
    copy_hash_flag: E,
    hash_internal_inputs: &[E],
) {
    // Point to be used in the double-and-add operations of registers [0..PROJECTIVE_POINT_WIDTH] (s.G)
    let generator_point: Vec<E> = GENERATOR.iter().map(|&coord| coord.into()).collect();

    // Point to be used in the double-and-add operations of registers [PROJECTIVE_POINT_WIDTH + 1..PROJECTIVE_POINT_WIDTH * 2 + 1] (h.P)
    let pkey_point: Vec<E> = pkey_point.to_vec();

    // When scalar_mult_flag = 1, constraints for a double-and-add
    // step are enforced on the dedicated registers for S and h.P,
    // as well as a double-and-add in the field for bin(h).

    // Enforce a step of double-and-add in the group for s.G
    ecc::enforce_point_doubling(
        &mut result[..PROJECTIVE_POINT_WIDTH + 1],
        &current[..PROJECTIVE_POINT_WIDTH + 1],
        &next[..PROJECTIVE_POINT_WIDTH + 1],
        doubling_flag,
    );

    ecc::enforce_point_addition_mixed(
        &mut result[..PROJECTIVE_POINT_WIDTH + 1],
        &current[..PROJECTIVE_POINT_WIDTH + 1],
        &next[..PROJECTIVE_POINT_WIDTH + 1],
        &generator_point,
        addition_flag,
    );

    // Enforce a step of double-and-add in the group for h.P
    ecc::enforce_point_doubling(
        &mut result[PROJECTIVE_POINT_WIDTH + 1..2 * PROJECTIVE_POINT_WIDTH + 2],
        &current[PROJECTIVE_POINT_WIDTH + 1..2 * PROJECTIVE_POINT_WIDTH + 2],
        &next[PROJECTIVE_POINT_WIDTH + 1..2 * PROJECTIVE_POINT_WIDTH + 2],
        doubling_flag,
    );

    ecc::enforce_point_addition_mixed(
        &mut result[PROJECTIVE_POINT_WIDTH + 1..2 * PROJECTIVE_POINT_WIDTH + 2],
        &current[PROJECTIVE_POINT_WIDTH + 1..2 * PROJECTIVE_POINT_WIDTH + 2],
        &next[PROJECTIVE_POINT_WIDTH + 1..2 * PROJECTIVE_POINT_WIDTH + 2],
        &pkey_point,
        addition_flag,
    );

    // Enforce a step of double-and-add in the field for the hash digest limbs
    for (i, &flag) in hash_digest_register_flag.iter().enumerate().take(4) {
        field::enforce_double_and_add_step_constrained(
            &mut result[2 * PROJECTIVE_POINT_WIDTH + 1..2 * PROJECTIVE_POINT_WIDTH + 6],
            &current[2 * PROJECTIVE_POINT_WIDTH + 1..2 * PROJECTIVE_POINT_WIDTH + 6],
            &next[2 * PROJECTIVE_POINT_WIDTH + 1..2 * PROJECTIVE_POINT_WIDTH + 6],
            4 - i,
            0,
            flag * doubling_flag, // Do not repeat it twice
        );
    }

    // Enforce temporary accumulators copy between double-and-add steps
    for i in 0..4 {
        result.agg_constraint(
            2 * PROJECTIVE_POINT_WIDTH + 2 + i,
            addition_flag,
            are_equal(
                current[2 * PROJECTIVE_POINT_WIDTH + 2 + i],
                next[2 * PROJECTIVE_POINT_WIDTH + 2 + i],
            ),
        );
    }

    // Enforce also copy for hash digest words cells outside of double-and-add steps
    for (i, &flag) in hash_digest_register_flag.iter().enumerate().take(4) {
        result.agg_constraint(
            2 * PROJECTIVE_POINT_WIDTH + 5 - i,
            not(flag) * doubling_flag,
            are_equal(
                current[2 * PROJECTIVE_POINT_WIDTH + 5 - i],
                next[2 * PROJECTIVE_POINT_WIDTH + 5 - i],
            ),
        );
    }

    // When hash_flag = 1, constraints for a Rescue round
    // are enforced on the dedicated registers
    rescue::enforce_round(
        &mut result[2 * PROJECTIVE_POINT_WIDTH + 6..],
        &current[2 * PROJECTIVE_POINT_WIDTH + 6..],
        &next[2 * PROJECTIVE_POINT_WIDTH + 6..],
        ark,
        hash_flag,
    );

    // When hash_flag = 0, constraints for copying hash values to the next step
    // and updating the rate registers with self.message[i] elements are enforced.

    enforce_hash_copy(
        &mut result[2 * PROJECTIVE_POINT_WIDTH + 6..],
        &current[2 * PROJECTIVE_POINT_WIDTH + 6..],
        &next[2 * PROJECTIVE_POINT_WIDTH + 6..],
        copy_hash_flag,
        hash_internal_inputs,
    );

    // When scalar_mult_flag = 0, compute the addition
    // R = S + h.P and enforce h = hash output

    // Add h.P to S, with the result stored directly in the coordinates of S
    ecc::enforce_point_addition_reduce_x(
        &mut result[..PROJECTIVE_POINT_WIDTH],
        &current[..PROJECTIVE_POINT_WIDTH], // S
        &next[..PROJECTIVE_POINT_WIDTH],
        &current[PROJECTIVE_POINT_WIDTH + 1..2 * PROJECTIVE_POINT_WIDTH + 1], // h.P
        final_point_addition_flag,
    );

    // Ensure that the accumulated value from the binary decomposition of h
    // matches the output of Rescue iterated hashes
    for i in 0..4 {
        result.agg_constraint(
            2 * PROJECTIVE_POINT_WIDTH + 2 + i,
            final_point_addition_flag,
            are_equal(
                current[2 * PROJECTIVE_POINT_WIDTH + 2 + i],
                current[2 * PROJECTIVE_POINT_WIDTH + 6 + i],
            ),
        );
    }
}

pub(crate) fn transition_constraint_degrees(
    num_tx: usize,
    cycle_length: usize,
) -> Vec<TransitionConstraintDegree> {
    let bit_degree = if num_tx == 1 { 3 } else { 5 };

    // First scalar multiplication
    let mut degrees =
        vec![
            TransitionConstraintDegree::with_cycles(5, vec![cycle_length, cycle_length]);
            POINT_COORDINATE_WIDTH
        ];

    // The x coordinate also stores the final point reduction, hence the first degrees are higher
    for _ in 0..AFFINE_POINT_WIDTH {
        degrees.push(TransitionConstraintDegree::with_cycles(
            4,
            vec![cycle_length, cycle_length],
        ));
    }
    degrees.push(TransitionConstraintDegree::with_cycles(
        2,
        vec![cycle_length],
    ));

    // Second scalar multiplication
    for _ in 0..PROJECTIVE_POINT_WIDTH {
        degrees.push(TransitionConstraintDegree::with_cycles(
            bit_degree,
            vec![cycle_length, cycle_length],
        ));
    }
    degrees.push(TransitionConstraintDegree::with_cycles(
        2,
        vec![cycle_length],
    ));

    // Rescue hash
    for _ in 0..4 {
        degrees.push(TransitionConstraintDegree::with_cycles(
            1,
            vec![cycle_length, cycle_length],
        ));
    }
    for _ in 0..HASH_STATE_WIDTH {
        degrees.push(TransitionConstraintDegree::with_cycles(
            3,
            vec![cycle_length],
        ));
    }

    degrees
}

// TODO: Maybe simplify signature definition a little
#[allow(clippy::type_complexity)]
fn transpose_signatures(
    signatures: &[([BaseElement; POINT_COORDINATE_WIDTH], Scalar)],
) -> (
    Vec<BaseElement>,
    Vec<BaseElement>,
    Vec<BaseElement>,
    Vec<BaseElement>,
    Vec<BaseElement>,
    Vec<BaseElement>,
    Vec<Scalar>,
) {
    let n = signatures.len();
    let mut r1 = Vec::with_capacity(n);
    let mut r2 = Vec::with_capacity(n);
    let mut r3 = Vec::with_capacity(n);
    let mut r4 = Vec::with_capacity(n);
    let mut r5 = Vec::with_capacity(n);
    let mut r6 = Vec::with_capacity(n);
    let mut r7 = Vec::with_capacity(n);
    for element in signatures {
        r1.push(element.0[0]);
        r2.push(element.0[1]);
        r3.push(element.0[2]);
        r4.push(element.0[3]);
        r5.push(element.0[4]);
        r6.push(element.0[5]);
        r7.push(element.1);
    }
    (r1, r2, r3, r4, r5, r6, r7)
}
