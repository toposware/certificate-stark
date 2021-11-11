// Copyright (c) ToposWare and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::super::utils::periodic_columns::stitch;
use super::constants::*;
use super::rescue::RATE_WIDTH;
use super::{ecc, field, rescue};
use crate::utils::{are_equal, is_zero, not, EvaluationResult};
use winterfell::{
    math::{curve::Scalar, fields::cheetah::BaseElement, FieldElement},
    Air, AirContext, Assertion, ByteWriter, EvaluationFrame, ProofOptions, Serializable, TraceInfo,
    TransitionConstraintDegree,
};

// SCHNORR AIR
// ================================================================================================

pub struct PublicInputs {
    pub messages: Vec<[BaseElement; 28]>,
    pub signatures: Vec<([BaseElement; 6], Scalar)>,
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
    messages: Vec<[BaseElement; 28]>,
    signatures: Vec<([BaseElement; 6], Scalar)>,
}

impl Air for SchnorrAir {
    type BaseElement = BaseElement;
    type PublicInputs = PublicInputs;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        // TODO: clean this up
        let bit_degree = if pub_inputs.signatures.len() == 1 {
            3
        } else {
            5
        };
        let degrees = vec![
            // First scalar multiplication
            TransitionConstraintDegree::with_cycles(5, vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(5, vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(5, vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(5, vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(5, vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(5, vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(4, vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(4, vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(4, vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(4, vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(4, vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(4, vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(4, vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(4, vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(4, vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(4, vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(4, vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(4, vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(2, vec![SIG_CYCLE_LENGTH]),
            // Second scalar multiplication
            // TODO: Fix this
            TransitionConstraintDegree::with_cycles(
                bit_degree,
                vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH],
            ),
            TransitionConstraintDegree::with_cycles(
                bit_degree,
                vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH],
            ),
            TransitionConstraintDegree::with_cycles(
                bit_degree,
                vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH],
            ),
            TransitionConstraintDegree::with_cycles(
                bit_degree,
                vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH],
            ),
            TransitionConstraintDegree::with_cycles(
                bit_degree,
                vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH],
            ),
            TransitionConstraintDegree::with_cycles(
                bit_degree,
                vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH],
            ),
            TransitionConstraintDegree::with_cycles(
                bit_degree,
                vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH],
            ),
            TransitionConstraintDegree::with_cycles(
                bit_degree,
                vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH],
            ),
            TransitionConstraintDegree::with_cycles(
                bit_degree,
                vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH],
            ),
            TransitionConstraintDegree::with_cycles(
                bit_degree,
                vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH],
            ),
            TransitionConstraintDegree::with_cycles(
                bit_degree,
                vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH],
            ),
            TransitionConstraintDegree::with_cycles(
                bit_degree,
                vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH],
            ),
            TransitionConstraintDegree::with_cycles(
                bit_degree,
                vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH],
            ),
            TransitionConstraintDegree::with_cycles(
                bit_degree,
                vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH],
            ),
            TransitionConstraintDegree::with_cycles(
                bit_degree,
                vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH],
            ),
            TransitionConstraintDegree::with_cycles(
                bit_degree,
                vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH],
            ),
            TransitionConstraintDegree::with_cycles(
                bit_degree,
                vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH],
            ),
            TransitionConstraintDegree::with_cycles(
                bit_degree,
                vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH],
            ),
            TransitionConstraintDegree::with_cycles(2, vec![SIG_CYCLE_LENGTH]),
            // Rescue hash
            TransitionConstraintDegree::with_cycles(1, vec![SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(3, vec![SIG_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(3, vec![SIG_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(3, vec![SIG_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(3, vec![SIG_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(3, vec![SIG_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(3, vec![SIG_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(3, vec![SIG_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(3, vec![SIG_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(3, vec![SIG_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(3, vec![SIG_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(3, vec![SIG_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(3, vec![SIG_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(3, vec![SIG_CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(3, vec![SIG_CYCLE_LENGTH]),
        ];
        assert_eq!(TRACE_WIDTH, trace_info.width());
        SchnorrAir {
            context: AirContext::new(trace_info, degrees, options),
            messages: pub_inputs.messages,
            signatures: pub_inputs.signatures,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseElement> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseElement>>(
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
        let pkey_point = &periodic_values[3..15];
        let hash_flag = periodic_values[15];
        let hash_internal_inputs = &periodic_values[16..23];
        let ark = &periodic_values[23..];

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
            pkey_point,
            final_point_addition_flag,
            hash_flag,
            copy_hash_flag,
            hash_internal_inputs,
        );
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseElement>> {
        let signatures = transpose_signatures(&self.signatures);
        // Assert starting and ending values
        vec![
            // Starting values (see init_sig_verification_state() in build_trace())
            Assertion::periodic(0, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(1, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(2, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(3, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(4, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(5, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(6, 0, SIG_CYCLE_LENGTH, BaseElement::ONE),
            Assertion::periodic(7, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(8, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(9, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(10, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(11, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(12, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(13, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(14, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(15, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(16, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(17, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(18, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(19, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(20, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(21, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(22, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(23, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(24, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(25, 0, SIG_CYCLE_LENGTH, BaseElement::ONE),
            Assertion::periodic(26, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(27, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(28, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(29, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(30, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(31, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(32, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(33, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(34, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(35, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(36, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(37, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(38, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::sequence(39, 0, SIG_CYCLE_LENGTH, signatures.0.clone()),
            Assertion::sequence(40, 0, SIG_CYCLE_LENGTH, signatures.1.clone()),
            Assertion::sequence(41, 0, SIG_CYCLE_LENGTH, signatures.2.clone()),
            Assertion::sequence(42, 0, SIG_CYCLE_LENGTH, signatures.3.clone()),
            Assertion::sequence(43, 0, SIG_CYCLE_LENGTH, signatures.4.clone()),
            Assertion::sequence(44, 0, SIG_CYCLE_LENGTH, signatures.5.clone()),
            Assertion::periodic(45, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(46, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(47, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(48, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(49, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(50, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(51, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            Assertion::periodic(52, 0, SIG_CYCLE_LENGTH, BaseElement::ZERO),
            // Ending values
            // We can compute R = S + h.P in the registers of S directly,
            // hence checking the x_coord of R in register 0 (i.e. x(S))
            Assertion::sequence(0, SCALAR_MUL_LENGTH + 1, SIG_CYCLE_LENGTH, signatures.0),
            Assertion::sequence(1, SCALAR_MUL_LENGTH + 1, SIG_CYCLE_LENGTH, signatures.1),
            Assertion::sequence(2, SCALAR_MUL_LENGTH + 1, SIG_CYCLE_LENGTH, signatures.2),
            Assertion::sequence(3, SCALAR_MUL_LENGTH + 1, SIG_CYCLE_LENGTH, signatures.3),
            Assertion::sequence(4, SCALAR_MUL_LENGTH + 1, SIG_CYCLE_LENGTH, signatures.4),
            Assertion::sequence(5, SCALAR_MUL_LENGTH + 1, SIG_CYCLE_LENGTH, signatures.5),
        ]
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseElement>> {
        // Start with empty periodic columns
        let mut columns = vec![Vec::new(); 6 + POINT_WIDTH - 1];
        // Stitch in the periodic columns applicable to all uses of Schnorr
        stitch(
            &mut columns,
            periodic_columns(),
            vec![(0, 0), (1, 1), (2, 2), (3, 3 + POINT_WIDTH * 2 / 3)],
        );
        // Values to feed to the last registers of the hash state at the end of a cycle.
        // Always zero (i.e. resetting the rate) or equal to the chunks of the message.
        let mut hash_intermediate_inputs =
            vec![vec![BaseElement::ZERO; SIG_CYCLE_LENGTH * self.signatures.len()]; RATE_WIDTH];

        // Public key coordinates extracted from the signed messages and to be used during scalar multiplications
        let pkey_len = POINT_WIDTH * 2 / 3; // ignore Z
        let mut pub_keys =
            vec![vec![BaseElement::ZERO; SIG_CYCLE_LENGTH * self.signatures.len()]; pkey_len];

        for message_index in 0..self.signatures.len() {
            for i in 0..SIG_CYCLE_LENGTH {
                for j in 0..RATE_WIDTH {
                    if i < NUM_HASH_ITER - 1 {
                        hash_intermediate_inputs[j][i * HASH_CYCLE_LENGTH
                            + NUM_HASH_ROUNDS
                            + message_index * SIG_CYCLE_LENGTH] =
                            self.messages[message_index][j + i * RATE_WIDTH];
                    }
                    pub_keys[j][i + message_index * SIG_CYCLE_LENGTH] =
                        self.messages[message_index][j];
                }
                for j in RATE_WIDTH..pkey_len {
                    pub_keys[j][i + message_index * SIG_CYCLE_LENGTH] =
                        self.messages[message_index][j];
                }
            }
        }

        // Stitch in the above columns in the appropriate places
        stitch(
            &mut columns,
            pub_keys,
            (3..3 + pkey_len).enumerate().collect(),
        );
        stitch(
            &mut columns,
            hash_intermediate_inputs,
            (3 + pkey_len + 1..3 + POINT_WIDTH + 2)
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
/// - the first two registers are equal to the values from the previous step
/// - the other two registers are equal to 0,
///   and add the values of internal_inputs for hash merging if any (only at last round)
fn enforce_hash_copy<E: FieldElement>(
    result: &mut [E],
    current: &[E],
    next: &[E],
    flag: E,
    internal_inputs: &[E],
) {
    result.agg_constraint(0, flag, are_equal(current[0], next[0]));
    result.agg_constraint(1, flag, are_equal(current[1], next[1]));
    result.agg_constraint(2, flag, are_equal(current[2], next[2]));
    result.agg_constraint(3, flag, are_equal(current[3], next[3]));
    result.agg_constraint(4, flag, are_equal(current[4], next[4]));
    result.agg_constraint(5, flag, are_equal(current[5], next[5]));
    result.agg_constraint(6, flag, are_equal(current[6], next[6]));
    // internal_inputs are either zero (no difference with original hash chain) when resetting the
    // last registers or equal to the message elements, to be fed to the hash in an iterated way.
    // See build_trace() for more info
    result.agg_constraint(7, flag, is_zero(next[7] - internal_inputs[0]));
    result.agg_constraint(8, flag, is_zero(next[8] - internal_inputs[1]));
    result.agg_constraint(9, flag, is_zero(next[9] - internal_inputs[2]));
    result.agg_constraint(10, flag, is_zero(next[10] - internal_inputs[3]));
    result.agg_constraint(11, flag, is_zero(next[11] - internal_inputs[4]));
    result.agg_constraint(12, flag, is_zero(next[12] - internal_inputs[5]));
    result.agg_constraint(13, flag, is_zero(next[13] - internal_inputs[6]));
}

// HELPER FUNCTIONS
// ------------------------------------------------------------------------------------------------

pub fn periodic_columns() -> Vec<Vec<BaseElement>> {
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
    result.append(&mut vec![hash_flag]);
    result.append(&mut rescue_constants);

    result
}

#[allow(clippy::too_many_arguments)]
pub fn evaluate_constraints<E: FieldElement + From<BaseElement>>(
    result: &mut [E],
    current: &[E],
    next: &[E],
    ark: &[E],
    doubling_flag: E,
    addition_flag: E,
    pkey_point: &[E],
    final_point_addition_flag: E,
    hash_flag: E,
    copy_hash_flag: E,
    hash_internal_inputs: &[E],
) {
    // Point to be used in the double-and-add operations of registers [0,1,2] (s.G)
    let generator_point: Vec<E> = GENERATOR.iter().map(|&coord| coord.into()).collect();

    // Point to be used in the double-and-add operations of registers [4,5,6] (h.P)
    let mut pkey_point: Vec<E> = pkey_point.iter().map(|&coord| coord.into()).collect();
    pkey_point.push(E::ONE);
    pkey_point.push(E::ZERO);
    pkey_point.push(E::ZERO);
    pkey_point.push(E::ZERO);
    pkey_point.push(E::ZERO);
    pkey_point.push(E::ZERO);

    // When scalar_mult_flag = 1, constraints for a double-and-add
    // step are enforced on the dedicated registers for S and h.P,
    // as well as a double-and-add in the field for bin(h).

    // Enforce a step of double-and-add in the group for s.G
    ecc::enforce_point_doubling(
        &mut result[..POINT_WIDTH + 1],
        &current[..POINT_WIDTH + 1],
        &next[..POINT_WIDTH + 1],
        doubling_flag,
    );

    ecc::enforce_point_addition(
        &mut result[..POINT_WIDTH + 1],
        &current[..POINT_WIDTH + 1],
        &next[..POINT_WIDTH + 1],
        &generator_point,
        addition_flag,
    );

    // Enforce a step of double-and-add in the group for h.P
    ecc::enforce_point_doubling(
        &mut result[POINT_WIDTH + 1..2 * POINT_WIDTH + 2],
        &current[POINT_WIDTH + 1..2 * POINT_WIDTH + 2],
        &next[POINT_WIDTH + 1..2 * POINT_WIDTH + 2],
        doubling_flag,
    );

    ecc::enforce_point_addition(
        &mut result[POINT_WIDTH + 1..2 * POINT_WIDTH + 2],
        &current[POINT_WIDTH + 1..2 * POINT_WIDTH + 2],
        &next[POINT_WIDTH + 1..2 * POINT_WIDTH + 2],
        &pkey_point,
        addition_flag,
    );

    // Enforce a step of double-and-add in the field for h
    field::enforce_double_and_add_step_constrained(
        &mut result[2 * POINT_WIDTH + 1..2 * POINT_WIDTH + 3],
        &current[2 * POINT_WIDTH + 1..2 * POINT_WIDTH + 3],
        &next[2 * POINT_WIDTH + 1..2 * POINT_WIDTH + 3],
        1,
        0,
        doubling_flag, // Do not repeat it twice
    );

    // When hash_flag = 1, constraints for a Rescue round
    // are enforced on the dedicated registers
    rescue::enforce_round(
        &mut result[2 * POINT_WIDTH + 3..],
        &current[2 * POINT_WIDTH + 3..],
        &next[2 * POINT_WIDTH + 3..],
        ark,
        hash_flag,
    );

    // When hash_flag = 0, constraints for copying hash values to the next step
    // and updating the rate registers with self.message[i] elements are enforced.

    enforce_hash_copy(
        &mut result[2 * POINT_WIDTH + 3..],
        &current[2 * POINT_WIDTH + 3..],
        &next[2 * POINT_WIDTH + 3..],
        copy_hash_flag,
        hash_internal_inputs,
    );

    // When scalar_mult_flag = 0, compute the addition
    // R = S + h.P and enforce h = hash output

    // Add h.P to S, with the result stored directly in the coordinates of S
    ecc::enforce_point_addition_reduce_x(
        &mut result[..POINT_WIDTH],
        &current[..POINT_WIDTH], // S
        &next[..POINT_WIDTH],
        &current[POINT_WIDTH + 1..2 * POINT_WIDTH + 1], // h.P
        final_point_addition_flag,
    );

    // Ensure that the accumulated value from the binary decomposition of h
    // matches the output of Rescue iterated hashes
    result.agg_constraint(
        2 * POINT_WIDTH + 2,
        final_point_addition_flag,
        are_equal(next[2 * POINT_WIDTH + 2], next[2 * POINT_WIDTH + 3]),
    );
}

fn transpose_signatures(
    signatures: &[([BaseElement; 6], Scalar)],
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
