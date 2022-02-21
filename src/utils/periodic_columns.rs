// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use winterfell::math::fields::f63::BaseElement;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Stitches some periodic values `additional_columns` within `original_columns`.
/// Their positions are determined by the provided `index_map`, a `vec` of tuples
/// `(additional_index, original_index)` stitching for each the column at position
/// `additional_index` within `additional_columns` within `original_columns` at
/// position `original_index`.
///
/// When plugging different sub-AIR programs together, it can be used to plug program
/// specific periodic values at portions of the execution when the involved sub-AIR
/// program is being evaluated.
///
/// # Example
///
/// Let A, B and C be 3 sub-AIR program blocks, executed successively in given order.
/// One can set up the unique periodic value column `column_for_B` by using
/// `stitch` in combination with `pad` as follows:
///
/// ```ignore
/// // Fill-up the periodic column for B with zeroes during A execution.
/// pad(
///     &mut periodic_columns,
///     vec![index_B],
///     length_A,
///     BaseElement::ZERO,
/// );
///
/// // Insert the periodic values for B.
/// stitch(
///     &mut periodic_columns,
///     periodic_value_B,
///     vec![index_B],
/// );
///
/// // Fill-up the periodic column for B with zeroes during C execution.
/// pad(
///     &mut periodic_columns,
///     vec![index_B],
///     length_C,
///     BaseElement::ZERO,
/// );
/// ```
pub(crate) fn stitch(
    original_columns: &mut [Vec<BaseElement>],
    additional_columns: Vec<Vec<BaseElement>>,
    index_map: Vec<(usize, usize)>,
) {
    for (add_index, org_index) in index_map {
        // Ensure indices are within bounds
        debug_assert!(
            add_index < additional_columns.len(),
            "Index out of bounds: No column {} in {} additional columns.",
            add_index,
            additional_columns.len(),
        );
        debug_assert!(
            org_index < original_columns.len(),
            "Index out of bounds: No column {} in {} original columns.",
            org_index,
            original_columns.len(),
        );
        original_columns[org_index].append(&mut additional_columns[add_index].clone());
    }
}

/// Fills some periodic values columns within `original_columns` with the provided
/// `additional_columns`. Their positions are determined by `index_map`, a `vec` of
/// tuples `(additional_index, original_index)` stitching for each the column at
/// position `additional_index` within `additional_columns` within `original_columns`
/// at position `original_index`.
///
/// Unlike `stitch()` which appends the whole additional columns, `fill()` injects the
/// additional columns values inside `original_columns` such that the values remain at
/// the same indices.
///
/// When plugging different sub-AIR programs together, it can be used to plug program
/// specific periodic values at portions of the execution when the involved sub-AIR
/// program is being evaluated.
///
/// # Example
///
/// ```ignore
/// let mut periodic_columns = vec![Vec::new(); 4];
/// periodic_columns[1] = vec![BaseElement::ZERO; 3];
///
/// let additional_column: Vec<BaseElement> = (10..18u32)
///     .iter()
///     .map(|e| BaseElement::new(e))
///     .collect();
///
/// // Fill-up the periodic columns at index 1 with the provided additional one.
/// fill(
///     &mut periodic_columns,
///     vec![additional_column],
///     vec![(0,1)],
///     8,
/// );
///
/// assert_eq(
///     periodic_columns[1],
///     vec![
///         BaseElement::ZERO,
///         BaseElement::ZERO,
///         BaseElement::ZERO,
///         BaseElement::new(13u32),
///         BaseElement::new(14u32),
///         BaseElement::new(15u32),
///         BaseElement::new(16u32),
///         BaseElement::new(17u32),
///     ],
/// );
/// ```
pub(crate) fn fill(
    original_columns: &mut [Vec<BaseElement>],
    additional_columns: Vec<Vec<BaseElement>>,
    index_map: Vec<(usize, usize)>,
    length: usize,
) {
    for (add_index, org_index) in index_map {
        // Ensure indices are within bounds
        debug_assert!(
            add_index < additional_columns.len(),
            "Index out of bounds: No column {} in {} additional columns to fill from.",
            add_index,
            additional_columns.len(),
        );
        debug_assert!(
            org_index < original_columns.len(),
            "Index out of bounds: No column {} in {} original columns to fill in.",
            org_index,
            original_columns.len(),
        );
        let org_column = &mut original_columns[org_index];
        let add_column = &additional_columns[add_index];
        for i in org_column.len()..length {
            org_column.push(add_column[i % add_column.len()]);
        }
    }
}

/// Pads some periodic values columns within `original_columns` indexed
/// by their `indices` with `pad_element`. The padding is done up to `length`.
///
/// When plugging different sub-AIR programs together, it can be used to deactivate
/// periodic values at portions of the execution when the involved sub-AIR program
/// is not being evaluated.
///
/// # Example
///
/// Let A, B and C be 3 sub-AIR program blocks, executed successively in given order.
/// One can set up the unique periodic value column `column_for_B` by using
/// `pad` in combination with `stitch` as follows:
///
/// ```ignore
/// // Fill-up the periodic column for B with zeroes during A execution.
/// pad(
///     &mut periodic_columns,
///     vec![index_B],
///     length_A,
///     BaseElement::ZERO,
/// );
///
/// // Insert the periodic values for B.
/// stitch(
///     &mut periodic_columns,
///     periodic_value_B,
///     vec![index_B],
/// );
///
/// // Fill-up the periodic column for B with zeroes during C execution.
/// pad(
///     &mut periodic_columns,
///     vec![index_B],
///     length_C,
///     BaseElement::ZERO,
/// );
/// ```
pub(crate) fn pad(
    original_columns: &mut [Vec<BaseElement>],
    indices: Vec<usize>,
    length: usize,
    pad_element: BaseElement,
) {
    for index in indices {
        // Ensure index is within bounds
        debug_assert!(
            index < original_columns.len(),
            "Index out of bounds: No column {} in {} columns to pad.",
            index,
            original_columns.len(),
        );
        let column = &mut original_columns[index];
        // Ensure padding can be added
        debug_assert!(
            length >= column.len(),
            "No room to pad: column {} has length {} > {}.",
            index,
            column.len(),
            length,
        );
        column.append(&mut vec![pad_element; length - column.len()]);
    }
}
