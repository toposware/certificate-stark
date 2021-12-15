// Copyright (c) Toposware, Inc. 2021
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use winterfell::math::fields::f63::BaseElement;

pub fn stitch(
    original_columns: &mut Vec<Vec<BaseElement>>,
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

pub fn fill(
    original_columns: &mut Vec<Vec<BaseElement>>,
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

pub fn pad(
    original_columns: &mut Vec<Vec<BaseElement>>,
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
