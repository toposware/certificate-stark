use super::constants::*;
use winterfell::{
    math::{fields::f63::BaseElement, FieldElement},
    ProofOptions, Prover, Trace, TraceTable,
};

#[cfg(feature = "concurrent")]
use winterfell::iterators::*;

use super::trace::*;
use super::MerkleAir;
use super::PublicInputs;

use crate::TransactionMetadata;

// MERKLE UPDATE PROVER
// ================================================================================================

pub struct MerkleProver {
    options: ProofOptions,
}

impl MerkleProver {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }

    pub fn build_trace(&self, tx_metadata: &TransactionMetadata) -> TraceTable<BaseElement> {
        let initial_roots = &tx_metadata.initial_roots;
        let s_old_values = &tx_metadata.s_old_values;
        let r_old_values = &tx_metadata.r_old_values;
        let s_indices = &tx_metadata.s_indices;
        let r_indices = &tx_metadata.r_indices;
        let s_paths = &tx_metadata.s_paths;
        let r_paths = &tx_metadata.r_paths;
        let deltas = &tx_metadata.deltas;

        let num_transactions = tx_metadata.initial_roots.len();

        // allocate memory to hold the trace table
        let mut trace = TraceTable::new(TRACE_WIDTH, num_transactions * TRANSACTION_CYCLE_LENGTH);

        // Apply the same init and update steps for each separate transaction
        trace
            .fragments(TRANSACTION_CYCLE_LENGTH)
            .for_each(|mut merkle_trace| {
                let i = merkle_trace.index();

                merkle_trace.fill(
                    |state| {
                        init_merkle_update_state(
                            initial_roots[i],
                            s_old_values[i],
                            r_old_values[i],
                            deltas[i],
                            state,
                        );
                    },
                    |step, state| {
                        update_merkle_update_state(
                            step,
                            s_indices[i],
                            r_indices[i],
                            s_paths[i].clone(),
                            r_paths[i].clone(),
                            state,
                        );
                    },
                )
            });

        // set index bit at the second step to one; this still results in a valid execution trace
        // because actual index bits are inserted into the trace after step 7, but it ensures
        // that there are no repeating patterns in the index bit register, and thus the degree
        // of the index bit constraint is stable.
        trace.set(SENDER_BIT_POS, 1, BaseElement::ONE);
        trace.set(RECEIVER_BIT_POS, 1, BaseElement::ONE);

        trace
    }
}

impl Prover for MerkleProver {
    type BaseField = BaseElement;
    type Air = MerkleAir;
    type Trace = TraceTable<BaseElement>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> PublicInputs {
        let last_step = trace.length() - 1;

        PublicInputs {
            initial_root: [
                trace.get(PREV_TREE_ROOT_POS, 0),
                trace.get(PREV_TREE_ROOT_POS + 1, 0),
                trace.get(PREV_TREE_ROOT_POS + 2, 0),
                trace.get(PREV_TREE_ROOT_POS + 3, 0),
                trace.get(PREV_TREE_ROOT_POS + 4, 0),
                trace.get(PREV_TREE_ROOT_POS + 5, 0),
                trace.get(PREV_TREE_ROOT_POS + 6, 0),
            ],
            final_root: [
                trace.get(PREV_TREE_ROOT_POS, last_step),
                trace.get(PREV_TREE_ROOT_POS + 1, last_step),
                trace.get(PREV_TREE_ROOT_POS + 2, last_step),
                trace.get(PREV_TREE_ROOT_POS + 3, last_step),
                trace.get(PREV_TREE_ROOT_POS + 4, last_step),
                trace.get(PREV_TREE_ROOT_POS + 5, last_step),
                trace.get(PREV_TREE_ROOT_POS + 6, last_step),
            ],
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }
}
