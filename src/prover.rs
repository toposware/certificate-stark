use bitvec::{order::Lsb0, view::AsBits};
use winterfell::{math::fields::f63::BaseElement, ProofOptions, Prover, Trace, TraceTable};

#[cfg(feature = "concurrent")]
use winterfell::iterators::*;

use super::constants::*;
use super::schnorr;
use super::trace::*;
use super::PublicInputs;
use super::TransactionAir;
use super::TransactionMetadata;

use merkle_const::PREV_TREE_ROOT_POS;
use schnorr_const::AFFINE_POINT_WIDTH;

// TRANSACTION PROVER
// ================================================================================================

pub struct TransactionProver {
    options: ProofOptions,
}

impl TransactionProver {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }

    // The trace is composed as follows:
    // (note that sigma here refers to sender_balance - delta)
    //
    // | 4 * HASH_STATE + 2 + HASH_RATE |      2 * AFF_POINT + 3      | number of registers
    // |          merkle::init          | copy_keys_delta_sigma_nonce | sub-programs
    // |         merkle::update         | copy_keys_delta_sigma_nonce |
    // |         schnorr::init          | copy_keys_delta_sigma_nonce |
    // |         schnorr::verif         | range_proof_delta_and_sigma |
    pub fn build_trace(&self, tx_metadata: &TransactionMetadata) -> TraceTable<BaseElement> {
        let initial_roots = &tx_metadata.initial_roots;
        let s_old_values = &tx_metadata.s_old_values;
        let r_old_values = &tx_metadata.r_old_values;
        let s_indices = &tx_metadata.s_indices;
        let r_indices = &tx_metadata.r_indices;
        let s_paths = &tx_metadata.s_paths;
        let r_paths = &tx_metadata.r_paths;
        let deltas = &tx_metadata.deltas;
        let signatures = &tx_metadata.signatures;
        let num_transactions = tx_metadata.initial_roots.len();
        // allocate memory to hold the trace table
        let mut trace = TraceTable::new(TRACE_WIDTH, num_transactions * TRANSACTION_CYCLE_LENGTH);
        trace
            .fragments(TRANSACTION_CYCLE_LENGTH)
            .for_each(|mut transaction_trace| {
                let i = transaction_trace.index();
                let delta_bytes = deltas[i].to_bytes();
                let delta_bits = delta_bytes.as_bits::<Lsb0>();
                let sigma_bytes = (s_old_values[i][AFFINE_POINT_WIDTH] - deltas[i]).to_bytes();
                let sigma_bits = sigma_bytes.as_bits::<Lsb0>();
                let message = super::build_tx_message(
                    &s_old_values[i][0..AFFINE_POINT_WIDTH],
                    &r_old_values[i][0..AFFINE_POINT_WIDTH],
                    deltas[i],
                    s_old_values[i][AFFINE_POINT_WIDTH + 1],
                );
                let (pkey_point, sig_bytes, sig_hash_bytes) =
                    schnorr::build_sig_info(&message, &signatures[i]);
                let sig_bits = sig_bytes.as_bits::<Lsb0>();
                let sig_hash_bits = sig_hash_bytes.as_bits::<Lsb0>();
                transaction_trace.fill(
                    |state| {
                        init_transaction_state(
                            initial_roots[i],
                            s_old_values[i],
                            r_old_values[i],
                            deltas[i],
                            state,
                        );
                    },
                    |step, state| {
                        update_transaction_state(
                            step,
                            s_indices[i],
                            r_indices[i],
                            s_paths[i].clone(),
                            r_paths[i].clone(),
                            delta_bits,
                            sigma_bits,
                            signatures[i],
                            sig_bits,
                            sig_hash_bits,
                            message,
                            pkey_point,
                            state,
                        );
                    },
                )
            });
        trace
    }
}

impl Prover for TransactionProver {
    type BaseField = BaseElement;
    type Air = TransactionAir;
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
