// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use certificate_stark::TransactionExample;
use winterfell::{FieldExtension, HashFunction, ProofOptions};

use gumdrop::Options;
use log::debug;
use std::io::Write;
use std::time::Instant;

#[derive(Debug, Options)]
struct MyOptions {
    #[options(help = "Print this help message.")]
    help: bool,

    #[options(help = "number of transactions (default 4)", short = "n")]
    num_tx: Option<usize>,

    #[options(help = "number of FRI queries (default 42)", short = "q")]
    num_queries: Option<usize>,

    #[options(
        help = "field extension (default 3 (Cubic); can be 1 (None) or 2 (Quadratic))",
        short = "e"
    )]
    field_extension: Option<u8>,

    #[options(help = "blowup factor (default 8)", short = "b")]
    blowup_factor: Option<usize>,

    #[options(help = "grinding factor (default 0)", short = "g")]
    grinding_factor: Option<u32>,

    #[options(
        help = "external hash function (default Blake3)\n\t- 0 for Blake3\n\t- 1 for Sha3",
        short = "h"
    )]
    hash_function: Option<u8>,

    #[options(help = "FRI folding factor (default 4)", short = "f")]
    fri_folding: Option<usize>,
}

fn main() {
    // configure logging
    env_logger::Builder::new()
        .format(|buf, record| writeln!(buf, "{}", record.args()))
        .filter_level(log::LevelFilter::Debug)
        .init();

    let options = MyOptions::parse_args_default_or_exit();
    let num_tx = options.num_tx.unwrap_or(4);
    let num_queries = options.num_queries.unwrap_or(42);
    let blowup_factor = options.blowup_factor.unwrap_or(8);
    let grinding_factor = options.grinding_factor.unwrap_or(0);
    let field_extension = match options.field_extension.unwrap_or(3) {
        2 => FieldExtension::Quadratic,
        3 => FieldExtension::Cubic,
        _ => FieldExtension::None,
    };
    let hash_function = if options.hash_function.unwrap_or(0) == 1 {
        HashFunction::Sha3_256
    } else {
        HashFunction::Blake3_256
    };
    let fri_folding = options.fri_folding.unwrap_or(4);

    let proof_options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        hash_function,
        field_extension,
        fri_folding,
        256,
    );

    let state_transition_example = TransactionExample::new(proof_options, num_tx);

    debug!("============================================================");

    // generate proof
    let now = Instant::now();
    let proof = state_transition_example.prove();
    debug!(
        "---------------------\nProof generated in {} ms",
        now.elapsed().as_millis()
    );

    let proof_bytes = proof.to_bytes();
    debug!("Proof size: {:.1} KB", proof_bytes.len() as f64 / 1024f64);
    debug!("Proof security: {} bits", proof.security_level(true));

    let now = Instant::now();
    match state_transition_example.verify(proof) {
        Ok(_) => debug!(
            "Proof verified in {:.1} ms",
            now.elapsed().as_micros() as f64 / 1000f64
        ),
        Err(msg) => debug!("Failed to verify proof: {}", msg),
    }
    debug!("============================================================");
}
