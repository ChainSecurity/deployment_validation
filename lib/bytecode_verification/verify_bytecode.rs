use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

use alloy::primitives::Address;
use colored::Colorize;
use prettytable::Table;
use tracing::debug;

use crate::bytecode_verification::{compare_bytecodes::CompareBytecode, parse_json::ProjectInfo};
use crate::types::Immutable;
use crate::utils::pretty::PrettyPrinter;

fn decode_into_rows(table: &mut Table, immutable: &Immutable, pretty_printer: &PrettyPrinter) {
    assert!(!immutable.type_string.starts_with("t_"));
    debug!("Decoding {:?}", immutable);
    let translated_type = format!("t_{}", immutable.type_string);
    pretty_printer.add_decoded_to_table(&translated_type, &immutable.value, table);
}

pub fn print_verification_summary(
    project_dir: &Path,
    contract_name: &String,
    contract_address: &Address,
    status: CompareBytecode,
    project_info: &ProjectInfo,
    on_chain_bytecode: &String,
) {
    let mut table = Table::new();

    table.add_row(row!["Deployment Validation Summary", {
        if status.matched && status.metadata_matched {
            "Deployment Validation succeeded".green()
        } else if status.matched {
            "Deployment Validation succeeded\n(see ouput files for compare)".yellow()
        } else {
            "Deployment Validation failed".red()
        }
    }]);

    table.add_row(row!["Project Directory", project_dir.display()]);

    table.add_row(row!["Contract Name", contract_name]);

    table.add_row(row!["compiler version", &project_info.compiler_version]);

    table.add_row(row![
        "optimization enabled",
        &project_info.optimization_enabled
    ]);

    table.add_row(row!["optimization runs", &project_info.optimization_runs]);

    table.add_row(row!["Deployment Address", contract_address]);

    let mut immutable_table = Table::new();
    immutable_table.add_row(row!["immutable name", "immutable value"]);

    for immutable in &project_info.immutables {
        immutable_table.add_row(row![immutable.name, immutable.value]);
    }

    table.add_row(row!["immutables summary", immutable_table]);

    // create output files if necessary
    if !status.matched || !status.metadata_matched {
        write_out_bytecodes(project_info, on_chain_bytecode, &mut table);
    }

    table.printstd();
}

pub fn write_out_bytecodes(
    project_info: &ProjectInfo,
    on_chain_bytecode: &String,
    table: &mut Table,
) {
    let mut compiled_file = File::create("compiled_bytecode.txt").expect("Could not create file");
    let mut on_chain_file = File::create("on_chain_bytecode.txt").expect("Could not create file");

    compiled_file
        .write_all(project_info.compiled_bytecode.as_bytes())
        .unwrap();
    on_chain_file
        .write_all(on_chain_bytecode.as_bytes())
        .unwrap();

    table.add_row(row![
        "output files",
        format!("{}\n{}", "compiled_bytecode.txt", "on_chain_bytecode.txt")
    ]);
}

pub fn print_generation_summary(
    project_dir: &String,
    contract_name: &String,
    contract_address: &Address,
    status: CompareBytecode,
    project_info: &ProjectInfo,
    on_chain_bytecode: &String,
    pretty_printer: &PrettyPrinter,
) {
    let mut table = Table::new();

    if let Some(cbor) = &project_info.cbor_metadata {
        table.add_row(row!["Metadata Hash", { format!("{}", cbor) }]);
    }

    table.add_row(row!["Bytecode Check", {
        if status.matched && status.metadata_matched {
            "Bytecode Full Match".green()
        } else if status.matched {
            "Bytecode Match except for Metadata hash".yellow()
        } else {
            "Bytecode Mismatch".red()
        }
    }]);

    table.add_row(row!["Project Directory", project_dir]);

    table.add_row(row!["Contract Name", contract_name]);

    table.add_row(row!["Compiler Version", &project_info.compiler_version]);

    table.add_row(row![
        "optimization enabled",
        &project_info.optimization_enabled
    ]);

    if project_info.optimization_enabled {
        table.add_row(row!["Optimization Runs", &project_info.optimization_runs]);
    }

    table.add_row(row![
        "Deployment Address",
        format!("{:?}", contract_address)
    ]);

    let mut immutable_table = Table::new();
    immutable_table.add_row(row!["Immutable name", "Immutable value"]);

    for immutable in &project_info.immutables {
        immutable_table.add_row(row![immutable.name, immutable.value]);
        decode_into_rows(&mut immutable_table, immutable, pretty_printer);
    }

    if !project_info.immutables.is_empty() {
        table.add_row(row!["Immutables Summary", immutable_table]);
    } else {
        table.add_row(row!["Immutables Summary", "No Immutables found"]);
    }

    // create output files if necessary
    if !status.matched || !status.metadata_matched {
        write_out_bytecodes(project_info, on_chain_bytecode, &mut table);
    }

    table.printstd();
}
