use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::str::FromStr;

use alloy::json_abi::Event;
use alloy::primitives::{Address, B256};
use alloy_dyn_abi::EventExt;
use clap::{arg, value_parser, ArgMatches, Command};
use colored::Colorize;
use console::style;
use dvf_libs::bytecode_verification::compare_bytecodes::{CompareBytecode, CompareInitCode};
use dvf_libs::bytecode_verification::parse_json::{Environment, ProjectInfo};
use dvf_libs::bytecode_verification::verify_bytecode;
use dvf_libs::dvf::config::{replace_tilde, DVFConfig};
use dvf_libs::dvf::parse::{self, ValidationError, CURRENT_VERSION_STRING};
use dvf_libs::dvf::registry::{self, Registry};
use dvf_libs::state::contract_state::ContractState;
use dvf_libs::state::forge_inspect::{self, StateVariable, TypeDescription};
use dvf_libs::utils::pretty::PrettyPrinter;
use dvf_libs::web3;
use indicatif::ProgressBar;
use prettytable::{row, Table};
use scanf::sscanf;
use semver::Version;
use tracing::{debug, info};

pub const FIRST_STORAGE_LAYOUT: Version = Version::new(0, 5, 13);

// independent == true  => Multiple different DVFs for the same address/ID
// independent == false => Multiple references for the same DVFs
fn aggregate_results(
    results: &mut Vec<Result<(), ValidationError>>,
    independent: bool,
) -> Result<(), ValidationError> {
    if results.len() == 1 {
        return results.remove(0);
    }

    let mut has_valid = false;
    let mut no_dvf_found_msgs: Vec<String> = vec![];
    let mut invalid_msgs: Vec<String> = vec![];
    let mut error_msgs: Vec<String> = vec![];
    for result in results {
        match result {
            Ok(()) => has_valid = true,
            Err(ValidationError::Insecure(s)) => {
                return Err(ValidationError::Insecure(s.to_owned()))
            }
            Err(ValidationError::Invalid(s)) => invalid_msgs.push(s.to_owned()),
            Err(ValidationError::Error(s)) => error_msgs.push(s.to_owned()),
            Err(ValidationError::NoDVFFound(s)) => no_dvf_found_msgs.push(s.to_owned()),
        }
    }
    if !independent && !error_msgs.is_empty() {
        return Err(ValidationError::Error(error_msgs.join("\n")));
    }
    if !invalid_msgs.is_empty() && !has_valid {
        return Err(ValidationError::Invalid(invalid_msgs.join("\n")));
    }
    if !no_dvf_found_msgs.is_empty() {
        return Err(ValidationError::NoDVFFound(no_dvf_found_msgs.join(", ")));
    }
    if !has_valid && !error_msgs.is_empty() {
        return Err(ValidationError::Error(error_msgs.join("\n")));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_dvf(
    config: &DVFConfig,
    input_file: &Path,
    validation_block_num: u64,
    registry: &Registry,
    seen_ids: &mut HashSet<String>,
    allow_untrusted: bool,
    continue_on_mismatch: bool,
    expected_contract_name: Option<String>,
) -> Result<(), ValidationError> {
    let mut pc = 1_u64;
    let progress_mode = ProgressMode::Validation;
    print_progress("Consistency Checks.", &mut pc, &progress_mode);
    let mut mismatch_found = false;

    let filled = parse::CompleteDVF::from_path(input_file)?;

    config.compare_chain_id(filled.chain_id)?;

    info!("Validating {}", input_file.display());
    filled.validate_id()?;
    if !allow_untrusted {
        filled.validate_signature(!allow_untrusted)?;
        if let Some(signature) = filled.signature {
            if !registry.is_trusted_signer(&signature.signer) {
                return Err(ValidationError::NoDVFFound(format!(
                    "Signed by an untrusted signer: {:?}",
                    signature.signer
                )));
            }
        }
    }

    // Remember IDs for recursive validation
    seen_ids.insert(filled.id.clone().unwrap().clone());

    if validation_block_num < filled.deployment_block_num {
        return Err(ValidationError::from(
            "Validation block is before Deployment Block.",
        ));
    }

    if filled.init_block_num < filled.deployment_block_num {
        return Err(ValidationError::from(
            "Validation block is before Init Block.",
        ));
    }

    // Check deployment block if possible
    match web3::get_deployment_block(config, &filled.address) {
        Ok(deployment_block_num) => {
            if deployment_block_num != filled.deployment_block_num {
                return Err(ValidationError::Invalid(format!(
                    "Incorrect deployment block. Specified to be {}, but expected {}.",
                    deployment_block_num, filled.deployment_block_num
                )));
            }
        }
        Err(_) => {
            println!(
                "Warning. Could not verify that the contract was deployed in block {}.",
                filled.deployment_block_num
            )
        }
    }

    if let Some(expected) = expected_contract_name {
        if expected != filled.contract_name {
            return Err(ValidationError::NoDVFFound(format!(
                "DVF was supposed to contain contract {} but contained {}.",
                expected.clone(),
                filled.contract_name.clone()
            )));
        }
    }

    if let Some(expiry) = filled.expiry_in_epoch_seconds {
        let current_timestamp = web3::get_eth_block_timestamp(config, validation_block_num)?;
        if current_timestamp > expiry {
            return Err(ValidationError::Invalid(format!(
                "DVF {} is expired.",
                filled.id.clone().unwrap()
            )));
        }
    }

    // Validate Codehash
    print_progress("Validating Codehash.", &mut pc, &progress_mode);
    let rpc_code_hash = web3::get_eth_codehash(config, &filled.address, validation_block_num)?;
    if rpc_code_hash != filled.codehash {
        return Err(ValidationError::from("Different codehash."));
    }

    // Validate Storage slots
    print_progress("Validating Storage Variables.", &mut pc, &progress_mode);
    for storage_variable in &filled.critical_storage_variables {
        let current_val = web3::get_eth_storage_at(
            config,
            &filled.address,
            &storage_variable.slot,
            validation_block_num,
        )?;
        let size: usize = storage_variable.value.len();
        let start_index: usize = 32 - storage_variable.offset - size;
        let end_index: usize = start_index + size;
        if !storage_variable.compare(&current_val[start_index..end_index]) {
            let message = format!(
                "Value mismatch for {} (slot {:#x}, offset {}).\nNew value: 0x{}\nOperator:  {}\nOld value: 0x{}",
                &storage_variable.var_name,
                &storage_variable.slot,
                &storage_variable.offset,
                hex::encode(&current_val[start_index..end_index]),
                &storage_variable.comparison_operator,
                hex::encode(&storage_variable.value)
            );
            if continue_on_mismatch {
                mismatch_found = true;
                println!("{}", message);
            } else {
                return Err(ValidationError::Invalid(message));
            }
        }
    }

    // Validate events
    print_progress("Validating Critical Events.", &mut pc, &progress_mode);
    let pb = ProgressBar::new(filled.critical_events.len().try_into().unwrap());
    for critical_event in &filled.critical_events {
        let seen_events = web3::get_eth_events(
            config,
            &filled.address,
            filled.deployment_block_num,
            validation_block_num,
            &vec![critical_event.topic0],
        )?;
        if seen_events.len() != critical_event.occurrences.len() {
            return Err(ValidationError::Invalid(format!(
                "Found {} occurrences of event {}, but expected {}.",
                seen_events.len(),
                critical_event.sig,
                critical_event.occurrences.len()
            )));
        }

        #[allow(clippy::needless_range_loop)]
        for i in 0..seen_events.len() {
            let log_inner = &seen_events[i].inner;
            if log_inner.topics() != critical_event.occurrences[i].topics {
                let message = format!(
                    "Mismatching topics for event occurrence {} of {}.",
                    i, critical_event.sig
                );
                if continue_on_mismatch {
                    mismatch_found = true;
                    println!("{}", message);
                } else {
                    return Err(ValidationError::Invalid(message));
                }
            }
            if log_inner.data.data != critical_event.occurrences[i].data {
                let message = format!(
                    "Mismatching data for event occurrence {} of {}.",
                    i, critical_event.sig
                );
                if continue_on_mismatch {
                    mismatch_found = true;
                    println!("{}", message);
                } else {
                    return Err(ValidationError::Invalid(message));
                }
            }
        }
        pb.inc(1);
    }
    pb.finish_and_clear();

    if mismatch_found {
        return Err(ValidationError::Invalid(String::from(
            "See previous mismatches.",
        )));
    }

    // Check insecure flag
    if let Some(insecure) = filled.insecure {
        if insecure {
            return Err(ValidationError::Insecure(format!(
                "{} ({}) is insecure.",
                filled.contract_name, filled.address
            )));
        }
    }

    // Check optional references
    print_progress("Validating References.", &mut pc, &progress_mode);
    let mut reference_results: Vec<Result<(), ValidationError>> = vec![];
    if let Some(references) = filled.references {
        for reference in &references {
            if !seen_ids.contains(&reference.id) {
                let referenced_dvfs = registry.find_dvf_by_id(&reference.id)?;
                if referenced_dvfs.is_empty() {
                    reference_results.push(Err(ValidationError::NoDVFFound(reference.id.clone())))
                } else {
                    let mut subresults: Vec<Result<(), ValidationError>> = vec![];
                    for referenced_dvf in referenced_dvfs {
                        subresults.push(validate_dvf(
                            config,
                            &referenced_dvf,
                            validation_block_num,
                            registry,
                            seen_ids,
                            allow_untrusted,
                            false,
                            Some(reference.contract_name.clone()),
                        ));
                    }
                    let aggregated_subresult = aggregate_results(&mut subresults, true);
                    reference_results.push(aggregated_subresult);
                };
            }
        }
        return aggregate_results(&mut reference_results, false);
    }
    Ok(())
}

// Validator function
fn is_valid_32_byte_hex(val: &str) -> Result<String, String> {
    if !val.starts_with("0x") {
        return Err(format!("Argument {} needs to start with 0x.", val));
    }
    if val.len() != 66 {
        return Err(format!("Argument {} needs to be 66 characters long.", val));
    }
    Ok(val.to_string())
}

// Validator function
fn is_valid_path(val: &str) -> Result<PathBuf, String> {
    let path = Path::new(val);
    if path.exists() {
        Ok(path.to_path_buf())
    } else {
        Err(String::from("The path provided is not valid"))
    }
}

// Validator function
fn is_valid_address(val: &str) -> Result<Address, String> {
    match Address::from_str(val) {
        Ok(a) => {
            if a != Address::ZERO {
                Ok(a)
            } else {
                Err(String::from("Zero is not a valid address."))
            }
        }
        Err(e) => Err(format!("Could not parse address: {:?}", e)),
    }
}

// Validator function
fn is_valid_blocknum(val: &str) -> Result<u64, String> {
    match val.parse::<u64>() {
        Ok(b) => Ok(b),
        Err(e) => Err(format!("Could not parse block number: {:?}", e)),
    }
}

fn is_filename_only_path(path: &Path) -> bool {
    path.components().count() == 1
}

fn make_relative_to_dvf_storage(config: &DVFConfig, path: &Path) -> PathBuf {
    let mut new_path = PathBuf::from(&config.dvf_storage);
    new_path.push(path);
    new_path.clone()
}

fn parse_input_path(config: &DVFConfig, path_val: &str) -> Result<PathBuf, ValidationError> {
    let input_path_buf = Path::new(path_val).canonicalize()?;
    let input_path = input_path_buf.as_path();
    if input_path_buf.exists() {
        Ok(input_path_buf)
    } else if is_filename_only_path(input_path)
        && make_relative_to_dvf_storage(config, input_path).exists()
    {
        Ok(make_relative_to_dvf_storage(config, input_path))
    } else {
        Err(ValidationError::from("The path provided is not valid."))
    }
}

fn main() {
    let matches = Command::new("dv")
        .version(CURRENT_VERSION_STRING)
        .about("Deployment Verification")
        .author("ChainSecurity")
        .arg(arg!(-v --verbose "Sets the level of verbosity").action(clap::ArgAction::Count))
        .arg(
            arg!(-c --config <FILE>)
                .help("Path of config file, default location: undefined")
                .action(clap::ArgAction::Set)
                .value_parser(value_parser!(String)),
        )
        .subcommand(
            Command::new("init")
                .about("Initializes a new DVF")
                .arg(
                    arg!(--initblock <BLOCK>)
                        .help("The block number at which the state snapshot should be taken.")
                        .value_parser(is_valid_blocknum),
                )
                .arg(
                    arg!(--project <PATH>)
                        .help("Path to the root folder of the source code project")
                        .required(true)
                        .value_parser(is_valid_path),
                )
                .arg(
                    arg!(--address <ADDRESS>)
                        .help("Address of the contract")
                        .required(true)
                        .value_parser(is_valid_address),
                )
                .arg(
                    arg!(--chainid <CHAINID>)
                        .help("Chain ID where the contract is deployed")
                        .value_parser(value_parser!(u64))
                        .default_value("1"),
                )
                .arg(
                    arg!(--contractname <NAME>)
                        .help("Name of the contract")
                        .required(true),
                )
                .arg(
                    arg!(--implementation <NAME>)
                        .help("Optional name of the implementation contract"),
                )
                .arg(
                    arg!(--implementationproject <PATH>)
                        .help("Path to the root folder of the implementation project")
                        .value_parser(is_valid_path),
                )
                .arg(
                    arg!(--factory)
                        .help(
                            "Treat this contract as a factory, which changes bytecode verification",
                        )
                        .action(clap::ArgAction::SetTrue),
                )
                .arg(
                    arg!(--implementationenv <ENV>)
                        .help("Implementation project's development environment")
                        .value_parser(value_parser!(Environment))
                        .default_value("foundry"),
                )
                .arg(
                    arg!(--implementationartifacts <PATH>)
                        .help("Folder containing the implementation project artifacts")
                        .default_value("artifacts"),
                )
                .arg(
                    arg!(--env <ENV>)
                        .help("Project's development environment")
                        .value_parser(value_parser!(Environment))
                        .default_value("foundry"),
                )
                .arg(
                    arg!(--artifacts <PATH>)
                        .help("Folder containing the project artifacts")
                        .default_value("artifacts"),
                )
                .arg(arg!(--buildcache <PATH>).help("Folder containing build-info files"))
                .arg(
                    arg!(--implementationbuildcache <PATH>)
                        .help("Folder containing the implementation contract's build-info files"),
                )
                .arg(
                    arg!(<OUTPUT>)
                        .help("Path of the generated DVF file")
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("id")
                .about("Generates the DVF ID")
                .arg(arg!(<DVF>).help("The provided DVF file - updated in-place")),
        )
        .subcommand(
            Command::new("add-reference")
                .about("Adds a reference")
                .arg(
                    arg!(--id <ID>)
                        .help("Specifies the new reference ID")
                        .required(true)
                        .value_parser(is_valid_32_byte_hex),
                )
                .arg(
                    arg!(--contractname <NAME>)
                        .help("Contract Name of the reference")
                        .required(true),
                )
                .arg(
                    arg!(<DVF>)
                        .help("The DVF file - updated in-place")
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("sign").about("Signs a DVF").arg(
                arg!(<DVF>)
                    .help("The DVF file - updated in-place")
                    .required(true),
            ),
        )
        .subcommand(
            Command::new("validate")
                .about("Validates a DVF")
                .arg(
                    arg!(--validationblock <BLOCK>)
                        .help("The block number used for validation")
                        .value_parser(is_valid_blocknum),
                )
                .arg(
                    arg!(--allowuntrusted)
                        .help("Allows validation of unsigned or untrusted DVFs")
                        .action(clap::ArgAction::SetTrue),
                )
                .arg(
                    arg!(--continue)
                        .help("Do not stop on the first mismatch but continue to show more")
                        .action(clap::ArgAction::SetTrue),
                )
                .arg(arg!(<DVF>).help("The DVF file").required(true)),
        )
        .subcommand(
            Command::new("update")
                .about("Updates a DVF")
                .arg(
                    arg!(--validationblock <BLOCK>)
                        .help("The block number used for validation")
                        .value_parser(is_valid_blocknum),
                )
                .arg(arg!(<DVF>).help("The DVF file")),
        )
        .subcommand(
            Command::new("generate-config").about("Interactively generates a configuration file"),
        )
        .subcommand(
            Command::new("generate-build-cache")
                .about("Generates the build cache")
                .arg(
                    arg!(--project <PATH>)
                        .help("Path to the root folder of the source code project")
                        .required(true)
                        .value_parser(is_valid_path),
                )
                .arg(
                    arg!(--env <ENV>)
                        .help("Project's development environment")
                        .value_parser(clap::value_parser!(Environment))
                        .default_value("foundry"),
                )
                .arg(
                    arg!(--artifacts <PATH>)
                        .help("Folder containing the artifacts")
                        .default_value("artifacts"),
                ),
        )
        .subcommand(
            Command::new("bytecode-check")
                .about("Performs just the bytecode check")
                .arg(
                    arg!(--initblock <BLOCK>)
                        .help("The block number for querying code")
                        .value_parser(is_valid_blocknum),
                )
                .arg(
                    arg!(--project <PATH>)
                        .help("Path to the root folder of the source code project")
                        .required(true)
                        .value_parser(is_valid_path),
                )
                .arg(
                    arg!(--address <ADDRESS>)
                        .help("Address of the contract")
                        .required(true)
                        .value_parser(is_valid_address),
                )
                .arg(
                    arg!(--chainid <CHAINID>)
                        .help("Chain ID where the contract is deployed")
                        .value_parser(value_parser!(u64))
                        .default_value("1"),
                )
                .arg(
                    arg!(--contractname <NAME>)
                        .help("Name of the contract")
                        .required(true),
                )
                .arg(
                    arg!(--factory)
                        .help("Treats this contract as a factory, altering bytecode verification")
                        .action(clap::ArgAction::SetTrue),
                )
                .arg(
                    arg!(--env <ENV>)
                        .help("Project's development environment")
                        .value_parser(value_parser!(Environment))
                        .default_value("foundry"),
                )
                .arg(
                    arg!(--artifacts <PATH>)
                        .help("Folder containing the artifacts")
                        .default_value("artifacts"),
                )
                .arg(arg!(--buildcache <PATH>).help("Folder containing build-info files")),
        )
        .get_matches();

    /*

    let matches = Command::new("dv")
        .version(CURRENT_VERSION.to_string().as_str())
        .about("Deployment Verification")
        .author("ChainSecurity")
        .arg(
            Arg::with_name("verbose")
                .short('v')
                .long("verbose")
                .action(clap::ArgAction::Count)
                .help("Sets the level of verbosity"),
        )
        .arg(
            Arg::with_name("config")
                .short('c')
                .long("config")
                .help(
                    format!(
                        "Path of config file, default location: {}",
                        DVFConfig::default_path()
                            .unwrap_or(PathBuf::from("undefined"))
                            .display()
                    )
                    .as_str(),
                )
                .action(ArgAction::Set)
                .validator(is_valid_path),
        )
        .subcommand(SubCommand::with_name("init").about("initializes a new dvf")
                .arg(
                    Arg::with_name("initblock")
                        .long("initblock")
                        .help("The block number at which the state snapshot should be taken. Current block if not set. Its final state is used.")
                        .validator(is_valid_blocknum)
                        .action(ArgAction::Set),
                )
                .arg(
                    Arg::with_name("project")
                        .long("project")
                        .help("Path to the root folder of source code project")
                        .required(true)
                        .validator(is_valid_path)
                        .action(ArgAction::Set),
                )
                .arg(
                    Arg::with_name("address")
                        .long("address")
                        .help("Address of the contract")
                        .required(true)
                        .validator(is_valid_address)
                        .action(ArgAction::Set),
                )
                .arg(
                    Arg::with_name("chainid")
                        .long("chainid")
                        .help("Chain ID where contract is deployed")
                        .value_parser(value_parser!(u64))
                        .default_value("1")
                        .action(ArgAction::Set),
                )
                .arg(
                    Arg::with_name("contractname")
                        .long("contractname")
                        .help("Name of the contract")
                        .required(true)
                        .action(ArgAction::Set),
                )
                .arg(
                    Arg::with_name("implementation")
                        .long("implementation")
                        .help("Optional Name of implementation contract")
                        .action(ArgAction::Set),
                )
                .arg(
                    Arg::with_name("implementationproject")
                        .long("implementationproject")
                        .help("Path to root folder of source code project, if an implementation contract is used and it is in a different project")
                        .validator(is_valid_path) // TODO: validator() is deprecated
                        .action(ArgAction::Set),
                )
                .arg(
                    Arg::with_name("factory")
                        .long("factory")
                        .help("Treat this contract as a factory, this changes bytecode verification")
                        .action(ArgAction::SetTrue)
                )
                .arg(
                    Arg::with_name("implementationenv")
                        .long("implementationenv")
                        .help("Implementation project's development environment")
                        .value_parser(clap::value_parser!(Environment))
                        .default_value(Environment::Foundry.to_string().as_str())
                        .action(ArgAction::Set)
                )
                .arg(
                    Arg::with_name("implementationartifacts")
                        .long("implementationartifacts")
                        .help("Folder containing the artifacts of the implementation project relative to the project folder (Hardhat only)")
                        .action(ArgAction::Set)
                        .default_value("artifacts")
                )
                .arg(
                    Arg::with_name("env")
                        .long("env")
                        .help("Project's development environment")
                        .value_parser(clap::value_parser!(Environment))
                        .default_value(Environment::Foundry.to_string().as_str())
                        .action(ArgAction::Set)
                )
                .arg(
                    Arg::with_name("artifacts")
                        .long("artifacts")
                        .help("Folder containing the artifacts relative to the project folder (Hardhat only)")
                        .action(ArgAction::Set)
                        .default_value("artifacts")
                )
                .arg(
                    Arg::with_name("buildcache")
                        .long("buildcache")
                        .help("Folder containing build-info files")
                        .action(ArgAction::Set)
                )
                .arg(
                    Arg::with_name("implementationbuildcache")
                        .long("implementationbuildcache")
                        .help("Folder containing build-info files of the implementation contract")
                        .action(ArgAction::Set)
                )
                .arg(
                    Arg::with_name("OUTPUT")
                        .help("Path of the generated DVF file")
                        .required(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("id")
                .about("generates the dvf id")
                .arg(
                    Arg::with_name("DVF")
                        .help("The provided DVF file - updated in-place")
                ),
        )
        .subcommand(
            SubCommand::with_name("add-reference")
                .about("add a reference")
                .arg(
                    Arg::with_name("id")
                        .long("id")
                        .help("Specifies the new reference ID")
                        .required(true)
                        .validator(is_valid_32_byte_hex)
                        .action(ArgAction::Set),
                )
                .arg(
                    Arg::with_name("contractname")
                        .long("contractname")
                        .help("Contract Name of the reference")
                        .required(true)
                        .action(ArgAction::Set),
                )
                .arg(
                    Arg::with_name("DVF")
                        .help("The DVF file - updated in-place")
                        .required(true)
                ),
        )
        .subcommand(
            SubCommand::with_name("sign").about("sign a dvf").arg(
                Arg::with_name("DVF")
                    .help("The DVF file - updated in-place")
                    .required(true)
            ),
        )
        .subcommand(
            SubCommand::with_name("validate")
                .about("validate a dvf")
                .arg(
                    Arg::with_name("validationblock")
                        .long("validationblock")
                        .help("The block number that should be used for validation. Current block if not set. Its final state is used.")
                        .validator(is_valid_blocknum)
                        .action(ArgAction::Set),
                )
                .arg(
                    Arg::with_name("allowuntrusted")
                        .long("allowuntrusted")
                        .help("Allow the validation of unsigned DVFs or DVFs from untrusted signers")
                        .action(ArgAction::SetTrue)
                )
                .arg(
                    Arg::with_name("DVF")
                        .help("The DVF file")
                        .required(true)
                ),
        )
        .subcommand(
            SubCommand::with_name("update")
                .about("update a dvf")
                .arg(
                    Arg::with_name("validationblock")
                        .long("validationblock")
                        .help("The block number that should be used for validation. Current block if not set. Its final state is used.")
                        .validator(is_valid_blocknum)
                        .action(ArgAction::Set),
                )
                .arg(
                    Arg::with_name("DVF")
                        .help("The DVF file")
                ),
        )
        .subcommand(SubCommand::with_name("generate-config")
                .about("interactively generate configuration file")
        )
        .subcommand(SubCommand::with_name("generate-build-cache").about("generate the build cache")
                .arg(
                    Arg::with_name("project")
                        .long("project")
                        .help("Path to the root folder of source code project")
                        .required(true)
                        .validator(is_valid_path)
                        .action(ArgAction::Set),
                )
                .arg(
                    Arg::with_name("env")
                        .long("env")
                        .help("Project's development environment")
                        .value_parser(clap::value_parser!(Environment))
                        .default_value(Environment::Foundry.to_string().as_str())
                        .action(ArgAction::Set)
                )
                .arg(
                    Arg::with_name("artifacts")
                        .long("artifacts")
                        .help("Folder containing the artifacts (Hardhat only)")
                        .default_value("artifacts")
                        .action(ArgAction::Set)
                )
        )
        .subcommand(SubCommand::with_name("bytecode-check").about("perform just the bytecode check")
                .arg(
                    Arg::with_name("initblock")
                        .long("initblock")
                        .help("The block number at which the code should be queried, if not set current block is used.")
                        .validator(is_valid_blocknum)
                        .action(ArgAction::Set),
                )
                .arg(
                    Arg::with_name("project")
                        .long("project")
                        .help("Path to the root folder of source code project")
                        .required(true)
                        .validator(is_valid_path)
                        .action(ArgAction::Set),
                )
                .arg(
                    Arg::with_name("address")
                        .long("address")
                        .help("Address of the contract")
                        .required(true)
                        .validator(is_valid_address)
                        .action(ArgAction::Set),
                )
                .arg(
                    Arg::with_name("chainid")
                        .long("chainid")
                        .help("Chain ID where contract is deployed")
                        .value_parser(value_parser!(u64))
                        .default_value("1")
                        .action(ArgAction::Set),
                )
                .arg(
                    Arg::with_name("contractname")
                        .long("contractname")
                        .help("Name of the contract")
                        .required(true)
                        .action(ArgAction::Set),
                )
                .arg(
                    Arg::with_name("factory")
                        .long("factory")
                        .help("Treat this contract as a factory, this changes bytecode verification")
                        .action(ArgAction::SetTrue)
                )
                .arg(
                    Arg::with_name("env")
                        .long("env")
                        .help("Project's development environment")
                        .value_parser(clap::value_parser!(Environment))
                        .default_value(Environment::Foundry.to_string().as_str())
                        .action(ArgAction::Set)
                )
                .arg(
                    Arg::with_name("artifacts")
                        .long("artifacts")
                        .help("Folder containing the artifacts (Hardhat only)")
                        .default_value("artifacts")
                        .action(ArgAction::Set)
                )
                .arg(
                    Arg::with_name("buildcache")
                        .long("buildcache")
                        .help("Folder containing build-info files")
                        .action(ArgAction::Set)
                )
        )
        .get_matches();
    */

    match matches.get_count("verbose") {
        0 => {} // Normal verbosity
        1 => {
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::INFO)
                .init();
        }
        _ => {
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .init();
        }
    };

    match process(matches) {
        Ok(()) => exit(0),
        Err(ValidationError::Error(e)) => {
            println!("{} {}", "Error occurred:".yellow(), e.yellow());
            exit(1);
        }
        Err(ValidationError::Insecure(e)) => {
            println!(
                "{} {}",
                "Error. Insecure Contract found:".yellow(),
                e.yellow()
            );
            exit(1);
        }
        Err(ValidationError::Invalid(e)) => {
            println!("{} {}", "Error. Deployment invalid:".yellow(), e.yellow());
            exit(1);
        }
        Err(ValidationError::NoDVFFound(e)) => {
            println!("{} {}", "Error. DVF(s) missing:".yellow(), e.yellow());
            exit(1);
        }
    };
}

enum ProgressMode {
    Init,
    InitProxy,
    Update,
    Validation,
    BytecodeCheck,
    GenerateBuildCache,
}

fn updated_filename(original_path: &Path) -> PathBuf {
    // Extract the directory and name
    let parent = original_path.parent().unwrap_or_else(|| Path::new(""));
    let file_name = original_path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new(""))
        .to_string_lossy();
    let name = file_name.split(".dvf.json").next();

    // Create a new stem with "_updated" added.
    let updated_name = format!("{}_updated", name.unwrap_or(""));

    // Assemble the new path.
    let mut updated_path = PathBuf::from(parent);
    updated_path.push(updated_name);
    updated_path.set_extension("dvf.json");
    updated_path
}

fn print_progress(s: &str, i: &mut u64, pm: &ProgressMode) {
    let total = match pm {
        ProgressMode::InitProxy => 14,
        ProgressMode::Init => 12,
        ProgressMode::Update => 4,
        ProgressMode::Validation => 5,
        ProgressMode::BytecodeCheck => 3,
        ProgressMode::GenerateBuildCache => 1,
    };
    println!("{} {}", style(format!("[{i:2}/{total:2}]")).bold().dim(), s);
    *i += 1;
}

fn get_project_paths(project: &Path, artifacts: &str) -> PathBuf {
    // no way to access other clap arguments during argument parsing so we have to verify
    // artifacts paths here
    let build_info_dir = "build-info";
    let mut artifacts_path = project.to_path_buf();
    artifacts_path.push(artifacts);
    artifacts_path.push(build_info_dir);

    artifacts_path
}

fn process(matches: ArgMatches) -> Result<(), ValidationError> {
    let mut config = DVFConfig::from_matches(&matches)?;
    // Check which subcommand was used
    match matches.subcommand() {
        Some(("init", sub_m)) => {
            println!("Starting information gathering. This might take several minutes.");

            let env = *sub_m.get_one::<Environment>("env").unwrap();
            let project = sub_m.get_one::<PathBuf>("project").unwrap();
            let artifacts = sub_m.get_one::<String>("artifacts").unwrap();
            let build_cache = sub_m.get_one::<String>("buildcache");
            let artifacts_path = get_project_paths(project, artifacts);

            let mut imp_env = *sub_m.get_one::<Environment>("implementationenv").unwrap();
            let imp_project = sub_m.get_one::<PathBuf>("implementationproject");
            let mut imp_build_cache = sub_m.get_one::<String>("implementationbuildcache");
            let imp_artifacts = sub_m.get_one::<String>("implementationartifacts").unwrap();
            let imp_path: PathBuf;
            let imp_artifacts_path: PathBuf;
            if let Some(imp_project) = imp_project {
                imp_artifacts_path = get_project_paths(imp_project, imp_artifacts);
                imp_path = imp_project.clone();
            } else {
                imp_path = project.clone();
                imp_artifacts_path = artifacts_path.clone();
                imp_build_cache = build_cache;
                imp_env = env
            }

            let user_output_path = Path::new(sub_m.get_one::<String>("OUTPUT").unwrap());
            // This is just a file name so we will place it in the configured folder
            let output_path: &Path = if is_filename_only_path(user_output_path) {
                &make_relative_to_dvf_storage(&config, user_output_path)
            } else {
                if !user_output_path.starts_with(&config.dvf_storage) {
                    println!("If you want to reference your generated DVF in another DVF, you need to place it in the configured directory.");
                }
                user_output_path
            };

            let mut dumped = parse::CompleteDVF::from_cli(sub_m)?;
            config.set_chain_id(dumped.chain_id)?;

            let registry = registry::Registry::from_config(&config)?;
            let pretty_printer = PrettyPrinter::new(&config, Some(&registry));

            // Parse optional initblock or take deployment_block_num + 1
            let (deployment_block_num, deployment_tx) =
                web3::get_deployment(&config, &dumped.address)?;
            info!("Deployment Block: {}", deployment_block_num);
            dumped.deployment_block_num = deployment_block_num;
            dumped.deployment_tx = deployment_tx;

            let init_block_num = *sub_m
                .get_one::<u64>("initblock")
                .unwrap_or(&(deployment_block_num + 1));
            dumped.init_block_num = init_block_num;

            let mut pc = 1_u64;
            let progress_mode: ProgressMode =
                match sub_m.get_one::<String>("implementation").is_some() {
                    true => ProgressMode::InitProxy,
                    false => ProgressMode::Init,
                };

            print_progress("Getting code hash.", &mut pc, &progress_mode);
            let rpc_code_hash = web3::get_eth_codehash(&config, &dumped.address, init_block_num)?;
            dumped.codehash = rpc_code_hash;

            print_progress("Fetching on-chain bytecode.", &mut pc, &progress_mode);
            let rpc_code = web3::get_eth_code(&config, &dumped.address, init_block_num)?;
            // Bytecode and Immutable check

            print_progress("Fetching init code.", &mut pc, &progress_mode);
            let init_code = web3::get_init_code(&config, &dumped.deployment_tx, &dumped.address)?;

            debug!("Fetching forge output");
            let compile_output = match build_cache {
                None => "Compiling local code.",
                Some(_) => "Loading build cache.",
            };
            print_progress(compile_output, &mut pc, &progress_mode);
            let mut project_info = ProjectInfo::new(
                &dumped.contract_name,
                project,
                env,
                &artifacts_path,
                build_cache,
            )?;

            print_progress("Comparing bytecode.", &mut pc, &progress_mode);
            let factory_mode = sub_m.get_flag("factory");
            let compare_status =
                CompareBytecode::compare(&mut project_info, factory_mode, &rpc_code);

            if !compare_status.matched {
                if matches.get_count("verbose") > 0 {
                    let mut error_info_table = Table::new();
                    verify_bytecode::write_out_bytecodes(
                        &project_info,
                        &rpc_code,
                        &mut error_info_table,
                    );
                    error_info_table.printstd();
                    return Err(ValidationError::from(
                        "Generation Failed. Bytecode mismatch. Consider running with --factory if this is a factory contract.",
                    ));
                } else {
                    return Err(ValidationError::from(
                        "Generation Failed. Bytecode mismatch. Run in verbose mode for more info.",
                    ));
                }
            }

            print_progress("Comparing init code.", &mut pc, &progress_mode);
            let compare_init =
                CompareInitCode::compare(&mut project_info, &init_code, factory_mode);
            if !compare_init.matched {
                return Err(ValidationError::Error(format!(
                    "Init code not matched for contract {:?}",
                    dumped.address
                )));
            }
            // immutable values are set in CompareBytecode::compare so this has to be after the call
            dumped.copy_immutables(&project_info, &pretty_printer);

            debug!("Copying parsed constructor arguments to dvf file");
            dumped.copy_constructor_args(&project_info, &pretty_printer);

            print_progress("Getting storage snapshot.", &mut pc, &progress_mode);
            let mut snapshot = web3::StorageSnapshot::from_api(
                &config,
                &dumped.address,
                deployment_block_num,
                init_block_num,
            )?;

            if init_block_num < deployment_block_num {
                return Err(ValidationError::Error(format!(
                    "Deployment Block {} is bigger than snapshot block {}.",
                    deployment_block_num, init_block_num
                )));
            }

            print_progress("Obtaining storage layout.", &mut pc, &progress_mode);
            // Fetch storage layout
            let layout = forge_inspect::ForgeInspect::generate_and_parse_layout(
                project,
                &dumped.contract_name,
                project_info.absolute_path.clone(),
            );
            let mut contract_state =
                ContractState::new_with_address(&dumped.address, &pretty_printer);
            contract_state.add_forge_inspect(&layout);

            // Proxy Mode
            let mut storage: Vec<StateVariable> = project_info.storage.clone();
            let mut types: HashMap<String, TypeDescription> = project_info.types.clone();
            let mut imp_project_info: Option<ProjectInfo> = None;
            if let Some(implementation_name) = sub_m.get_one::<String>("implementation") {
                print_progress(
                    "Obtaining ABI of implementation contract.",
                    &mut pc,
                    &progress_mode,
                );
                let tmp_project_info = ProjectInfo::new(
                    &implementation_name.to_string(),
                    &imp_path,
                    imp_env,
                    &imp_artifacts_path,
                    imp_build_cache,
                )?;

                print_progress(
                    "Obtaining storage layout of implementation contract.",
                    &mut pc,
                    &progress_mode,
                );
                let implementation_layout = forge_inspect::ForgeInspect::generate_and_parse_layout(
                    &imp_path,
                    implementation_name,
                    tmp_project_info.absolute_path.clone(),
                );
                contract_state.add_forge_inspect(&implementation_layout);

                storage.extend(tmp_project_info.storage.clone());
                types.extend(tmp_project_info.types.clone());
                imp_project_info = Some(tmp_project_info);
            }
            print_progress("Getting relevant traces.", &mut pc, &progress_mode);
            // TODO: Use this elsewhere also
            let tx_hashes: Vec<String> = web3::get_all_txs_for_contract(
                &config,
                &dumped.address,
                deployment_block_num,
                init_block_num,
            )?;
            let mut seen_transactions = HashSet::new();
            let mut missing_traces = false;
            for tx_hash in &tx_hashes {
                if seen_transactions.contains(tx_hash) {
                    continue;
                }
                seen_transactions.insert(tx_hash);
                info!("Getting trace for {}", tx_hash);
                let mut found_trace = true;
                if let Ok(trace) = web3::get_eth_debug_trace(&config, tx_hash) {
                    if contract_state.record_traces(&config, vec![trace]).is_err() {
                        found_trace = false;
                        missing_traces = true;
                    }
                } else {
                    found_trace = false;
                    missing_traces = true;
                }
                if !found_trace {
                    info!("Warning. The trace for {tx_hash} cannot be obtained. Some mapping slots might not be decodable. You can try to increase the timeout in the config.");
                }
            }

            if missing_traces {
                println!("{}", "Warning. At least one transaction trace could not be obtained. This might result in \"unknown\" storage slots due to undecoded mapping keys.".yellow())
            }

            print_progress("Parsing storage snapshot.", &mut pc, &progress_mode);
            let mut storage_var_table = Table::new();
            let critical_storage_variables: Vec<parse::DVFStorageEntry> = contract_state
                .get_critical_storage_variables(
                    &mut snapshot,
                    &mut storage_var_table,
                    &storage,
                    &types,
                )?;

            let mut proxy_warning = critical_storage_variables
                .iter()
                .any(|var| var.var_name == "unknown");

            dumped.critical_storage_variables = critical_storage_variables;

            let mut critical_events: Vec<parse::DVFEventEntry> = vec![];

            print_progress("Obtaining past events.", &mut pc, &progress_mode);
            let seen_events = web3::get_eth_events(
                &config,
                &dumped.address,
                deployment_block_num,
                init_block_num,
                &vec![],
            )?;

            let mut covered_events = 0;
            let mut event_table = Table::new();

            print_progress("Decoding events.", &mut pc, &progress_mode);

            // Collect all Event Types, making sure to avoid duplications
            // Event does not implement PartialEq
            let all_events = match &imp_project_info {
                None => project_info.events.clone(),
                Some(imp_project) => {
                    let mut set_of_sigs: HashSet<B256> = HashSet::new();
                    let mut res: Vec<Event> = vec![];
                    for eventlist in [&project_info.events, &imp_project.events] {
                        for event in eventlist {
                            let sig = event.selector();
                            if set_of_sigs.contains(&sig) {
                                info!(
                                    "Warning. Event {} omitted, as it is already known.",
                                    PrettyPrinter::event_to_string(event)
                                );
                                continue;
                            }
                            set_of_sigs.insert(sig);
                            debug!(
                                "Adding event {} to list.",
                                PrettyPrinter::event_to_string(event)
                            );

                            res.push(event.clone());
                        }
                    }
                    res
                }
            };
            for abi_event in &all_events {
                let sig = PrettyPrinter::event_to_string(abi_event);
                debug!("Found the following event: {}", sig);
                let topic0 = abi_event.selector();
                debug!("Topic0: {:?}", topic0);
                let mut table_head = false;

                // Collect Occurrences
                let mut occurrences: Vec<parse::DVFEventOccurrence> = vec![];
                for seen_event in &seen_events {
                    if seen_event.topic0() == Some(&topic0) {
                        let log_inner = &seen_event.inner;
                        let decoded_event = abi_event.decode_log(log_inner)?;
                        let pretty_event =
                            pretty_printer.pretty_event_params(abi_event, &decoded_event, true);

                        // Add Event Name to table
                        if !table_head {
                            event_table.add_row(row![sig]);
                            table_head = true;
                        }
                        // Add Event Occurrence to table
                        event_table.add_row(row![format!("- {}", pretty_event)]);

                        let occurrence = parse::DVFEventOccurrence {
                            topics: log_inner.data.topics().to_vec(),
                            data: log_inner.data.data.clone(),
                        };
                        occurrences.push(occurrence);
                        covered_events += 1;
                    }
                }

                let event_entry = parse::DVFEventEntry {
                    sig: sig.clone(),
                    topic0,
                    occurrences,
                };
                critical_events.push(event_entry);
            }
            if covered_events != seen_events.len() {
                proxy_warning = true;
                println!(
                    "Warning! Saw {} events, but able to decode {}.",
                    seen_events.len(),
                    covered_events
                );
                let used_topics_0: HashSet<B256> =
                    all_events.iter().map(|e| e.selector()).collect();
                let all_topics_0: HashSet<B256> =
                    seen_events.iter().map(|e| *e.topic0().unwrap()).collect();
                for unused_topic in all_topics_0.difference(&used_topics_0) {
                    // Collect Occurrences
                    let mut occurrences: Vec<parse::DVFEventOccurrence> = vec![];
                    for seen_event in &seen_events {
                        let log_inner = &seen_event.inner;
                        if seen_event.topic0() == Some(unused_topic) {
                            let occurrence = parse::DVFEventOccurrence {
                                topics: log_inner.data.topics().to_vec(),
                                data: log_inner.data.data.clone(),
                            };
                            occurrences.push(occurrence);
                        }
                    }
                    let event_entry = parse::DVFEventEntry {
                        sig: String::from("Unknown Signature"),
                        topic0: *unused_topic,
                        occurrences,
                    };
                    critical_events.push(event_entry);
                }
            }
            dumped.critical_events = critical_events;

            pc = 1;
            println!();
            println!("DVF Initialization complete. Please follow these steps:");

            if project_info.compiler_version < FIRST_STORAGE_LAYOUT {
                println!(
                    "{}. Warning. You are using an old compiler without storage layout. There will be no storage decoding.", pc
                );
                pc += 1;
            } else if proxy_warning && imp_project_info.is_none() {
                println!(
                    "{}. Warning. Not everything could be decoded. This could be because this is a proxy contract. In that case use --implementation to decode more.", pc
                );
                pc += 1;
            }

            println!("{pc}. Validate that the results in the table below are as expected.");
            pc += 1;
            verify_bytecode::print_generation_summary(
                &project.to_string_lossy().to_string(),
                &dumped.contract_name,
                &dumped.address,
                compare_status,
                &project_info,
                &rpc_code,
                &pretty_printer,
            );
            if !dumped.critical_storage_variables.is_empty() {
                println!(
                    "{}. Select critical storage variables by deleting the others from {}.",
                    pc,
                    output_path.display()
                );
                pc += 1;

                if storage_var_table.is_empty() {
                    println!("    No values were decoded, this could be because it is a proxy contract or because of an old compiler version.");
                } else {
                    println!("    Below you see decoded values for non-zero storage variables:");
                    storage_var_table.printstd();
                }
            }

            if !all_events.is_empty() {
                println!(
                    "{}. Select critical events by deleting the others from {}",
                    pc,
                    output_path.display()
                );
                pc += 1;

                if event_table.is_empty() {
                    println!(
                        "   No events occurred up until block {}.",
                        deployment_block_num
                    );
                } else {
                    println!("   Event occurrences up to block {}:", deployment_block_num);
                    event_table.printstd();
                }
            }

            println!(
                "{}. Decide whether you want to signal that the contract is insecure, if so set the insecure flag to true.", pc
            );
            pc += 1;

            println!(
                "{}. Decide if this validation should have an expiry date. Also you can fill in additional, unvalidated metadata.", pc
            );

            dumped.generate_id()?;
            dumped.write_to_file(output_path)?;
            println!("Wrote DVF to {}!", output_path.display());
            exit(0);
        }
        Some(("id", sub_m)) => {
            let input_path: PathBuf =
                parse_input_path(&config, sub_m.get_one::<String>("DVF").unwrap())?;
            let mut filled = parse::CompleteDVF::from_path(input_path.as_path())?;

            filled.generate_id()?;

            filled.write_to_file(input_path.as_path())?;
            println!("Wrote to file: {}", input_path.display());
            exit(0);
        }
        Some(("add-reference", sub_m)) => {
            let input_path: PathBuf =
                parse_input_path(&config, sub_m.get_one::<String>("DVF").unwrap())?;
            let mut filled = parse::CompleteDVF::from_path(&input_path)?;
            let new_ref_id = sub_m.get_one::<String>("id").unwrap();
            let new_ref_name = sub_m.get_one::<String>("contractname").unwrap().to_string();
            filled.add_reference(new_ref_id, &new_ref_name);
            filled.generate_id()?;
            filled.clear_signature_data();
            filled.write_to_file(input_path.as_path())?;
            println!("Wrote to file: {}", input_path.display());
            exit(0);
        }
        Some(("sign", sub_m)) => {
            let input_path: PathBuf =
                parse_input_path(&config, sub_m.get_one::<String>("DVF").unwrap())?;
            let mut filled = parse::CompleteDVF::from_path(&input_path)?;

            filled.sign(&config)?;
            // Regenerate ID
            filled.write_to_file(input_path.as_path())?;
            println!("Wrote signed DVF to file: {}", input_path.display());
            exit(0);
        }
        Some(("validate", sub_m)) => {
            let input_path: PathBuf =
                parse_input_path(&config, sub_m.get_one::<String>("DVF").unwrap())?;
            let filled = match parse::CompleteDVF::from_path(&input_path) {
                Ok(filled) => filled,
                Err(e) => {
                    println!(
                        "Validation, because the DVF file could not be parsed: {:?}",
                        e
                    );
                    exit(1);
                }
            };

            config.set_chain_id(filled.chain_id)?;

            let registry = registry::Registry::from_config(&config)?;
            let allow_untrusted = sub_m.get_flag("allowuntrusted");
            let continue_on_mismatch = sub_m.get_flag("continue");

            let validation_block_num: u64 = *sub_m
                .get_one::<u64>("validationblock")
                .unwrap_or(&web3::get_eth_block_number(&config)?);

            match validate_dvf(
                &config,
                &input_path,
                validation_block_num,
                &registry,
                &mut HashSet::new(),
                allow_untrusted,
                continue_on_mismatch,
                None,
            ) {
                Ok(()) => {
                    println!(
                        "Validation of {} succeeded based on block {}.",
                        input_path.display(),
                        validation_block_num
                    );
                    exit(0);
                }
                Err(ValidationError::Error(e)) => {
                    println!(
                        "Validation of {} failed because of an error: {}",
                        input_path.display(),
                        e
                    );
                    exit(1);
                }
                Err(ValidationError::Insecure(e)) => {
                    println!(
                        "Validation of {} failed. Insecure Contract found: {}",
                        input_path.display(),
                        e
                    );
                    exit(1);
                }
                Err(ValidationError::Invalid(e)) => {
                    println!(
                        "Validation of {} failed. Deployment invalid: {}",
                        input_path.display(),
                        e
                    );
                    exit(1);
                }
                Err(ValidationError::NoDVFFound(e)) => {
                    println!(
                        "Validation of {} failed. DVF(s) missing: {}",
                        input_path.display(),
                        e
                    );
                    exit(1);
                }
            };
        }
        Some(("update", sub_m)) => {
            let input_path: PathBuf =
                parse_input_path(&config, sub_m.get_one::<String>("DVF").unwrap())?;

            println!("input path {}", input_path.display());
            let mut pc = 1_u64;
            let progress_mode = ProgressMode::Update;
            print_progress("Loading file.", &mut pc, &progress_mode);

            let filled = parse::CompleteDVF::from_path(&input_path)?;
            let mut updated = filled.clone();

            // Validate ChainID
            config.set_chain_id(filled.chain_id)?;

            let validation_block_num = *sub_m
                .get_one::<u64>("validationblock")
                .unwrap_or(&web3::get_eth_block_number(&config)?);

            if validation_block_num < filled.deployment_block_num {
                return Err(ValidationError::from(
                    "Validation block is before Deployment Block.",
                ));
            }

            if filled.init_block_num < filled.deployment_block_num {
                return Err(ValidationError::from(
                    "Validation block is before Init Block.",
                ));
            }

            print_progress("Checking Codehash.", &mut pc, &progress_mode);
            // Validate Codehash
            let rpc_code_hash =
                web3::get_eth_codehash(&config, &filled.address, validation_block_num)?;
            if rpc_code_hash != filled.codehash {
                println!("Mismatched codehash.");
                updated.codehash = rpc_code_hash;
            }

            print_progress("Checking Storage Variables.", &mut pc, &progress_mode);
            // Validate Storage slots
            for storage_variable in updated.critical_storage_variables.iter_mut() {
                let current_val = web3::get_eth_storage_at(
                    &config,
                    &filled.address,
                    &storage_variable.slot,
                    validation_block_num,
                )?;
                let size: usize = storage_variable.value.len();
                let start_index: usize = 32 - (storage_variable.offset + size);
                let end_index: usize = 32 - storage_variable.offset;
                if current_val[start_index..end_index] != storage_variable.value {
                    println!(
                        "Different value for {} (slot {:#x}, offset {})\nOld value was: 0x{}\nNew value is:  0x{}.",
                        &storage_variable.var_name,
                        &storage_variable.slot,
                        &storage_variable.offset,
                        hex::encode(&storage_variable.value),
                        hex::encode(&current_val[start_index..end_index])
                    );
                    storage_variable.value = current_val[start_index..end_index].to_vec();
                    storage_variable.value_hint = None;
                }
            }

            print_progress("Checking Events.", &mut pc, &progress_mode);
            // Validate events
            for critical_event in updated.critical_events.iter_mut() {
                let seen_events = web3::get_eth_events(
                    &config,
                    &filled.address,
                    filled.deployment_block_num,
                    validation_block_num,
                    &vec![critical_event.topic0],
                )?;
                let mut replace_events = false;
                if seen_events.len() != critical_event.occurrences.len() {
                    println!(
                        "Old DVF had {} occurrences of event {}, but new should have {}.",
                        critical_event.occurrences.len(),
                        critical_event.sig,
                        seen_events.len()
                    );
                    replace_events = true;
                }

                let num_shared = std::cmp::min(seen_events.len(), critical_event.occurrences.len());
                #[allow(clippy::needless_range_loop)]
                for i in 0..num_shared {
                    let log_innner = &seen_events[i].inner;
                    if log_innner.topics() != critical_event.occurrences[i].topics {
                        println!(
                            "Mismatching topics for event occurrence {} of {}.",
                            i, critical_event.sig
                        );
                        replace_events = true;
                    }
                    if log_innner.data.data != critical_event.occurrences[i].data {
                        println!(
                            "Mismatching data for event occurrence {} of {}.",
                            i, critical_event.sig
                        );
                        replace_events = true;
                    }
                }
                if replace_events {
                    // Collect Occurrences
                    let mut occurrences: Vec<parse::DVFEventOccurrence> = vec![];
                    for seen_event in &seen_events {
                        let log_inner = &seen_event.inner;
                        let occurrence = parse::DVFEventOccurrence {
                            topics: log_inner.data.topics().to_vec(),
                            data: log_inner.data.data.clone(),
                        };
                        occurrences.push(occurrence);
                    }
                    critical_event.occurrences = occurrences;
                }
            }
            updated.clear_id();
            updated.clear_signature();
            // Change file name to "_updated"
            let mut output_path: PathBuf = input_path.to_path_buf();

            println!("output path {}", output_path.display());
            loop {
                output_path = updated_filename(&output_path);
                if !output_path.exists() {
                    break;
                }
            }
            updated.write_to_file(&output_path)?;
            println!("Wrote the updated file to file: {}", output_path.display());
            println!(
                "{}: Arrays are not properly supported in the update mode.",
                "Warning".yellow()
            );
            println!("Note that 'update' will just update existing storage variables and events. If new critical variables or events were introduced, they need to be added manually.");
            Ok(())
        }
        Some(("generate-config", _sub_m)) => {
            let newconfig = DVFConfig::from_interactive_cli()?;
            let default_path = DVFConfig::default_path();

            println!();
            println!(
                "{}",
                "Your configuration has been generated successfully".green()
            );
            println!();
            println!("{}", "STEP 8".green());
            loop {
                println!("Please enter the directory where your config should be stored.");
                println!(
                    "Hit {} to use default value: {}",
                    "<Enter>".green(),
                    default_path.display()
                );
                print!("> ");

                let mut input = String::new();
                let _ = std::io::Write::flush(&mut std::io::stdout());
                io::stdin().read_line(&mut input).unwrap();

                if input.trim().is_empty() {
                    if newconfig.write_to_file(&default_path).is_ok() {
                        break;
                    } else {
                        println!("{}", "Error writing to the provided file.".yellow());
                        continue;
                    }
                }

                let mut path_str = String::new();
                if sscanf!(&input, "{}", path_str).is_ok() {
                    if let Ok(path) = replace_tilde(path_str.trim()) {
                        if newconfig.write_to_file(&path).is_ok() {
                            break;
                        } else {
                            println!("{}", "Error writing to the provided file.".yellow());
                        }
                    }
                } else {
                    println!("{}", "The provided path could not be parsed.".yellow());
                }
            }

            Ok(())
        }
        Some(("generate-build-cache", sub_m)) => {
            println!("Generating Build Cache.");

            let env = *sub_m.get_one::<Environment>("env").unwrap();
            let project = sub_m.get_one::<PathBuf>("project").unwrap();
            let artifacts = sub_m.get_one::<String>("artifacts").unwrap();
            let artifacts_path = get_project_paths(project, artifacts);

            let mut pc = 1_u64;
            let progress_mode: ProgressMode = ProgressMode::GenerateBuildCache;

            // Bytecode and Immutable check
            print_progress("Compiling local bytecode.", &mut pc, &progress_mode);

            let build_cache_path = ProjectInfo::compile(project, env, &artifacts_path)?;

            println!("Build Cache: {}", build_cache_path.display());
            exit(0);
        }
        Some(("bytecode-check", sub_m)) => {
            println!("Starting bytecode check.");

            let env = *sub_m.get_one::<Environment>("env").unwrap();
            let project = sub_m.get_one::<PathBuf>("project").unwrap();
            let artifacts = sub_m.get_one::<String>("artifacts").unwrap();
            let artifacts_path = get_project_paths(project, artifacts);

            let contract_name = sub_m.get_one::<String>("contractname").unwrap().to_string();
            let address = sub_m.get_one::<Address>("address").unwrap();
            let build_cache = sub_m.get_one::<String>("buildcache");
            let chain_id = *sub_m.get_one("chainid").unwrap();

            config.set_chain_id(chain_id)?;

            // Parse optional initblock or take deployment_block_num + 1
            let deployment_block_num = web3::get_deployment_block(&config, address)?;
            info!("Deployment Block: {}", deployment_block_num);

            let init_block_num = *sub_m
                .get_one::<u64>("initblock")
                .unwrap_or(&web3::get_eth_block_number(&config)?);

            let mut pc = 1_u64;
            let progress_mode: ProgressMode = ProgressMode::BytecodeCheck;

            print_progress("Fetching on-chain bytecode.", &mut pc, &progress_mode);
            let rpc_code = web3::get_eth_code(&config, address, init_block_num)?;
            // Bytecode and Immutable check
            print_progress("Compiling local bytecode.", &mut pc, &progress_mode);

            let mut project_info =
                ProjectInfo::new(&contract_name, project, env, &artifacts_path, build_cache)?;

            print_progress("Comparing bytecode.", &mut pc, &progress_mode);
            let factory_mode = sub_m.get_flag("factory");
            let compare_status =
                CompareBytecode::compare(&mut project_info, factory_mode, &rpc_code);

            if !compare_status.matched {
                if matches.get_count("verbose") > 0 {
                    let mut error_info_table = Table::new();
                    verify_bytecode::write_out_bytecodes(
                        &project_info,
                        &rpc_code,
                        &mut error_info_table,
                    );
                    error_info_table.printstd();
                    return Err(ValidationError::from(
                        "Bytecode Check Failed. Bytecode mismatch. Consider running with --factory if this is a factory contract.",
                    ));
                } else {
                    return Err(ValidationError::from(
                        "Bytecode Check Failed. Bytecode mismatch. Run in verbose mode for more info.",
                    ));
                }
            }

            println!();
            if !compare_status.metadata_matched {
                println!("Info: Metadata was different!");
            }

            println!("Bytecode check succeeded!");
            exit(0);
        }
        _ => Err(ValidationError::Error(
            "Please specify a command.".to_string(),
        )),
    }
}
