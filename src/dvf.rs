use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::str::FromStr;

use alloy::primitives::{Address, B256};
use clap::{arg, value_parser, ArgMatches, Command};
use colored::Colorize;
use dvf_libs::bytecode_verification::compare_bytecodes::{CompareBytecode, CompareInitCode};
use dvf_libs::bytecode_verification::parse_json::{Environment, ProjectInfo};
use dvf_libs::bytecode_verification::verify_bytecode;
use dvf_libs::dvf::config::{replace_tilde, DVFConfig};
use dvf_libs::dvf::discovery::{
    create_discovery_params_for_init, create_discovery_params_for_update,
    discover_storage_and_events, DiscoveryResult,
};
use dvf_libs::dvf::parse::{self, DVFStorageEntry, ValidationError, CURRENT_VERSION_STRING};
use dvf_libs::dvf::registry::{self, Registry};
use dvf_libs::utils::pretty::PrettyPrinter;
use dvf_libs::utils::progress::{print_progress, ProgressMode};
use dvf_libs::utils::read_write_file::get_project_paths;
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

    let pretty_printer = PrettyPrinter::new(config, Some(registry));

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
            let message = get_mismatch_msg(
                &pretty_printer,
                storage_variable,
                &current_val[start_index..end_index],
                true,
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

    let start_block = filled.deployment_block_num;
    let end_block = validation_block_num;
    println!("Max_block per event {}", config.max_blocks_per_event_query);

    // For each critical event
    for critical_event in &filled.critical_events {
        let mut num_occurrences = 0;
        let num_occurrences_expected = critical_event.occurrences.len();

        let mut current_from = start_block;

        // For each block range at most config.max_blocks_per_event_query - 1
        while current_from < end_block {
            let current_to = std::cmp::min(
                current_from + config.max_blocks_per_event_query - 2,
                end_block,
            );

            // Get event logs from `current_from` to `current_to`
            let seen_events = web3::get_eth_events(
                config,
                &filled.address,
                current_from,
                current_to,
                &vec![critical_event.topic0],
            )?;

            // Early quit if num. of occurrences observed so far is already greater than the num. of occurrences expected
            if num_occurrences + seen_events.len() > num_occurrences_expected {
                return Err(ValidationError::Invalid(format!(
                    "Found at least {} occurrences of event {}, but expected {}.",
                    num_occurrences + seen_events.len(),
                    critical_event.sig,
                    num_occurrences_expected
                )));
            }

            // For each occurrence of critical event
            for event in seen_events {
                let expected = &critical_event.occurrences[num_occurrences];
                let log_inner = &event.inner;

                if log_inner.topics() != expected.topics {
                    let message = format!(
                        "Mismatching topics for event occurrence {} of {}.",
                        num_occurrences, critical_event.sig
                    );
                    if continue_on_mismatch {
                        mismatch_found = true;
                        println!("{}", message);
                    } else {
                        return Err(ValidationError::Invalid(message));
                    }
                }

                if log_inner.data.data != expected.data {
                    let message = format!(
                        "Mismatching data for event occurrence {} of {}.",
                        num_occurrences, critical_event.sig
                    );
                    if continue_on_mismatch {
                        mismatch_found = true;
                        println!("{}", message);
                    } else {
                        return Err(ValidationError::Invalid(message));
                    }
                }

                num_occurrences += 1;
            }

            current_from = current_to + 1;
        }

        // if num_occurrences != num_occurrences_expected {
        //     return Err(ValidationError::Invalid(format!(
        //         "Found {} occurrences of event {}, but expected {}.",
        //         num_occurrences, critical_event.sig, num_occurrences_expected
        //     )));
        // }

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
                    arg!(--eventtopics <TOPICS>)
                        .help("Event topics to filter by (comma-separated list)")
                        .value_parser(|s: &str| -> Result<Vec<B256>, String> {
                            if s.trim().is_empty() {
                                return Ok(vec![]);
                            }
                            s.split(',')
                                .map(|topic| {
                                    B256::from_str(topic.trim())
                                        .map_err(|e| format!("Invalid topic: {}", e))
                                })
                                .collect::<Result<Vec<_>, _>>()
                        }),
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
                    arg!(--deployment <TX>)
                        .help("Transaction hash of the deployment transaction")
                        .value_parser(is_valid_32_byte_hex),
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
                .arg(
                    arg!(--zerovalue)
                        .help(
                            "Write initialized storage slots that have been reset to 0 to the DVF",
                        )
                        .action(clap::ArgAction::SetTrue),
                )
                .arg(arg!(--buildcache <PATH>).help("Folder containing build-info files"))
                .arg(
                    arg!(--libraries <LIBRARY> ...)
                        .help("Library specifiers in the form Path:Name:Address. Accepts comma-separated values or repeated flags")
                        .value_delimiter(',')
                        .action(clap::ArgAction::Append),
                )
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
                .arg(
                    arg!(--discover)
                    .help(
                        "Also discover new storage variables and events"
                    ).action(clap::ArgAction::SetTrue)
                )
                .arg(
                    arg!(--project <PATH>)
                        .help("Path to the root folder of the source code project (optional, improves storage layout discovery)")
                        .value_parser(is_valid_path)
                        .requires("discover"),
                )
                .arg(
                    arg!(--artifacts <PATH>)
                        .help("Relative path to the compilation artifacts")
                        .default_value("artifacts")
                        .requires("discover"),
                )
                .arg(
                    arg!(--buildcache <PATH>)
                        .help("Build cache, if you have a very large project")
                        .requires("discover"),
                )
                .arg(
                    arg!(--libraries <LIBRARIES>)
                        .help("Library linking information (address mapping)")
                        .value_parser(value_parser!(String))
                        .action(clap::ArgAction::Append)
                        .requires("discover"),
                )
                .arg(
                    arg!(--env <ENV>)
                        .help("The compile environment")
                        .value_parser(value_parser!(Environment))
                        .default_value("foundry")
                        .requires("discover"),
                )
                .arg(
                    arg!(--implementation <NAME>)
                        .help("Optional name of the implementation contract")
                        .requires("discover"),
                )
                .arg(
                    arg!(--implementationproject <PATH>)
                        .help("Path to the root folder of the implementation project")
                        .value_parser(is_valid_path)
                        .requires("discover"),
                )
                .arg(
                    arg!(--implementationenv <ENV>)
                        .help("Implementation project's development environment")
                        .value_parser(value_parser!(Environment))
                        .default_value("foundry")
                        .requires("discover"),
                )
                .arg(
                    arg!(--implementationartifacts <PATH>)
                        .help("Folder containing the implementation project artifacts")
                        .default_value("artifacts")
                        .requires("discover"),
                )
                .arg(
                    arg!(--implementationbuildcache <PATH>)
                        .help("Folder containing the implementation contract's build-info files")
                        .requires("discover"),
                )
                .arg(
                    arg!(--zerovalue)
                        .help(
                            "Write initialized storage slots that have been reset to 0 to the DVF",
                        )
                        .action(clap::ArgAction::SetTrue),
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
                )
                .arg(
                    arg!(--libraries <LIBRARY> ...)
                        .help("Library specifiers in the form Path:Name:Address. Accepts comma-separated values or repeated flags")
                        .value_delimiter(',')
                        .action(clap::ArgAction::Append),
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
               .arg(
                    arg!(--libraries <LIBRARY> ...)
                        .help("Library specifiers in the form Path:Name:Address. Accepts comma-separated values or repeated flags")
                        .value_delimiter(',')
                        .action(clap::ArgAction::Append),
                )
                .arg(arg!(--buildcache <PATH>).help("Folder containing build-info files")),
        )
        .subcommand(
            Command::new("list-events")
                .about("Lists all event topics of a contract")
                .arg(
                    arg!(--project <PATH>)
                        .help("Path to the root folder of the source code project")
                        .required(true)
                        .value_parser(is_valid_path),
                )
                .arg(
                    arg!(--contractname <NAME>)
                        .help("Name of the contract")
                        .required(true),
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

fn get_mismatch_msg(
    pretty_printer: &PrettyPrinter,
    storage_variable: &DVFStorageEntry,
    current_value_slice: &[u8],
    display_mismatch: bool,
) -> String {
    let var_type = storage_variable.var_type.clone().unwrap_or_default();
    let dec_current_value_slice = pretty_printer.pretty_value_short_from_bytes(
        &var_type,
        &current_value_slice.to_vec(),
        true,
    );
    let dec_old_value =
        pretty_printer.pretty_value_short_from_bytes(&var_type, &storage_variable.value, true);

    let msg = if display_mismatch {
        "Value mismatch"
    } else {
        "Updated value"
    };

    format!(
        "{} for {} (slot {:#x}, offset {}).\nNew value: 0x{} Decoded: {}\nOperator:  {}\nOld value: 0x{} Decoded: {}",
        msg,
        storage_variable.var_name,
        storage_variable.slot,
        storage_variable.offset,
        hex::encode(current_value_slice),
        dec_current_value_slice,
        storage_variable.comparison_operator,
        hex::encode(&storage_variable.value),
        dec_old_value
    )
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
            let libraries = sub_m
                .get_many::<String>("libraries")
                .map(|vals| vals.cloned().collect());
            let event_topics = sub_m
                .get_many::<Vec<B256>>("eventtopics")
                .map(|v| v.flat_map(|x| x.clone()).collect::<Vec<_>>());

            let zerovalue = sub_m.get_flag("zerovalue");
            let user_deployment_tx = sub_m.get_one::<String>("deployment");

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
            let (deployment_block_num, deployment_tx) = if user_deployment_tx.is_some() {
                let (block_num, _, _) =
                    web3::get_transaction_details(&config, user_deployment_tx.unwrap())?;
                (block_num, user_deployment_tx.unwrap().clone())
            } else {
                web3::get_deployment(&config, &dumped.address)?
            };
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
                libraries.clone(),
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

            print_progress("Comparing initcode.", &mut pc, &progress_mode);
            let compare_init =
                CompareInitCode::compare(&mut project_info, &init_code, factory_mode);
            if !compare_init.matched {
                if matches.get_count("verbose") > 0 {
                    let mut error_info_table = Table::new();
                    verify_bytecode::write_out_initcodes(
                        &project_info,
                        &init_code,
                        &mut error_info_table,
                    );
                    error_info_table.printstd();
                } else {
                    println!("Initcode mismatch. Run in verbose mode for more info.");
                }
                return Err(ValidationError::from(
                    "Initcode mismatch. Consider running with --factory if this is a factory contract.",
                ));
            }
            // immutable values are set in CompareBytecode::compare so this has to be after the call
            dumped.copy_immutables(&project_info, &pretty_printer);

            debug!("Copying parsed constructor arguments to dvf file");
            dumped.copy_constructor_args(&project_info, &pretty_printer);

            let DiscoveryResult {
                critical_storage_variables,
                critical_events,
                storage_var_table,
                event_table,
                all_events,
                proxy_warning,
            } = discover_storage_and_events(create_discovery_params_for_init(
                &config,
                &dumped,
                deployment_block_num,
                init_block_num,
                project,
                artifacts,
                env,
                build_cache,
                libraries.clone(),
                zerovalue,
                event_topics,
                sub_m,
                &mut pc,
                &progress_mode,
            ))?;

            dumped.critical_storage_variables = critical_storage_variables;
            dumped.critical_events = critical_events;

            let mut pc = 1;
            println!();
            println!("DVF Initialization complete. Please follow these steps:");

            if project_info.compiler_version < FIRST_STORAGE_LAYOUT {
                println!(
                    "{}. Warning. You are using an old compiler without storage layout. There will be no storage decoding.", pc
                );
                pc += 1;
            } else if proxy_warning && sub_m.get_one::<String>("implementation").is_none() {
                println!(
                    "{}. Warning. Some storage slots could not be decoded. This might happen because this is a proxy contract. In that case, use --implementation to decode more.", pc
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
                    println!("   No events occurred up until block {}.", init_block_num);
                } else {
                    println!("   Event occurrences up to block {}:", init_block_num);
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
            let zerovalue = sub_m.get_flag("zerovalue");

            println!("input path {}", input_path.display());
            let mut pc = 1_u64;

            let discover = sub_m.get_flag("discover");
            println!("running discover mode? {}", discover);

            let progress_mode = if discover {
                ProgressMode::UpdateFull
            } else {
                ProgressMode::Update
            };

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

            if discover {
                let discovery_result =
                    discover_storage_and_events(create_discovery_params_for_update(
                        &config,
                        &updated,
                        validation_block_num,
                        sub_m.get_one::<PathBuf>("project"),
                        sub_m.get_one::<String>("artifacts").unwrap(),
                        *sub_m.get_one::<Environment>("env").unwrap(),
                        sub_m.get_one::<String>("buildcache"),
                        sub_m
                            .get_many::<String>("libraries")
                            .map(|vals| vals.cloned().collect()),
                        zerovalue,
                        sub_m,
                        &mut pc,
                        &progress_mode,
                    ))?;

                updated.init_block_num = validation_block_num;

                // Update existing storage variables and add new ones
                let current_storage_map: HashMap<String, &parse::DVFStorageEntry> =
                    discovery_result
                        .critical_storage_variables
                        .iter()
                        .map(|var| (format!("{:#x}", var.slot), var))
                        .collect();

                // Check for changes in existing storage variables
                for storage_variable in updated.critical_storage_variables.iter_mut() {
                    let slot_key = format!("{:#x}", storage_variable.slot);
                    if let Some(current_var) = current_storage_map.get(&slot_key) {
                        if current_var.value != storage_variable.value {
                            let registry = registry::Registry::from_config(&config)?;
                            let pretty_printer = PrettyPrinter::new(&config, Some(&registry));
                            println!(
                                "{}",
                                get_mismatch_msg(
                                    &pretty_printer,
                                    storage_variable,
                                    &current_var.value,
                                    false
                                )
                            );
                            storage_variable.value = current_var.value.clone();
                            storage_variable.value_hint = current_var.value_hint.clone();
                        }
                    }
                }

                // Add new storage variables
                let existing_slots: HashSet<_> = updated
                    .critical_storage_variables
                    .iter()
                    .map(|var| var.slot)
                    .collect();

                for new_var in discovery_result.critical_storage_variables {
                    if !existing_slots.contains(&new_var.slot) {
                        println!(
                            "Found new storage variable: {} at slot {}",
                            new_var.var_name, new_var.slot
                        );
                        updated.critical_storage_variables.push(new_var);
                    }
                }

                // Update events similarly
                let current_events_map: HashMap<B256, &parse::DVFEventEntry> = discovery_result
                    .critical_events
                    .iter()
                    .map(|event| (event.topic0, event))
                    .collect();

                // Check for changes in existing events
                for critical_event in updated.critical_events.iter_mut() {
                    if let Some(current_event) = current_events_map.get(&critical_event.topic0) {
                        if current_event.occurrences.len() != critical_event.occurrences.len() {
                            println!(
                                "Event {} occurrence count changed from {} to {}",
                                critical_event.sig,
                                critical_event.occurrences.len(),
                                current_event.occurrences.len()
                            );
                            critical_event.occurrences = current_event.occurrences.clone();
                        }
                    }
                }

                // Add new events
                let existing_topics: HashSet<_> = updated
                    .critical_events
                    .iter()
                    .map(|event| event.topic0)
                    .collect();

                for new_event in discovery_result.critical_events {
                    if !existing_topics.contains(&new_event.topic0) {
                        println!(
                            "Found new event: {} with {} occurrences",
                            new_event.sig,
                            new_event.occurrences.len()
                        );
                        updated.critical_events.push(new_event);
                    }
                }
            } else {
                // Fallback: manual storage checking without project info (original approach)
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
                        let registry = registry::Registry::from_config(&config)?;
                        let pretty_printer = PrettyPrinter::new(&config, Some(&registry));
                        println!(
                            "{}",
                            get_mismatch_msg(
                                &pretty_printer,
                                storage_variable,
                                &current_val[start_index..end_index],
                                false
                            )
                        );
                        storage_variable.value = current_val[start_index..end_index].to_vec();

                        if let Some(var_type) = &storage_variable.var_type {
                            storage_variable.value_hint =
                                Some(pretty_printer.pretty_value_short_from_bytes(
                                    var_type,
                                    &storage_variable.value,
                                    false,
                                ));
                        } else {
                            storage_variable.value_hint = None;
                        }
                    }
                }
                if !zerovalue {
                    // Remove storage variables with value 0
                    updated
                        .critical_storage_variables
                        .retain(|var| !var.is_zero());
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

                    let num_shared =
                        std::cmp::min(seen_events.len(), critical_event.occurrences.len());
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
            updated.generate_id()?;
            updated.write_to_file(&output_path)?;
            println!("Wrote the updated file to file: {}", output_path.display());
            println!(
                "{}: Arrays are not properly supported in the update mode.",
                "Warning".yellow()
            );
            if discover {
                println!("Note: For better storage variable naming and value hints, consider using --project and / or -- implementationproject to provide the source code path.");
            }
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
            let libraries = sub_m
                .get_many::<String>("libraries")
                .map(|vals| vals.cloned().collect());

            let mut pc = 1_u64;
            let progress_mode: ProgressMode = ProgressMode::GenerateBuildCache;

            // Bytecode and Immutable check
            print_progress("Compiling local bytecode.", &mut pc, &progress_mode);

            let build_cache_path = ProjectInfo::compile(project, env, &artifacts_path, libraries)?;

            println!("Build Cache: {}", build_cache_path.display());
            exit(0);
        }
        Some(("bytecode-check", sub_m)) => {
            println!("Starting bytecode check.");

            let env = *sub_m.get_one::<Environment>("env").unwrap();
            let project = sub_m.get_one::<PathBuf>("project").unwrap();
            let artifacts = sub_m.get_one::<String>("artifacts").unwrap();
            let artifacts_path = get_project_paths(project, artifacts);
            let libraries = sub_m
                .get_many::<String>("libraries")
                .map(|vals| vals.cloned().collect());

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

            let mut project_info = ProjectInfo::new(
                &contract_name,
                project,
                env,
                &artifacts_path,
                build_cache,
                libraries,
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
        Some(("list-events", sub_m)) => {
            let env = *sub_m.get_one::<Environment>("env").unwrap();
            let project = sub_m.get_one::<PathBuf>("project").unwrap();
            let artifacts = sub_m.get_one::<String>("artifacts").unwrap();
            let artifacts_path = get_project_paths(project, artifacts);
            let libraries = sub_m
                .get_many::<String>("libraries")
                .map(|vals| vals.cloned().collect());

            let contract_name = sub_m.get_one::<String>("contractname").unwrap().to_string();
            let build_cache = sub_m.get_one::<String>("buildcache");

            let mut pc = 1_u64;
            let progress_mode: ProgressMode = ProgressMode::ListEvents;

            print_progress("Compiling local bytecode.", &mut pc, &progress_mode);
            let project_info = ProjectInfo::new(
                &contract_name,
                project,
                env,
                &artifacts_path,
                build_cache,
                libraries,
            )?;

            let mut event_table = Table::new();
            for event in project_info.events {
                event_table.add_row(row![event.name, event.selector()]);
            }
            event_table.printstd();

            println!("Bytecode check succeeded!");
            exit(0);
        }
        _ => Err(ValidationError::Error(
            "Please specify a command.".to_string(),
        )),
    }
}
