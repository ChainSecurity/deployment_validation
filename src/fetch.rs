use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;

use clap::ArgMatches;
use clap::{App, Arg, ArgAction};
use dvf_libs::dvf::config::DVFConfig;
use dvf_libs::dvf::parse::{ValidationError, CURRENT_VERSION};
use ethers_core::abi::Address;
use ethers_core::types::Chain;
use ethers_etherscan::contract::SourceCodeEntry;
use ethers_etherscan::Client;
use ethers_solc::artifacts::Settings;
use semver::Version;
use tokio::runtime::Runtime;
use toml::Table;
use toml::Value;
use tracing::debug;

fn main() {
    let matches = App::new("fetch")
        .version(CURRENT_VERSION.to_string().as_str())
        .about("Fetch from etherscan and create foundry project")
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
                .action(ArgAction::Set),
        )
        .arg(
            Arg::with_name("project")
                .long("project")
                .help("Sets path to foundry")
                .required(true)
                .action(ArgAction::Set),
        )
        .arg(
            Arg::with_name("address")
                .long("address")
                .help("Contract address")
                .required(true)
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::with_name("chainid")
                .long("chainid")
                .help("Chain ID")
                .action(ArgAction::Set),
        )
        .get_matches();

    if matches.get_flag("verbose") {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }
    fetch(&matches).unwrap();
}

// Returns src folder if found
fn parse_sources_foundry(
    sources: &HashMap<String, SourceCodeEntry>,
    foundry_path: &Path,
    settings: &Option<Settings>,
    main_contract_name: &str,
) -> Option<String> {
    let main_contract_file_name = format!("{main_contract_name}.sol");
    let mut src_folder: Option<String> = None;
    // Parse sources
    for (spath, entry) in sources.iter() {
        // Remove weird non-unicode and "../"
        let mut spath = Path::new(spath)
            .to_string_lossy()
            .into_owned()
            .replace("../", "");
        // Avoid absolute paths
        if Path::new(&spath).is_absolute() {
            // TODO handle non-unix systems here
            spath = format!(".{}", spath);
        }

        // 1. Check if main_contract_name
        if Path::new(&spath).file_name().unwrap().to_string_lossy() == main_contract_file_name {
            // 2. Extract folder name
            src_folder = Some(
                Path::new(&spath)
                    .components()
                    .next()
                    .unwrap()
                    .as_os_str()
                    .to_string_lossy()
                    .to_string(),
            );
        }

        let source_path = foundry_path.join(&spath);
        let source_dir = source_path.parent().unwrap();
        if !source_dir.exists() {
            fs::create_dir_all(source_dir)
                .unwrap_or_else(|_| panic!("Could not create directory: {}", source_dir.display()));
        }
        let mut file = File::create(&source_path).unwrap();

        // Write some data to the file
        file.write_all(entry.content.as_bytes())
            .expect("Unable to write file");

        // Sync file data to disk
        file.sync_all().expect("Unable to sync");
    }

    let remap_path = foundry_path.join("remappings.txt");
    let mut remappings: String = "".to_string();
    if let Some(sett) = settings {
        for remap in &sett.remappings {
            remappings.push_str(&format!("{}", remap));
            remappings.push('\n');
        }
        let mut file = File::create(remap_path).unwrap();

        // Write some data to the file
        file.write_all(remappings.as_bytes())
            .expect("Unable to write file");

        // Sync file data to disk
        file.sync_all().expect("Unable to sync");
    }
    // 3. Return as src
    src_folder
}

fn parse_sources(sources: &HashMap<String, SourceCodeEntry>, foundry_path: &Path) {
    // Parse sources
    let mut remappings: Vec<String> = vec![];
    for (spath, entry) in sources.iter() {
        // TODO: Handle this better
        let needs_link = !spath.contains('/');

        // Remove weird non-unicode and "../"
        let mut spath = Path::new(spath)
            .to_string_lossy()
            .into_owned()
            .replace("../", "");
        // Avoid absolute paths
        if Path::new(&spath).is_absolute() {
            // TODO handle non-unix systems here
            spath = format!(".{}", spath);
        }
        let source_path = foundry_path.join("src").join(&spath);
        let source_dir = source_path.parent().unwrap();
        if !source_dir.exists() {
            fs::create_dir_all(source_dir)
                .unwrap_or_else(|_| panic!("Could not create directory: {}", source_dir.display()));
        }
        let mut file = File::create(&source_path).unwrap();

        // Write some data to the file
        file.write_all(entry.content.as_bytes())
            .expect("Unable to write file");

        // Sync file data to disk
        file.sync_all().expect("Unable to sync");

        if needs_link {
            // Just try
            let _ = fs::hard_link(&source_path, &foundry_path.join(&spath));
        }

        // Remapping
        if let Some(slashindex) = spath.rfind('/') {
            let foldername = spath[..slashindex].to_string();
            if foldername != "src" {
                let mut new_remap = String::new();
                new_remap.push_str(&foldername);
                new_remap.push_str("/=src/");
                new_remap.push_str(&foldername);
                new_remap.push('\n');
                remappings.push(new_remap);
            }
        }
    }
    if !remappings.is_empty() {
        remappings.sort();

        // Remove duplicates
        remappings.dedup();

        let remap_path = foundry_path.join("remappings.txt");
        let mut file = File::create(remap_path).unwrap();

        // Write some data to the file
        for remap in &remappings {
            file.write_all(remap.as_bytes())
                .expect("Unable to write file");
        }

        // Sync file data to disk
        file.sync_all().expect("Unable to sync");
    }
}

fn fetch(matches: &ArgMatches) -> Result<(), ValidationError> {
    let mut config = DVFConfig::from_matches(matches)?;
    let foundry_path_str = matches.value_of("project").unwrap().to_string();
    std::fs::create_dir_all(foundry_path_str.clone())?;
    let foundry_path = Path::new(&foundry_path_str);
    let address_str = matches.value_of("address").unwrap().to_string();

    let chain_id = match matches.value_of("chainid") {
        Some(c) => c
            .parse::<u64>()
            .expect("Invalid input for chain id. Please provide an integer."),
        None => 1,
    };
    config.set_chain_id(chain_id)?;

    let chain = Chain::try_from(chain_id).expect("Invalid chain id.");

    // Celo hotfix
    // TODO Fix this properly
    let client = match chain_id {
        42220 => Client::builder()
            .with_api_key("327Y3RJVNVI3JS1RDSEKN5WTVIRP5PWPQA")
            .with_api_url("https://api.celoscan.io/api")
            .unwrap()
            .with_url("https://celoscan.io")
            .unwrap()
            .build()
            .unwrap(),
        _ => Client::builder()
            .with_api_key(config.get_etherscan_api_key()?)
            .chain(chain)
            .unwrap()
            .build()
            .unwrap(),
    };
    let address: Address = address_str.parse().unwrap();
    // Type: https://docs.rs/ethers-etherscan/2.0.7/ethers_etherscan/contract/struct.Metadata.html
    // TODO: Handle  ContractCodeNotVerified here
    let metadata = Runtime::new()
        .unwrap()
        .block_on(client.contract_source_code(address))
        .unwrap();
    Command::new("forge")
        .current_dir(foundry_path)
        .arg("init")
        .output()
        .unwrap();
    // Clean up
    Command::new("sh")
        .current_dir(foundry_path)
        .arg("-c")
        .arg("rm **/Counter*")
        .output()
        .unwrap();
    debug!("Received metadata: {:?}", metadata);

    // Write foundry.toml
    let toml_path = foundry_path.join("foundry.toml");
    let mut toml_file = File::open(&toml_path).unwrap();
    let mut contents = String::new();
    toml_file.read_to_string(&mut contents).unwrap();

    let mut value: Value = toml::from_str(&contents).unwrap();
    // Now you can use `value` to access your parsed TOML.

    let solc_str: String = if metadata.items[0].compiler_version.starts_with('v') {
        metadata.items[0].compiler_version[1..].to_string()
    } else {
        metadata.items[0].compiler_version[..].to_string()
    };
    let solc_version = match Version::from_str(&solc_str) {
        Ok(version) => Version::new(version.major, version.minor, version.patch),
        Err(err) => panic!("Failed to parse solc version: {}", err),
    };

    if metadata.items.len() > 1 {
        todo!()
    }

    let mut src_folder: Option<String> = None;
    let mut solc_settings: Option<Settings> = None;
    // Write sources
    match &metadata.items[0].source_code {
        ethers_etherscan::contract::SourceCodeMetadata::SourceCode(source_str) => {
            let sol_path = foundry_path
                .join("src")
                .join(&metadata.items[0].contract_name)
                .with_extension("sol");
            fs::write(sol_path, source_str).expect("Unable to write file");
        }
        ethers_etherscan::contract::SourceCodeMetadata::Sources(sources) => {
            parse_sources(sources, foundry_path);
        }
        ethers_etherscan::contract::SourceCodeMetadata::Metadata {
            sources, settings, ..
        } => {
            // Parse settings
            debug!("Settings: {:?}", settings);
            let mut foundry_mode = false;
            solc_settings = match settings {
                Some(s) => match serde_json::from_value::<Settings>(s.clone()) {
                    Ok(sett) => {
                        if !sett.remappings.is_empty() {
                            foundry_mode = true;
                        }
                        Some(sett)
                    }
                    Err(e) => {
                        println!("{:?}", e);
                        None
                    }
                },
                None => None,
            };
            if foundry_mode {
                println!("Looks like it was foundry already.");
                src_folder = parse_sources_foundry(
                    sources,
                    foundry_path,
                    &solc_settings,
                    &metadata.items[0].contract_name,
                );
            } else {
                parse_sources(sources, foundry_path);
            }
        }
    };

    // Parse TOML and change it
    if let Some(Value::Table(profile)) = value.get_mut("profile") {
        if let Some(Value::Table(default)) = profile.get_mut("default") {
            if let Some(src_f) = src_folder {
                default.insert("src".to_string(), Value::String(src_f));
            }
            default.insert("solc".to_string(), Value::String(solc_version.to_string()));
            default.insert(
                "optimizer".to_string(),
                Value::Boolean(metadata.items[0].optimization_used == 1),
            );
            default.insert(
                "optimizer_runs".to_string(),
                Value::Integer(metadata.items[0].runs.try_into().unwrap()),
            );
            if metadata.items[0].evm_version != "Default" {
                default.insert(
                    "evm_version".to_string(),
                    Value::String(metadata.items[0].evm_version.clone()),
                );
            } else {
                // "Default" evm_version. This is problematic because foundry does not support it
                let mut evm_version = None;
                if solc_version <= Version::new(0, 4, 20) {
                    evm_version = None;
                } else if solc_version < Version::new(0, 5, 5) {
                    evm_version = Some("byzantium");
                } else if solc_version < Version::new(0, 5, 13) {
                    evm_version = Some("petersburg");
                } else if solc_version < Version::new(0, 8, 5) {
                    evm_version = Some("istanbul");
                } else if solc_version < Version::new(0, 8, 18) {
                    evm_version = Some("london");
                } else if solc_version < Version::new(0, 8, 20) {
                    evm_version = Some("paris");
                } else if solc_version < Version::new(0, 8, 24) {
                    evm_version = Some("shanghai");
                }
                if let Some(evm_ver) = evm_version {
                    default.insert(
                        "evm_version".to_string(),
                        Value::String(evm_ver.to_string()),
                    );
                }
            }
            if let Some(settings) = solc_settings {
                if let Some(via_ir) = settings.via_ir {
                    default.insert("via_ir".to_string(), Value::Boolean(via_ir));
                };
                if let Some(metadata) = settings.metadata {
                    if let Some(bytecode_hash) = metadata.bytecode_hash {
                        default.insert(
                            "bytecode_hash".to_string(),
                            Value::String(bytecode_hash.to_string()),
                        );
                    };
                    if let Some(use_literal_content) = metadata.use_literal_content {
                        default.insert(
                            "use_literal_content".to_string(),
                            Value::Boolean(use_literal_content),
                        );
                    };
                    if let Some(cbor_metadata) = metadata.cbor_metadata {
                        default.insert("cbor_metadata".to_string(), Value::Boolean(cbor_metadata));
                    };
                };
                if let Some(details) = settings.optimizer.details {
                    let mut optimizer_table = Table::new();
                    if details.peephole.is_some() {
                        optimizer_table.insert(
                            "peephole".to_string(),
                            Value::Boolean(details.peephole.unwrap()),
                        );
                    }
                    if details.inliner.is_some() {
                        optimizer_table.insert(
                            "inliner".to_string(),
                            Value::Boolean(details.inliner.unwrap()),
                        );
                    }
                    if details.jumpdest_remover.is_some() {
                        optimizer_table.insert(
                            "jumpdestRemover".to_string(),
                            Value::Boolean(details.jumpdest_remover.unwrap()),
                        );
                    }
                    if details.order_literals.is_some() {
                        optimizer_table.insert(
                            "orderLiterals".to_string(),
                            Value::Boolean(details.order_literals.unwrap()),
                        );
                    }
                    if details.deduplicate.is_some() {
                        optimizer_table.insert(
                            "deduplicate".to_string(),
                            Value::Boolean(details.deduplicate.unwrap()),
                        );
                    }
                    if details.cse.is_some() {
                        optimizer_table
                            .insert("cse".to_string(), Value::Boolean(details.cse.unwrap()));
                    }
                    if details.constant_optimizer.is_some() {
                        optimizer_table.insert(
                            "constantOptimizer".to_string(),
                            Value::Boolean(details.constant_optimizer.unwrap()),
                        );
                    }
                    if details.yul.is_some() {
                        optimizer_table
                            .insert("yul".to_string(), Value::Boolean(details.yul.unwrap()));
                    }
                    if let Some(yul_details) = details.yul_details {
                        let mut details_table = Table::new();
                        if yul_details.stack_allocation.is_some() {
                            details_table.insert(
                                String::from("stackAllocation"),
                                Value::Boolean(yul_details.stack_allocation.unwrap()),
                            );
                        }
                        if yul_details.optimizer_steps.is_some() {
                            details_table.insert(
                                String::from("optimizerSteps"),
                                Value::String(yul_details.optimizer_steps.unwrap()),
                            );
                        }
                        optimizer_table
                            .insert("yulDetails".to_string(), Value::Table(details_table));
                    };
                    default.insert(
                        "optimizer_details".to_string(),
                        Value::Table(optimizer_table),
                    );
                };
                if !settings.libraries.is_empty() {
                    let mut libraries_list: Vec<Value> = Vec::new();
                    for (path, libs_in_path) in settings.libraries.as_ref().iter() {
                        for (lib_name, lib_addr) in libs_in_path.iter() {
                            // TODO: Make this nicer
                            let entry = path.to_str().unwrap().to_string()
                                + ":"
                                + lib_name
                                + ":"
                                + lib_addr;
                            libraries_list.push(Value::String(entry))
                        }
                    }
                    default.insert("libraries".to_string(), Value::Array(libraries_list));
                }
            };
        }
    }

    let modified_toml = toml::to_string(&value).unwrap();

    // Write TOML back to file
    fs::write(&toml_path, modified_toml).expect("Unable to write file");

    let contract_name = metadata.items[0].contract_name.clone();

    let config_str = match matches.value_of("config") {
        Some(config_path_str) => format!("-c {config_path_str} "),
        None => String::new(),
    };

    println!("Saved sources of {} at {}.", address_str, foundry_path_str);
    println!("You can run:");
    println!("dv {config_str}init --address {address_str} --project {foundry_path_str} --chainid {chain_id} --contractname {contract_name} {contract_name}_{address_str}.dvf.json");
    Ok(())
}
