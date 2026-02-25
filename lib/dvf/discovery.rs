use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use alloy::json_abi::Event;
use alloy::primitives::{Address, B256};
use alloy_dyn_abi::EventExt;
use alloy_rpc_types::Log;
use clap::ArgMatches;
use colored::Colorize;
use prettytable::{row, Table};
use tracing::{debug, info};

use crate::bytecode_verification::parse_json::{Environment, ProjectInfo};
use crate::dvf::config::DVFConfig;
use crate::dvf::parse::{self, ValidationError};
use crate::dvf::registry;
use crate::state::contract_state::ContractState;
use crate::state::forge_inspect;
use crate::utils::pretty::PrettyPrinter;
use crate::utils::progress::{print_progress, ProgressMode};
use crate::utils::read_write_file::get_project_paths;
use crate::web3;
use crate::web3::stop_anvil_instance;

pub struct DiscoveryParams<'a> {
    pub config: &'a DVFConfig,
    pub contract_name: &'a str,
    pub address: &'a Address,
    pub start_block_num: u64,
    pub end_block_num: u64,
    pub project: Option<&'a PathBuf>,
    pub artifacts: &'a str,
    pub env: Environment,
    pub build_cache: Option<&'a String>,
    pub libraries: Option<Vec<String>>,
    pub implementation_name: Option<&'a str>,
    pub implementation_project: Option<&'a PathBuf>,
    pub implementation_env: Environment,
    pub implementation_artifacts: &'a str,
    pub implementation_build_cache: Option<&'a String>,
    pub zerovalue: bool,
    pub event_topics: Option<Vec<B256>>,
    pub pc: &'a mut u64,
    pub progress_mode: &'a ProgressMode,
    pub use_storage_range: bool,
}

pub struct DiscoveryResult {
    pub critical_storage_variables: Vec<parse::DVFStorageEntry>,
    pub critical_events: Vec<parse::DVFEventEntry>,
    pub storage_var_table: Table,
    pub event_table: Table,
    pub all_events: Vec<Event>,
    pub proxy_warning: bool,
}

pub fn discover_storage_and_events(
    params: DiscoveryParams,
) -> Result<DiscoveryResult, ValidationError> {
    let registry = registry::Registry::from_config(params.config)?;
    let pretty_printer = PrettyPrinter::new(params.config, Some(&registry));

    // Initialize storage layout and types based on project availability
    let (mut storage_layout, mut types, mut contract_state) = if let Some(project_path) =
        params.project
    {
        let artifacts_path = get_project_paths(project_path, params.artifacts);

        // Load main project info
        let project_info = ProjectInfo::new(
            &params.contract_name.to_string(),
            project_path,
            params.env,
            &artifacts_path,
            params.build_cache,
            params.libraries.clone(),
        )?;

        // Load storage layout using forge inspect
        let fi_layout = forge_inspect::ForgeInspectLayoutStorage::generate_and_parse_layout(
            project_path,
            params.contract_name,
            if params.env == Environment::Hardhat {
                project_info.absolute_path.clone()
            } else {
                None
            },
        );
        let fi_ir = forge_inspect::ForgeInspectIrOptimized::generate_and_parse_ir_optimized(
            project_path,
            params.contract_name,
            if params.env == Environment::Hardhat {
                project_info.absolute_path.clone()
            } else {
                None
            },
        );
        let mut contract_state = ContractState::new_with_address(params.address, &pretty_printer);
        contract_state.add_forge_inspect(&fi_layout, &fi_ir);

        (
            project_info.storage.clone(),
            project_info.types.clone(),
            contract_state,
        )
    } else {
        // Fallback: discovery without layout info
        let contract_state = ContractState::new_with_address(params.address, &pretty_printer);
        (vec![], HashMap::new(), contract_state)
    };

    // Handle implementation contract if present
    let mut imp_project_info: Option<ProjectInfo> = None;
    if let Some(implementation_name) = params.implementation_name {
        print_progress(
            "Obtaining ABI of implementation contract.",
            params.pc,
            params.progress_mode,
        );

        let imp_path: PathBuf;
        let imp_artifacts_path: PathBuf;
        if let Some(imp_project) = params.implementation_project {
            imp_artifacts_path = get_project_paths(imp_project, params.implementation_artifacts);
            imp_path = imp_project.clone();
        } else if let Some(project_path) = params.project {
            imp_path = project_path.clone();
            imp_artifacts_path = get_project_paths(project_path, params.artifacts);
        } else {
            return Err(ValidationError::from(
                "Implementation contract specified but no project path provided",
            ));
        }

        let tmp_project_info = ProjectInfo::new(
            &implementation_name.to_string(),
            &imp_path,
            params.implementation_env,
            &imp_artifacts_path,
            params.implementation_build_cache,
            params.libraries.clone(),
        )?;

        print_progress(
            "Obtaining storage layout of implementation contract.",
            params.pc,
            params.progress_mode,
        );
        let fi_impl_layout = forge_inspect::ForgeInspectLayoutStorage::generate_and_parse_layout(
            &imp_path,
            implementation_name,
            if params.implementation_env == Environment::Hardhat {
                tmp_project_info.absolute_path.clone()
            } else {
                None
            },
        );
        let fi_impl_ir = forge_inspect::ForgeInspectIrOptimized::generate_and_parse_ir_optimized(
            &imp_path,
            implementation_name,
            if params.implementation_env == Environment::Hardhat {
                tmp_project_info.absolute_path.clone()
            } else {
                None
            },
        );
        contract_state.add_forge_inspect(&fi_impl_layout, &fi_impl_ir);

        storage_layout.extend(tmp_project_info.storage.clone());
        types.extend(tmp_project_info.types.clone());
        imp_project_info = Some(tmp_project_info);
    }

    // Get transaction hashes based on event topics
    let mut seen_events: Vec<Log> = vec![];
    let tx_hashes: Vec<String> = if let Some(event_topics) = &params.event_topics {
        print_progress(
            "Obtaining past events and transactions.",
            params.pc,
            params.progress_mode,
        );
        seen_events = web3::get_eth_events(
            params.config,
            params.address,
            params.start_block_num,
            params.end_block_num,
            event_topics,
        )?;
        seen_events
            .iter()
            .filter_map(|e| e.transaction_hash.map(|h| format!("{h:#x}")))
            .collect()
    } else {
        print_progress(
            "Obtaining past transactions.",
            params.pc,
            params.progress_mode,
        );
        web3::get_all_txs_for_contract(
            params.config,
            params.address,
            params.start_block_num,
            params.end_block_num,
        )?
    };

    print_progress("Getting storage snapshot.", params.pc, params.progress_mode);
    let mut snapshot = web3::StorageSnapshot::from_api(
        params.config,
        params.address,
        params.end_block_num,
        &tx_hashes,
        params.use_storage_range,
    )?;

    print_progress("Getting relevant traces.", params.pc, params.progress_mode);
    let mut seen_transactions = HashSet::new();
    let mut missing_traces = false;

    for tx_hash in &tx_hashes {
        if seen_transactions.contains(tx_hash) {
            continue;
        }
        seen_transactions.insert(tx_hash);

        info!("Getting trace for {}", tx_hash);
        match web3::get_eth_debug_trace_sim(params.config, tx_hash) {
            Ok((trace, anvil_config, anvil_instance)) => {
                let record_traces_config = match &anvil_config {
                    Some(c) => c,
                    None => params.config,
                };
                if let Err(err) = contract_state.record_traces(record_traces_config, vec![trace]) {
                    missing_traces = true;
                    info!("Warning. The trace for {tx_hash} cannot be obtained. Some mapping slots might not be decodable. You can try to increase the timeout in the config. Error: {}", err);
                }
                if let Some(anvil_instance) = anvil_instance {
                    stop_anvil_instance(anvil_instance);
                }
            }
            Err(err) => {
                missing_traces = true;
                info!("Warning. The trace for {tx_hash} cannot be obtained. Some mapping slots might not be decodable. You can try to increase the timeout in the config. Error: {}", err);
            }
        }
    }

    if missing_traces {
        println!("{}", "Warning. At least one transaction trace could not be obtained. This might result in \"unknown\" storage slots due to undecoded mapping keys.".yellow())
    }

    print_progress("Parsing storage snapshot.", params.pc, params.progress_mode);
    let mut storage_var_table = Table::new();
    let critical_storage_variables: Vec<parse::DVFStorageEntry> = contract_state
        .get_critical_storage_variables(
            &mut snapshot,
            &mut storage_var_table,
            &storage_layout,
            &types,
            params.zerovalue,
        )?;

    let proxy_warning = critical_storage_variables
        .iter()
        .any(|var| var.var_name == "unknown")
        && imp_project_info.is_some();

    // Event discovery logic
    if params.event_topics.is_none() {
        print_progress("Obtaining past events.", params.pc, params.progress_mode);
        seen_events = web3::get_eth_events_paginated(
            params.config,
            params.address,
            params.start_block_num,
            params.end_block_num,
            &vec![],
        )?;
    }

    let mut covered_events = 0;
    let mut event_table = Table::new();
    let mut critical_events: Vec<parse::DVFEventEntry> = vec![];

    print_progress("Decoding events.", params.pc, params.progress_mode);

    // Collect all Event Types, making sure to avoid duplications
    let all_events = match &imp_project_info {
        None => {
            if let Some(project_path) = params.project {
                let artifacts_path = get_project_paths(project_path, params.artifacts);
                let contract_name_string = params.contract_name.to_string();
                let project_info = ProjectInfo::new(
                    &contract_name_string,
                    project_path,
                    params.env,
                    &artifacts_path,
                    params.build_cache,
                    params.libraries.clone(),
                )?;
                project_info.events.clone()
            } else {
                vec![]
            }
        }
        Some(imp_project) => {
            let mut set_of_sigs: HashSet<B256> = HashSet::new();
            let mut res: Vec<Event> = vec![];

            // Get main project events if available
            let main_events = if let Some(project_path) = params.project {
                let artifacts_path = get_project_paths(project_path, params.artifacts);
                let contract_name_string = params.contract_name.to_string();
                let project_info = ProjectInfo::new(
                    &contract_name_string,
                    project_path,
                    params.env,
                    &artifacts_path,
                    params.build_cache,
                    params.libraries.clone(),
                )?;
                project_info.events.clone()
            } else {
                vec![]
            };

            for eventlist in [&main_events, &imp_project.events] {
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

    // Handle unknown events
    if covered_events != seen_events.len() {
        println!(
            "Warning! Saw {} events, but able to decode {}.",
            seen_events.len(),
            covered_events
        );
        let used_topics_0: HashSet<B256> = all_events.iter().map(|e| e.selector()).collect();
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

    Ok(DiscoveryResult {
        critical_storage_variables,
        critical_events,
        storage_var_table,
        event_table,
        all_events,
        proxy_warning,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn create_discovery_params_for_init<'a>(
    config: &'a DVFConfig,
    dumped: &'a parse::CompleteDVF,
    deployment_block_num: u64,
    init_block_num: u64,
    project: &'a PathBuf,
    artifacts: &'a str,
    env: Environment,
    build_cache: Option<&'a String>,
    libraries: Option<Vec<String>>,
    zerovalue: bool,
    event_topics: Option<Vec<B256>>,
    sub_m: &'a ArgMatches,
    pc: &'a mut u64,
    progress_mode: &'a ProgressMode,
) -> DiscoveryParams<'a> {
    DiscoveryParams {
        config,
        contract_name: &dumped.contract_name,
        address: &dumped.address,
        start_block_num: deployment_block_num,
        end_block_num: init_block_num,
        project: Some(project),
        artifacts,
        env,
        build_cache,
        libraries,
        implementation_name: sub_m
            .get_one::<String>("implementation")
            .map(|s| s.as_str()),
        implementation_project: sub_m.get_one::<PathBuf>("implementationproject"),
        implementation_env: env,
        implementation_artifacts: sub_m.get_one::<String>("implementationartifacts").unwrap(),
        implementation_build_cache: sub_m.get_one::<String>("implementationbuildcache"),
        zerovalue,
        event_topics,
        pc,
        progress_mode,
        use_storage_range: true,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn create_discovery_params_for_update<'a>(
    config: &'a DVFConfig,
    updated: &'a parse::CompleteDVF,
    validation_block_num: u64,
    project: Option<&'a PathBuf>,
    artifacts: &'a str,
    env: Environment,
    build_cache: Option<&'a String>,
    libraries: Option<Vec<String>>,
    zerovalue: bool,
    sub_m: &'a ArgMatches,
    pc: &'a mut u64,
    progress_mode: &'a ProgressMode,
) -> DiscoveryParams<'a> {
    DiscoveryParams {
        config,
        contract_name: &updated.contract_name,
        address: &updated.address,
        start_block_num: updated.init_block_num + 1,
        end_block_num: validation_block_num,
        project,
        artifacts,
        env,
        build_cache,
        libraries,
        implementation_name: sub_m
            .get_one::<String>("implementation")
            .map(|s| s.as_str()),
        implementation_project: sub_m.get_one::<PathBuf>("implementationproject"),
        implementation_env: *sub_m.get_one::<Environment>("implementationenv").unwrap(),
        implementation_artifacts: sub_m.get_one::<String>("implementationartifacts").unwrap(),
        implementation_build_cache: sub_m.get_one::<String>("implementationbuildcache"),
        zerovalue,
        event_topics: None, // Update mode doesn't filter by event topics
        pc,
        progress_mode,
        use_storage_range: false, // cannot use storage range here as we are only trying to get a subset of the state
    }
}
