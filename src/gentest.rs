use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use clap::ArgMatches;
use clap::{App, Arg, ArgAction};
use dvf_libs::dvf::config::DVFConfig;
use dvf_libs::dvf::parse::{ValidationError, CURRENT_VERSION};
use dvf_libs::state::contract_state::ContractState;
use dvf_libs::state::forge_inspect;
use dvf_libs::utils::pretty::PrettyPrinter;
use dvf_libs::web3;
use dvf_libs::web3::StorageSnapshot;
use prettytable::Table;
use tracing::debug;

fn main() {
    let matches = App::new("gentest")
        .version(CURRENT_VERSION.to_string().as_str())
        .about("Generate test case with storage snapshot and trace")
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
            Arg::with_name("txid")
                .long("txid")
                .help("Transaction ID")
                .required(true)
                .action(ArgAction::Set),
        )
        .arg(
            Arg::with_name("name")
                .long("name")
                .help("Contract Name")
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
    gen_test(&matches).unwrap();
}
fn gen_test(matches: &ArgMatches) -> Result<(), ValidationError> {
    let mut config = DVFConfig::from_matches(matches)?;
    let tx_id = matches.value_of("txid").unwrap().to_string();
    let name = matches.value_of("name").unwrap().to_string();

    let chain_id = match matches.value_of("chainid") {
        Some(c) => c
            .parse::<u64>()
            .expect("Invalid input for chain id. Please provide an integer."),
        None => 1,
    };
    config.set_chain_id(chain_id)?;

    let trace_w_a = web3::get_eth_debug_trace(&config, &tx_id)?;

    // Check that we can generate a snapshot
    let mut snapshot = StorageSnapshot::from_tx_id(&config, &trace_w_a.address, &tx_id)?;
    debug!(
        "Generated Snapshot: {}",
        serde_json::to_string_pretty(&snapshot)?
    );

    let serialized_trace = serde_json::to_string_pretty(&trace_w_a)?;
    /*
        let mut rusty_trace = "r#\"".to_string();
        rusty_trace.push_str(&serialized_trace);
        rusty_trace.push_str("\"#");
    */
    let trace_path = Path::new("tests/data/").join(format!("trace_{}.json", name));

    // Write TOML back to file
    fs::write(&trace_path, serialized_trace).expect("Unable to write file");
    println!("Saved trace of {} at {}.", name, trace_path.display());

    let pretty_printer = PrettyPrinter::new(&config, None);

    let mut global_state = ContractState::new_with_address(&trace_w_a.address, &pretty_printer);
    let forge_inspect = forge_inspect::ForgeInspect::generate_and_parse_layout(
        Path::new("tests/Contracts"),
        &name,
        None,
    );
    global_state.add_forge_inspect(&forge_inspect);
    global_state.record_traces(&config, vec![trace_w_a.clone()])?;
    let mut table = Table::new();
    let critical_vars = global_state.get_critical_storage_variables(
        &mut snapshot,
        &mut table,
        &vec![],
        &HashMap::new(),
    )?;

    let serialized_res = serde_json::to_string_pretty(&critical_vars)?;
    /*
        let mut rusty_res = "r#\"".to_string();
        rusty_res.push_str(&serialized_res);
        rusty_res.push_str("\"#");
    */

    let res_path = Path::new("tests/data/").join(format!("result_{}.json", name));

    // Write TOML back to file
    fs::write(&res_path, serialized_res).expect("Unable to write file");

    println!("Saved result of {} at {}.", name, res_path.display());
    Ok(())
}
