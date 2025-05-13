use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

use clap::ArgMatches;
use dirs_next::home_dir;

use alloy::primitives::Address;
use alloy_chains::NamedChain;

use alloy::signers::local::PrivateKeySigner; //LOCALWALLET
use alloy::signers::Signer;
use alloy_signer_ledger::{HDPath, LedgerSigner};

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use tempfile::{tempdir, NamedTempFile};
use tracing::debug;

use crate::dvf::abstract_wallet::AbstractWallet;
use crate::dvf::parse::ValidationError;
use crate::web3;
use colored::Colorize;
use dotenv::dotenv;
use scanf::sscanf;
use std::env;

pub const DEFAULT_CONFIG_LOCATION: &str = "~/.dv_config.json";
const DEFAULT_FALLBACK_CONFIG_LOCATION: &str = "dv_config.json";
const RPC_URLS_REPOSITORY: &str =
    "https://raw.githubusercontent.com/ethereum-lists/chains/master/_data/chains";

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DVFWalletType {
    SecretKey(DVFSecretKeyConfig),
    Ledger(DVFLedgerConfig), // TODO: YubiKey
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DVFSecretKeyConfig {
    pub secret_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum DVFLedgerType {
    LedgerLive,
    Legacy,
}

impl DVFLedgerType {
    fn from_u64(item: u64) -> Result<Self, ValidationError> {
        match item {
            1 => Ok(DVFLedgerType::LedgerLive),
            2 => Ok(DVFLedgerType::Legacy),
            _ => Ok(DVFLedgerType::LedgerLive),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DVFLedgerConfig {
    pub ledger_type: DVFLedgerType,
    pub ledger_index: usize,
}

impl DVFLedgerConfig {
    pub fn get_hd_path(&self) -> HDPath {
        match self.ledger_type {
            DVFLedgerType::LedgerLive => HDPath::LedgerLive(self.ledger_index),
            DVFLedgerType::Legacy => HDPath::Legacy(self.ledger_index),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DVFSignerConfig {
    #[serde(default)]
    pub wallet_address: Address,
    pub wallet_type: DVFWalletType,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EtherscanConfig {
    pub api_url: Option<String>,
    pub api_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockscoutConfig {
    pub api_url: Option<String>,
    pub api_key: String,
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct DVFConfig {
    pub rpc_urls: BTreeMap<u64, String>, // chain_id to URL
    pub dvf_storage: PathBuf,            // Storage of DVFs
    pub trusted_signers: Vec<Address>,
    #[serde(default)]
    pub etherscan_global: Option<EtherscanConfig>,
    #[serde(default)]
    pub etherscan_chain_configs: BTreeMap<u64, EtherscanConfig>,
    #[serde(default)]
    pub blockscout_global: Option<BlockscoutConfig>,
    #[serde(default)]
    pub blockscout_chain_configs: BTreeMap<u64, BlockscoutConfig>,
    #[serde(default = "default_max_blocks")]
    pub max_blocks_per_event_query: u64,
    #[serde(default = "default_web3_timeout")]
    pub web3_timeout: u64,
    pub signer: Option<DVFSignerConfig>,
    #[serde(skip_serializing)]
    pub active_chain_id: Option<u64>,
    #[serde(default, skip_serializing)]
    active_chain: Option<NamedChain>,
}

fn default_max_blocks() -> u64 {
    9999
}

fn default_web3_timeout() -> u64 {
    700
}

impl DVFConfig {
    const DEFAULT_ETHERSCAN_API_URL: &str = "https://api.etherscan.io/v2/api";
    const DEFAULT_BLOCKSCOUT_API_URL: &str = "https://eth.blockscout.com/api";
    
    pub fn from_matches(matches: &ArgMatches) -> Result<Self, ValidationError> {
        if let Some(("generate-config", _)) = matches.subcommand() {
            return Ok(Self::default());
        }
        match matches.get_one::<String>("config") {
            Some(config_path_str) => {
                if config_path_str == "env" {
                    Self::from_env(None)
                } else {
                    Self::from_path(Path::new(config_path_str))
                }
            }
            None => Self::from_default_path(),
        }
    }

    pub fn from_env(local_port: Option<u16>) -> Result<Self, ValidationError> {
        dotenv().ok();
        let rpc_urls: BTreeMap<u64, String>;
        if let Some(local_port) = local_port {
            rpc_urls = BTreeMap::from([
                (1, env::var("MAINNET_RPC")?),
                (1337, format!("http://127.0.0.1:{}", local_port)),
                (31337, format!("http://127.0.0.1:{}", local_port)),
            ]);
        } else {
            rpc_urls = BTreeMap::from([(1, env::var("MAINNET_RPC")?)]);
        }
        let temp_dir = tempdir().unwrap();

        // Create global Etherscan config if API key is available
        let etherscan_global = if let Ok(api_key) = env::var("ETHERSCAN_API_KEY") {
            Some(EtherscanConfig {
                api_url: env::var("ETHERSCAN_TEST_API_URL").ok(),
                api_key,
            })
        } else {
            None
        };

        // Create global Blockscout config if API key is available
        let blockscout_global = if let Ok(api_key) = env::var("BLOCKSCOUT_API_KEY") {
            Some(BlockscoutConfig {
                api_url: env::var("BLOCKSCOUT_TEST_API_URL").ok(),
                api_key,
            })
        } else {
            None
        };

        Ok(DVFConfig {
            rpc_urls,
            dvf_storage: temp_dir.path().to_path_buf(),
            trusted_signers: vec![
                Address::from_str("0x229F1a71262e4bE12215EE4648615D2bA0969682")?,
                Address::from_str("0xF063F84A88Bf621520583d386F8F642C475A0c5E")?,
                Address::from_str("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")?,
                Address::from_str(env::var("SIGNER_ADDRESS")?.as_str())?,
            ],
            etherscan_global,
            etherscan_chain_configs: BTreeMap::new(),
            blockscout_global,
            blockscout_chain_configs: BTreeMap::new(),
            max_blocks_per_event_query: default_max_blocks(),
            web3_timeout: default_web3_timeout(),
            signer: Some(DVFSignerConfig {
                wallet_address: Address::from_str(env::var("SIGNER_ADDRESS")?.as_str())?,
                wallet_type: DVFWalletType::SecretKey(DVFSecretKeyConfig {
                    secret_key: env::var("SIGNER_SECRET_KEY")?,
                }),
            }),
            active_chain_id: None,
            active_chain: None,
        })
    }

    pub fn test_config_file(local_port: Option<u16>) -> Result<NamedTempFile, ValidationError> {
        // @note we should use this file
        let config_file = NamedTempFile::new().unwrap();
        let config = DVFConfig::from_env(local_port)?;
        config.write_to_file(&config_file.path().to_path_buf())?;
        Ok(config_file)
    }

    fn validate_dvf_storage(path: &Path) -> Result<(), ValidationError> {
        if !path.is_dir() && std::fs::create_dir_all(path).is_err() {
            return Err(ValidationError::from(
                "'dvf_storage' in the Config File must point to a valid directory.",
            ));
        }
        Ok(())
    }

    pub fn from_path(config_path: &Path) -> Result<Self, ValidationError> {
        if !config_path.exists() {
            return Err(ValidationError::from(
                "Config File not found. See --help for more info.",
            ));
        }
        let mut file = File::open(config_path)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;

        let mut config: DVFConfig = serde_json::from_str(&content)?;

        config.dvf_storage = replace_tilde_from_path(&config.dvf_storage)?;

        Self::validate_dvf_storage(&config.dvf_storage)?;

        Ok(config)
    }

    pub fn default_path() -> PathBuf {
        if let Ok(p) = replace_tilde(DEFAULT_CONFIG_LOCATION) {
            p
        } else {
            PathBuf::from_str(DEFAULT_FALLBACK_CONFIG_LOCATION).unwrap()
        }
    }

    pub fn from_default_path() -> Result<Self, ValidationError> {
        Self::from_path(&Self::default_path())
    }

    pub fn get_abstract_wallet(&self, chain_id: u64) -> Result<AbstractWallet, ValidationError> {
        let wallet = match &self.signer {
            None => AbstractWallet::LocalWallet(PrivateKeySigner::random()),

            Some(signer) => {
                let temp_wallet = match &signer.wallet_type {
                    DVFWalletType::SecretKey(sk) => AbstractWallet::LocalWallet(
                        sk.secret_key
                            .parse::<PrivateKeySigner>()
                            .map_err(|_| {
                                ValidationError::Error("Could not parse private key.".to_string())
                            })?
                            .with_chain_id(Option::Some(chain_id)),
                    ),
                    DVFWalletType::Ledger(ledger_config) => {
                        let rt = tokio::runtime::Runtime::new().unwrap();
                        AbstractWallet::Ledger(rt.block_on(LedgerSigner::new(
                            ledger_config.get_hd_path(),
                            Option::Some(chain_id),
                        ))?)
                    }
                };
                if temp_wallet.address() != signer.wallet_address {
                    return Err(ValidationError::Error(format!("Address of wallet ({:?}) does not match provided address in config ({:?}).", temp_wallet.address(), signer.wallet_address)));
                }
                temp_wallet
            }
        };
        Ok(wallet)
    }

    pub fn from_interactive_cli() -> Result<Self, ValidationError> {
        println!("Welcome to the DV Config Generator.");
        println!("This program will guide you through the process of setting up your DV config.");

        let mut first_item = true;
        let mut rpc_urls: BTreeMap<u64, String> = BTreeMap::new();
        println!();
        println!("{}", "STEP 1".green());
        'chain_id_loop: loop {
            let mut chain_id: u64 = 1;
            if first_item {
                println!("Please provide a chain ID you plan to use.");
            } else {
                println!(
                    "Please provide another chain ID or hit {} to go to the next step.",
                    "<Enter>".green()
                );
            }
            print!("> ");

            let mut input = String::new();
            let _ = std::io::Write::flush(&mut std::io::stdout());
            io::stdin().read_line(&mut input).unwrap();

            if input.trim().is_empty() {
                if first_item {
                    println!("{}", "Please specify at least one chain ID.".yellow());
                    continue;
                } else {
                    break;
                }
            }

            if sscanf!(&input, "{}", chain_id).is_ok() {
                first_item = false;
                loop {
                    println!("Please provide an RPC URL for chain ID {} or hit {} to automatically retrieve one.", chain_id, "<Enter>".green());
                    print!("> ");

                    let mut input = String::new();
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                    io::stdin().read_line(&mut input).unwrap();

                    if input.trim().is_empty() {
                        if let Ok(rpc) = Self::fetch_rpc_url_for(&chain_id) {
                            println!("RPC URL {} has been added successfully.", rpc.green());
                            rpc_urls.insert(chain_id, rpc);
                            break;
                        } else {
                            println!(
                                "{}",
                                format!(
                                    "An RPC URL for chain ID {} could not be retrieved.",
                                    chain_id
                                )
                                .yellow()
                            );
                            println!(
                                "Please provide an RPC URL manually or hit {} to skip chain ID {}",
                                chain_id,
                                "<Enter>".green()
                            );
                            print!("> ");

                            let mut input = String::new();
                            let _ = std::io::Write::flush(&mut std::io::stdout());
                            io::stdin().read_line(&mut input).unwrap();

                            if input.trim().is_empty() {
                                println!("{}", format!("Chain ID {} skippd!", chain_id).yellow());
                                continue 'chain_id_loop;
                            }

                            let mut rpc = String::new();
                            if sscanf!(&input, "{}", rpc).is_ok() {
                                rpc_urls.insert(chain_id, rpc);
                                break;
                            } else {
                                println!(
                                    "{}",
                                    "The provided RPC URL could not be parsed.".yellow()
                                );
                            }
                            continue;
                        }
                    }
                    let mut rpc = String::new();
                    if sscanf!(&input, "{}", rpc).is_ok() {
                        rpc_urls.insert(chain_id, rpc);
                        break;
                    } else {
                        println!("{}", "The provided RPC URL could not be parsed.".yellow());
                    }
                }
            } else {
                println!("{}", "The provided chain ID could not be parsed.".yellow());
            }
        }

        let dvf_storage: PathBuf;
        println!();
        println!("{}", "STEP 2".green());
        loop {
            println!("Please enter the directory where your DVF files should be stored.");
            let default_path = home_dir().map(|mut x| {
                x.push("dvf");
                x
            });
            if let Some(default_path) = default_path.as_ref() {
                println!(
                    "Hit {} to use default value: {}",
                    "<Enter>".green(),
                    default_path.display().to_string().green()
                );
            };
            print!("> ");

            let mut input = String::new();
            let _ = std::io::Write::flush(&mut std::io::stdout());
            io::stdin().read_line(&mut input).unwrap();

            if let Some(default_path) = default_path {
                if input.trim().is_empty() {
                    if Self::validate_dvf_storage(&default_path).is_ok() {
                        dvf_storage = default_path;
                        break;
                    } else {
                        println!("{}", "The provided directory is not empty.".yellow());
                        continue;
                    }
                }
            }

            let mut path_str = String::new();
            if sscanf!(&input, "{}", path_str).is_ok() {
                if let Ok(path) = replace_tilde(path_str.trim()) {
                    if Self::validate_dvf_storage(&path).is_ok() {
                        dvf_storage = path;
                        break;
                    } else {
                        println!("{}", "The provided directory is not empty.".yellow());
                    }
                }
            } else {
                println!("{}", "The provided path could not be parsed.".yellow());
            }
        }

        let mut trusted_signers: Vec<Address> = vec![];
        first_item = true;
        println!();
        println!("{}", "STEP 3".green());
        loop {
            let mut signer = Address::default();
            if first_item {
                println!(
                    "Please provide a trusted signer or hit {} to go to the next step.",
                    "<Enter>".green()
                );
            } else {
                println!(
                    "Please provide another trusted signer or hit {} to go to the next step.",
                    "<Enter>".green()
                );
            }
            print!("> ");

            let mut input = String::new();
            let _ = std::io::Write::flush(&mut std::io::stdout());
            io::stdin().read_line(&mut input).unwrap();

            if input.trim().is_empty() {
                break;
            }

            if sscanf!(&input, "{}", signer).is_ok() {
                first_item = false;
                trusted_signers.push(signer);
            } else {
                println!("{}", "The provided address could not be parsed.".yellow());
            }
        }

        println!();
        println!("{}", "STEP 4".green());
        println!("In this step, you can configure Etherscan and Blockscout settings.");
        println!("You can set global configurations that will be used as fallbacks,");
        println!("and/or chain-specific configurations that will override the global settings.");
        println!();

        // Global Etherscan config
        let default_etherscan_api_url = String::from(Self::DEFAULT_ETHERSCAN_API_URL);
        let default_blockscout_api_url = String::from(Self::DEFAULT_BLOCKSCOUT_API_URL);
        println!("{}", "Global Etherscan Configuration".bold());
        println!("Would you like to set a global Etherscan configuration? (y/n)");
        print!("> ");
        let _ = std::io::Write::flush(&mut std::io::stdout());
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let mut etherscan_global = None;
        if input.trim().eq_ignore_ascii_case("y") {
            let mut api_key = String::new();
            loop {
                println!("Please enter your Etherscan API key:");
                print!("> ");
                let _ = std::io::Write::flush(&mut std::io::stdout());
                io::stdin().read_line(&mut api_key).unwrap();
                api_key = api_key.trim().to_string();
                if !api_key.is_empty() {
                    break;
                }
                println!("{}", "API key cannot be empty.".yellow());
            }

            let mut api_url = String::new();
            println!("Please enter the Etherscan API URL:");
            println!(
                "Hit {} to use default value: {}",
                "<Enter>".green(),
                &default_etherscan_api_url.to_string().green()
            );
            print!("> ");
            let _ = std::io::Write::flush(&mut std::io::stdout());
            io::stdin().read_line(&mut api_url).unwrap();
            api_url = api_url.trim().to_string();
            if api_url.is_empty() {
                api_url = default_etherscan_api_url.clone();
            }

            etherscan_global = Some(EtherscanConfig {
                api_url: if api_url.is_empty() { None } else { Some(api_url) },
                api_key,
            });
        }

        // Global Blockscout config
        println!();
        println!("{}", "Global Blockscout Configuration".bold());
        println!("Would you like to set a global Blockscout configuration? (y/n)");
        print!("> ");
        let _ = std::io::Write::flush(&mut std::io::stdout());
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let mut blockscout_global = None;
        if input.trim().eq_ignore_ascii_case("y") {
            let mut api_key = String::new();
            loop {
                println!("Please enter your Blockscout API key:");
                print!("> ");
                let _ = std::io::Write::flush(&mut std::io::stdout());
                io::stdin().read_line(&mut api_key).unwrap();
                api_key = api_key.trim().to_string();
                if !api_key.is_empty() {
                    break;
                }
                println!("{}", "API key cannot be empty.".yellow());
            }

            let mut api_url = String::new();
            println!("Please enter the Blockscout API URL:");
            println!(
                "Hit {} to use default value: {}",
                "<Enter>".green(),
                &default_blockscout_api_url.to_string().green()
            );
            print!("> ");
            let _ = std::io::Write::flush(&mut std::io::stdout());
            io::stdin().read_line(&mut api_url).unwrap();
            api_url = api_url.trim().to_string();
            if api_url.is_empty() {
                api_url = default_blockscout_api_url.clone();
            }

            blockscout_global = Some(BlockscoutConfig {
                api_url: if api_url.is_empty() { None } else { Some(api_url) },
                api_key,
            });
        }

        // Chain-specific configs
        let mut etherscan_chain_configs = BTreeMap::new();
        let mut blockscout_chain_configs = BTreeMap::new();

        println!();
        println!("Would you like to set chain-specific Etherscan / Blockscout configurations? (y/n)");
        print!("> ");
        let _ = std::io::Write::flush(&mut std::io::stdout());
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();

        if input.trim().eq_ignore_ascii_case("y") {
            for chain_id in rpc_urls.keys() {
                println!();
                println!("{}", format!("Configuration for Chain ID {}", chain_id).bold());

                // Etherscan config for this chain
                println!("Would you like to set an Etherscan configuration for this chain? (y/n)");
                print!("> ");
                let _ = std::io::Write::flush(&mut std::io::stdout());
                let mut input = String::new();
                io::stdin().read_line(&mut input).unwrap();
                if input.trim().eq_ignore_ascii_case("y") {
                    let mut api_key = String::new();
                    loop {
                        println!("Please enter your Etherscan API key for chain {}:", chain_id);
                        print!("> ");
                        let _ = std::io::Write::flush(&mut std::io::stdout());
                        io::stdin().read_line(&mut api_key).unwrap();
                        api_key = api_key.trim().to_string();
                        if !api_key.is_empty() {
                            break;
                        }
                        println!("{}", "API key cannot be empty.".yellow());
                    }

                    let mut api_url = String::new();
                    println!("Please enter the Etherscan API URL for chain {}:", chain_id);
                    println!(
                        "Hit {} to use default value: {}",
                        "<Enter>".green(),
                        &default_etherscan_api_url.to_string().green()
                    );
                    print!("> ");
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                    io::stdin().read_line(&mut api_url).unwrap();
                    api_url = api_url.trim().to_string();
                    if api_url.is_empty() {
                        api_url = default_etherscan_api_url.clone();
                    }

                    etherscan_chain_configs.insert(*chain_id, EtherscanConfig {
                        api_url: if api_url.is_empty() { None } else { Some(api_url) },
                        api_key,
                    });
                }

                // Blockscout config for this chain
                println!("Would you like to set a Blockscout configuration for this chain? (y/n)");
                print!("> ");
                let _ = std::io::Write::flush(&mut std::io::stdout());
                let mut input = String::new();
                io::stdin().read_line(&mut input).unwrap();
                if input.trim().eq_ignore_ascii_case("y") {
                    let mut api_key = String::new();
                    loop {
                        println!("Please enter your Blockscout API key for chain {}:", chain_id);
                        print!("> ");
                        let _ = std::io::Write::flush(&mut std::io::stdout());
                        io::stdin().read_line(&mut api_key).unwrap();
                        api_key = api_key.trim().to_string();
                        if !api_key.is_empty() {
                            break;
                        }
                        println!("{}", "API key cannot be empty.".yellow());
                    }

                    let mut api_url = String::new();
                    println!("Please enter the Blockscout API URL for chain {}:", chain_id);
                    println!(
                        "Hit {} to use default value: {}",
                        "<Enter>".green(),
                        &default_blockscout_api_url.green()
                    );
                    print!("> ");
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                    io::stdin().read_line(&mut api_url).unwrap();
                    api_url = api_url.trim().to_string();
                    if api_url.is_empty() {
                        api_url = default_blockscout_api_url.clone();
                    }

                    blockscout_chain_configs.insert(*chain_id, BlockscoutConfig {
                        api_url: if api_url.is_empty() { None } else { Some(api_url) },
                        api_key,
                    });
                }
            }
        }

        let mut max_blocks_per_event_query: u64 = default_max_blocks();
        println!();
        println!("{}", "STEP 5".green());
        loop {
            println!("Please enter the number of blocks that can be queried at once in your RPC.");
            println!(
                "Hit {} to use default value: {}",
                "<Enter>".green(),
                max_blocks_per_event_query.to_string().green()
            );
            print!("> ");

            let mut input = String::new();
            let _ = std::io::Write::flush(&mut std::io::stdout());
            io::stdin().read_line(&mut input).unwrap();

            if input.trim().is_empty() {
                break;
            }

            if sscanf!(&input, "{}", max_blocks_per_event_query).is_ok() {
                break;
            } else {
                println!("{}", "The provided number could not be parsed.".yellow());
            }
        }

        let mut web3_timeout: u64 = default_web3_timeout();
        println!();
        println!("{}", "STEP 6".green());
        loop {
            println!("Please enter the desired RPC timeout in seconds.");
            println!(
                "Hit {} to use default value: {}",
                "<Enter>".green(),
                web3_timeout.to_string().green()
            );
            print!("> ");

            let mut input = String::new();
            let _ = std::io::Write::flush(&mut std::io::stdout());
            io::stdin().read_line(&mut input).unwrap();

            if input.trim().is_empty() {
                break;
            }

            if sscanf!(&input, "{}", web3_timeout).is_ok() {
                break;
            } else {
                println!("{}", "The provided number could not be parsed.".yellow());
            }
        }

        let signer: Option<DVFSignerConfig>;
        println!();
        println!("{}", "STEP 7".green());
        println!(
            "In the following, you will be asked to provide an address and the associated secret"
        );
        println!("key (or Ledger) with which DFV files are signed.");
        println!(
            "This is optional but please be aware that providing none prevents you from being able"
        );
        println!("to create DVF files that can be validated.");
        println!();
        loop {
            println!(
                "Please provide a signing address or hit {} to provide none.",
                "<Enter>".green()
            );
            print!("> ");

            let mut input = String::new();
            let _ = std::io::Write::flush(&mut std::io::stdout());
            io::stdin().read_line(&mut input).unwrap();

            if input.trim().is_empty() {
                signer = None;
                break;
            }

            let mut address = Address::default();
            if sscanf!(&input, "{}", address).is_ok() {
                loop {
                    println!("Please enter your signing choice:");
                    println!("1. Secret Key");
                    println!("2. Ledger");
                    print!("> ");

                    let mut input = String::new();
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                    io::stdin().read_line(&mut input).unwrap();

                    let mut signing_choice: u64 = 0;
                    if sscanf!(&input, "{}", signing_choice).is_ok() {
                        signer = match signing_choice {
                            1 => {
                                let mut secret_key: String = String::new();
                                loop {
                                    println!("Please enter the secret key.");
                                    print!("> ");

                                    let mut input = String::new();
                                    let _ = std::io::Write::flush(&mut std::io::stdout());
                                    io::stdin().read_line(&mut input).unwrap();

                                    if sscanf!(&input, "{}", secret_key).is_ok()
                                        && !secret_key.is_empty()
                                    {
                                        if !secret_key.starts_with("0x") {
                                            secret_key = format!("0x{}", secret_key);
                                        }
                                        break;
                                    } else {
                                        println!(
                                            "{}",
                                            "The provided secret key could not be parsed.".yellow()
                                        );
                                    }
                                }
                                Some(DVFSignerConfig {
                                    wallet_address: address,
                                    wallet_type: DVFWalletType::SecretKey(DVFSecretKeyConfig {
                                        secret_key,
                                    }),
                                })
                            }
                            2 => {
                                let ledger_signer: Option<DVFSignerConfig>;
                                loop {
                                    println!("Please enter your derivation type choice.");
                                    println!("1. Ledger Live");
                                    println!("2. Legacy");
                                    print!("> ");

                                    let mut input = String::new();
                                    let _ = std::io::Write::flush(&mut std::io::stdout());
                                    io::stdin().read_line(&mut input).unwrap();

                                    let mut ledger_choice: u64 = 0;
                                    if sscanf!(&input, "{}", ledger_choice).is_ok() {
                                        ledger_signer = match ledger_choice {
                                            1 | 2 => {
                                                let ledger_type: DVFLedgerType =
                                                    DVFLedgerType::from_u64(ledger_choice).unwrap();
                                                let mut ledger_index: usize = 0;
                                                loop {
                                                    println!("Please enter derivation index.");
                                                    println!(
                                                        "Hit {} to use default value: {}",
                                                        "<Enter>".green(),
                                                        ledger_index.to_string().green()
                                                    );
                                                    print!("> ");

                                                    if input.trim().is_empty() {
                                                        break;
                                                    }

                                                    let mut input = String::new();
                                                    let _ = std::io::Write::flush(
                                                        &mut std::io::stdout(),
                                                    );
                                                    io::stdin().read_line(&mut input).unwrap();

                                                    if sscanf!(&input, "{}", ledger_index).is_ok() {
                                                        break;
                                                    } else {
                                                        println!("{}", "The provided number could not be parsed.".yellow());
                                                    }
                                                }
                                                Some(DVFSignerConfig {
                                                    wallet_address: address,
                                                    wallet_type: DVFWalletType::Ledger(
                                                        DVFLedgerConfig {
                                                            ledger_type,
                                                            ledger_index,
                                                        },
                                                    ),
                                                })
                                            }
                                            _ => {
                                                println!(
                                                    "{}",
                                                    "Please enter a valid choice.".yellow()
                                                );
                                                continue;
                                            }
                                        };
                                        break;
                                    } else {
                                        println!(
                                            "{}",
                                            "The provided number could not be parsed.".yellow()
                                        );
                                    }
                                }
                                ledger_signer
                            }
                            _ => {
                                println!("{}", "Please enter a valid choice.".yellow());
                                continue;
                            }
                        };
                        break;
                    } else {
                        println!("{}", "The provided number could not be parsed.".yellow());
                    }
                }
                break;
            } else {
                println!("{}", "The provided address could not be parsed.".yellow());
            }
        }

        Ok(DVFConfig {
            rpc_urls,
            dvf_storage,
            trusted_signers,
            etherscan_global,
            etherscan_chain_configs,
            blockscout_global,
            blockscout_chain_configs,
            max_blocks_per_event_query,
            web3_timeout,
            signer,
            active_chain_id: None,
            active_chain: None,
        })
    }

    pub fn set_chain_id(&mut self, chain_id: u64) -> Result<(), ValidationError> {
        // Check that we have an RPC URL for this chain id
        match self.rpc_urls.get(&chain_id) {
            None => {
                println!(
                    "Warning: No rpc url found in config for chain id {}.",
                    chain_id
                );
                self.active_chain_id = Some(chain_id);
                return Ok(());
            }
            Some(_) => self.active_chain_id = Some(chain_id),
        }
        self.active_chain = NamedChain::try_from(chain_id).ok();

        let rpc_chain_id = web3::get_eth_chain_id(self)?;
        if rpc_chain_id != chain_id {
            let msg = format!(
                "Specified chain_id {} does not match RPC's chain_id {}!",
                chain_id, rpc_chain_id
            );
            return Err(ValidationError::Error(msg));
        }

        Ok(())
    }

    pub fn get_chain(&self) -> NamedChain {
        self.active_chain.unwrap()
    }

    pub fn has_chain_id(&self) -> bool {
        self.active_chain.is_some()
    }
    pub fn compare_chain_id(&self, chain_id: u64) -> Result<(), ValidationError> {
        match self.active_chain_id {
            None => Err(ValidationError::Error("No active Chain ID.".to_string())),
            Some(active_chain_id) => {
                if active_chain_id == chain_id {
                    Ok(())
                } else {
                    Err(ValidationError::Error(format!(
                        "Chain IDs do not match: {} vs. {}",
                        chain_id, active_chain_id
                    )))
                }
            }
        }
    }

    pub fn get_blockscout_api_key(&self) -> Result<String, ValidationError> {
        match self.active_chain_id {
            None => Err(ValidationError::Error("No chain id chosen.".to_string())),
            Some(chain_id) => {
                // First try chain-specific config
                if let Some(chain_config) = self.blockscout_chain_configs.get(&chain_id) {
                    return Ok(chain_config.api_key.clone());
                }
                // Then try global config
                if let Some(global_config) = &self.blockscout_global {
                    return Ok(global_config.api_key.clone());
                }
                Err(ValidationError::Error(format!(
                    "No Blockscout API Key found in config for chain id {}.",
                    chain_id
                )))
            }
        }
    }

    pub fn get_etherscan_api_key(&self) -> Result<String, ValidationError> {
        match self.active_chain_id {
            None => Err(ValidationError::Error("No chain id chosen.".to_string())),
            Some(chain_id) => {
                // First try chain-specific config
                if let Some(chain_config) = self.etherscan_chain_configs.get(&chain_id) {
                    return Ok(chain_config.api_key.clone());
                }
                // Then try global config
                if let Some(global_config) = &self.etherscan_global {
                    return Ok(global_config.api_key.clone());
                }
                Err(ValidationError::Error(format!(
                    "No Etherscan API Key found in config for chain id {}.",
                    chain_id
                )))
            }
        }
    }

    pub fn get_rpc_url(&self) -> Result<String, ValidationError> {
        match self.active_chain_id {
            None => Err(ValidationError::Error("No chain id chosen.".to_string())),
            Some(chain_id) => match self.rpc_urls.get(&chain_id) {
                None => Err(ValidationError::Error(format!(
                    "No rpc url found in config for chain id {}.",
                    chain_id
                ))),
                Some(rpc_url) => Ok(rpc_url.clone()),
            },
        }
    }

    pub fn get_rpc_url_for(&self, chain_id: u64) -> Result<String, ValidationError> {
        match self.rpc_urls.get(&chain_id) {
            None => Err(ValidationError::Error(format!(
                "No rpc url found in config for chain id {}.",
                chain_id
            ))),
            Some(rpc_url) => Ok(rpc_url.clone()),
        }
    }

    pub fn get_etherscan_api_url(&self) -> Result<String, ValidationError> {
        match self.active_chain_id {
            Some(chain_id) => {
                // First try chain-specific config
                if let Some(chain_config) = self.etherscan_chain_configs.get(&chain_id) {
                    if let Some(api_url) = &chain_config.api_url {
                        return Ok(api_url.clone());
                    } else {
                        return Ok(String::from(Self::DEFAULT_ETHERSCAN_API_URL));
                    }
                }
                // Then try global config
                if let Some(global_config) = &self.etherscan_global {
                    if let Some(api_url) = &global_config.api_url {
                        return Ok(api_url.clone());
                    } else {
                        return Ok(String::from(Self::DEFAULT_ETHERSCAN_API_URL));
                    }
                }
                // Finally fall back to chain-specific URL
                match self.active_chain {
                    Some(active_chain) => match active_chain.etherscan_urls() {
                        Some((api_url, _base_url)) => Ok(api_url.to_string()),
                        None => Err(ValidationError::from(
                            "Invalid active chain. Cannot chose Etherscan API.",
                        )),
                    },
                    None => Err(ValidationError::from(
                        "No active chain. Cannot chose Etherscan API.",
                    )),
                }
            }
            None => Err(ValidationError::from(
                "No active chain. Cannot chose Etherscan API.",
            )),
        }
    }

    pub fn get_blockscout_api_url(&self) -> Result<String, ValidationError> {
        match self.active_chain_id {
            Some(chain_id) => {
                // First try chain-specific config
                if let Some(chain_config) = self.blockscout_chain_configs.get(&chain_id) {
                    if let Some(api_url) = &chain_config.api_url {
                        return Ok(api_url.clone());
                    } else {
                        return Ok(String::from(Self::DEFAULT_BLOCKSCOUT_API_URL));
                    }
                }
                // Then try global config
                if let Some(global_config) = &self.blockscout_global {
                    if let Some(api_url) = &global_config.api_url {
                        return Ok(api_url.clone());
                    } else {
                        return Ok(String::from(Self::DEFAULT_BLOCKSCOUT_API_URL));
                    }
                }
                // Finally fall back to chain-specific URL
                let hostname = match chain_id {
                    // Add More from https://www.blockscout.com/chains-and-projects
                    1 => "eth.blockscout.com/api",
                    10 => "optimism.blockscout.com/api",
                    100 => "gnosis.blockscout.com/api",
                    137 => "polygon.blockscout.com/api",
                    8453 => "base.blockscout.com/api",
                    42161 => "arbitrum.blockscout.com/api",
                    81457 => "blast.blockscout.com/api",
                    11155111 => "eth-sepolia.blockscout.com/api",
                    _ => {
                        return Err(ValidationError::from(format!(
                            "Invalid chain id: {:?}.",
                            self.active_chain_id
                        )))
                    }
                };
                Ok(format!("https://{hostname}"))
            }
            None => Err(ValidationError::from(
                "No active chain. Cannot chose Blockscout API.",
            )),
        }
    }

    pub fn get_graphql_name(&self) -> Result<String, ValidationError> {
        match self.active_chain_id {
            Some(1) => Ok("ethereum".to_string()),
            Some(5) => Ok("goerli".to_string()),
            Some(25) => Ok("cronos".to_string()),
            Some(56) => Ok("bsc".to_string()),
            Some(97) => Ok("bsc_testnet".to_string()),
            Some(137) => Ok("matic".to_string()),
            Some(250) => Ok("fantom".to_string()),
            Some(1284) => Ok("moonbeam".to_string()),
            Some(8217) => Ok("klaytn".to_string()),
            Some(42220) => Ok("celo_mainnet".to_string()),
            Some(43114) => Ok("avalanche".to_string()),
            Some(44787) => Ok("celo_alfajores".to_string()),
            Some(62320) => Ok("celo_baklava".to_string()),
            _ => Err(ValidationError::from(format!(
                "Invalid chain id: {:?}.",
                self.active_chain_id
            ))),
        }
    }
    pub fn write_to_file(&self, path: &PathBuf) -> Result<(), ValidationError> {
        let output = serde_json::to_string_pretty(&self)?;

        let mut file = File::create(path)?;
        file.write_all(output.as_bytes())?;
        file.sync_all().expect("Unable to sync");
        Ok(())
    }

    fn fetch_rpc_url_for(chain_id: &u64) -> Result<String, ValidationError> {
        let client = Client::new();
        let url: &str = &format!("{}/eip155-{}.json", RPC_URLS_REPOSITORY, chain_id);
        let response = client.get(url).send()?;
        let chain_info: serde_json::Value = response.json()?;
        debug!("Fetched JSON: {:?}", chain_info);

        let rpc_urls = chain_info
            .get("rpc")
            .ok_or("No RPC field in JSON object")?
            .as_array()
            .ok_or("The RPC value is not an array")?;
        for rpc_url in rpc_urls {
            // takes the first rpc url that does NOT need API keys
            let rpc_url_str = rpc_url.as_str().ok_or("RPC URL is not a string")?;
            if !rpc_url_str.contains("${") {
                debug!("Fetched RPC URL: {}", rpc_url_str);
                return Ok(rpc_url_str.to_string());
            }
        }
        Err(ValidationError::from(format!(
            "Could not find a suitable RPC URL for chainId {}",
            chain_id
        )))
    }
}

fn replace_tilde_from_path(path: &Path) -> Result<PathBuf, ValidationError> {
    let path_str = path
        .to_str()
        .ok_or_else(|| ValidationError::from("Path cannot be converted to string"))?;
    replace_tilde(path_str)
}

pub fn replace_tilde(path_str: &str) -> Result<PathBuf, ValidationError> {
    if path_str.starts_with('~') {
        let mut home_path: PathBuf = home_dir()
            .ok_or_else(|| ValidationError::from("Home directory used in path, but not found"))?;

        if path_str.len() > 2 {
            home_path.push(&path_str[2..]);
        }

        Ok(home_path)
    } else {
        Ok(PathBuf::from(path_str))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replace_tilde_with_home_dir() {
        let path = PathBuf::from("~/Documents");
        let expected_path = home_dir().unwrap().join("Documents");
        assert_eq!(replace_tilde_from_path(&path).unwrap(), expected_path);
    }

    #[test]
    fn test_replace_tilde_only() {
        let path = PathBuf::from("~");
        let expected_path = home_dir().unwrap();
        assert_eq!(replace_tilde_from_path(&path).unwrap(), expected_path);
    }

    #[test]
    fn test_no_tilde() {
        let path = PathBuf::from("/usr/local/bin");
        assert_eq!(replace_tilde_from_path(&path).unwrap(), path);
    }
}
