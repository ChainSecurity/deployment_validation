use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::Read;
use std::str::FromStr;
use std::time::Duration;

use colored::Colorize;
use indicatif::ProgressBar;
use reqwest::blocking::get;
use reqwest::blocking::Client;
use serde::{de, de::Visitor, Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use tiny_keccak::Hasher;
use tiny_keccak::Keccak;
use tracing::{debug, info, warn};

use crate::dvf::config::DVFConfig;
use crate::dvf::parse::ValidationError;

use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::rpc::types::{Block, EIP1186AccountProofResponse, Log, Transaction, TransactionReceipt};
use alloy_rpc_types_trace::geth::{CallFrame, DefaultFrame, DiffMode, StructLog};
use alloy_rpc_types_trace::parity::{
    Action, LocalizedTransactionTrace, TraceOutput, TransactionTrace,
};

use reth_trie::root;

const NUM_STORAGE_QUERIES: u64 = 32;
const LARGE_BLOCK_RANGE: u64 = 100000;

mod pathological_rpc_deserde {
    use serde::{self, Deserialize};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: super::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        u64::from_str_radix(s.trim_start_matches("0x"), 16).map_err(serde::de::Error::custom)
    }
}

// @note Some rpc returns gas in hex string
// Copy pasted the alloy DefaultFrame with customized deserde impl
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntermediateDefaultFrame {
    /// Whether the transaction failed
    pub failed: bool,
    /// How much gas was used.
    #[serde(deserialize_with = "pathological_rpc_deserde::deserialize")]
    pub gas: u64,
    /// Output of the transaction
    pub return_value: Bytes,
    /// Recorded traces of the transaction
    pub struct_logs: Vec<StructLog>,
}

impl From<IntermediateTraceWithAddress> for TraceWithAddress {
    fn from(x: IntermediateTraceWithAddress) -> Self {
        let df = DefaultFrame {
            failed: x.trace.failed,
            gas: x.trace.gas,
            return_value: x.trace.return_value,
            struct_logs: x.trace.struct_logs,
        };
        TraceWithAddress {
            trace: df,
            address: x.address,
            tx_id: x.tx_id,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IntermediateTraceWithAddress {
    pub trace: IntermediateDefaultFrame,
    pub address: Address,
    pub tx_id: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TraceWithAddress {
    pub trace: DefaultFrame,
    pub address: Address,
    pub tx_id: String,
}

pub fn get_block_traces(
    config: &DVFConfig,
    block_num: u64,
) -> Result<Vec<LocalizedTransactionTrace>, ValidationError> {
    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "trace_block",
        "params": [block_num],
        "id": 1
    });
    let result = send_blocking_web3_post(config, &request_body)?;
    let traces: Vec<LocalizedTransactionTrace> = serde_json::from_value(result)?;
    Ok(traces)
}

pub fn get_geth_block_traces(
    config: &DVFConfig,
    block_num: u64,
) -> Result<Vec<CallFrame>, ValidationError> {
    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "debug_traceBlockByNumber",
        "params": [block_num, {"tracer": "callTracer"}],
        "id": 1
    });
    let result = send_blocking_web3_post(config, &request_body)?;
    // Parse the response as a JSON list
    let traces: Vec<CallFrame> = serde_json::from_value(result)?;
    Ok(traces)
}

pub fn get_eth_diff_trace(config: &DVFConfig, tx_id: &str) -> Result<DiffMode, ValidationError> {
    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "debug_traceTransaction",
        "params": [tx_id, {"tracer": "prestateTracer", "tracerConfig": {"diffMode": true}}],
        "id": 1
    });
    let result = send_blocking_web3_post(config, &request_body)?;
    // Parse the response as a JSON list
    let trace: DiffMode = serde_json::from_value(result)?;
    Ok(trace)
}

pub fn get_many_diff_traces(
    config: &DVFConfig,
    tx_hashes: &Vec<String>,
) -> Result<Vec<DiffMode>, ValidationError> {
    let mut all_diffs: Vec<DiffMode> = vec![];
    for tx_hash in tx_hashes {
        all_diffs.push(get_eth_diff_trace(config, tx_hash)?);
    }
    Ok(all_diffs)
}

pub fn get_many_debug_traces(
    config: &DVFConfig,
    tx_hashes: &Vec<String>,
) -> Result<Vec<TraceWithAddress>, ValidationError> {
    let mut all_traces: Vec<TraceWithAddress> = vec![];
    for tx_hash in tx_hashes {
        all_traces.push(get_eth_debug_trace(config, tx_hash)?);
    }
    Ok(all_traces)
}

pub fn get_init_code(
    config: &DVFConfig,
    tx_id: &String,
    address: &Address,
) -> Result<String, ValidationError> {
    info!("Get init code for {:?}", address);

    // create a mapping for failed traces
    let mut failed_parity_traces: HashMap<Vec<usize>, bool> = HashMap::new();

    match get_tx_trace(config, tx_id) {
        Ok(traces) => {
            for trace in &traces {
                let trace_address = &trace.trace_address;

                if trace.error.is_some()
                    || (trace_address.len() > 1
                        && failed_parity_traces
                            .contains_key(&trace_address[..trace_address.len() - 1]))
                {
                    failed_parity_traces.insert(trace_address.clone(), true); // make subtraces fail
                    continue;
                }

                if let (Action::Create(create_action), Some(TraceOutput::Create(create_res))) =
                    (&trace.action, &trace.result)
                {
                    if &create_res.address == address {
                        let init_code = format!("{:#x}", create_action.init);
                        return Ok(init_code);
                    }
                }
            }
            Err(ValidationError::from(format!(
                "Found no deployment trace for tx {:?} and contract {:?}",
                tx_id, address
            )))?
        }
        Err(_e) => {
            let call_frame = get_eth_debug_call_trace(config, tx_id)?;

            match extract_create_call_frame(&call_frame, address) {
                Ok(call_frame) => {
                    let init_code = format!("{:#x}", call_frame.input);
                    Ok(init_code)
                }
                Err(e) => Err(e),
            }
        }
    }
}

// Searches recursively for create call frame
// Ignores reverting call frames
fn extract_create_call_frame(
    call_frame: &CallFrame,
    address: &Address,
) -> Result<CallFrame, ValidationError> {
    if call_frame.typ.starts_with("CREATE")
        && call_frame.error.is_none()
        && call_frame.to.as_ref() == Some(address)
    {
        return Ok(call_frame.clone());
    }

    for call in &call_frame.calls {
        if call.error.is_none() {
            if let Ok(call_frame) = extract_create_call_frame(call, address) {
                return Ok(call_frame);
            }
        }
    }

    Err(ValidationError::from("Cannot determine create addresses"))
}
pub fn get_eth_debug_call_trace(
    config: &DVFConfig,
    tx_id: &str,
) -> Result<CallFrame, ValidationError> {
    debug!("Searching debug trace for {tx_id}");
    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "debug_traceTransaction",
        "params": [tx_id, {"tracer": "callTracer"}],
        "id": 1
    });
    let result = send_blocking_web3_post(config, &request_body)?;
    // Parse the response as a JSON list
    let trace: CallFrame = serde_json::from_value(result)?;
    Ok(trace)
}

pub fn get_eth_debug_trace(
    config: &DVFConfig,
    tx_id: &str,
) -> Result<TraceWithAddress, ValidationError> {
    debug!("Obtaining debug trace.");
    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "debug_traceTransaction",
        "params": [tx_id, {"enableMemory": true, "enableStorage": true, "enableReturnData": false}],
        "id": 1
    });
    let result = send_blocking_web3_post(config, &request_body)?;
    // Parse the response as a JSON list
    let trace: DefaultFrame = serde_json::from_value(result)?;

    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "eth_getTransactionReceipt",
        "params": [tx_id],
        "id": 1
    });
    let result = send_blocking_web3_post(config, &request_body)?;
    // Parse the response as a JSON list
    let receipt: TransactionReceipt = serde_json::from_value(result)?;

    let tx_id = tx_id.to_string();
    if let Some(address) = receipt.to {
        Ok(TraceWithAddress {
            trace,
            address,
            tx_id,
        })
    } else if let Some(address) = receipt.contract_address {
        return Ok(TraceWithAddress {
            trace,
            address,
            tx_id,
        });
    } else {
        return Err(ValidationError::from(format!(
            "Found no address for tx {}",
            tx_id
        )));
    }
}

// Returns create addresses of internal calls, if the initial call is a create, then it is not included
// Reverting creates are indicated with a Zero address
fn extract_create_addresses_from_call_frame(
    call_frame: &CallFrame,
    addresses: &mut Vec<Address>,
    is_first: bool,
) -> Result<(), ValidationError> {
    if !is_first && call_frame.typ.starts_with("CREATE") {
        let rec = call_frame.to.as_ref();
        match rec {
            Some(addr) => addresses.push(*addr),
            None => {
                // This is a reverting create
                // We insert zero to keep it aligned with later parsing
                addresses.push(Address::from([0; 20]));
            }
        };
    }
    for call in &call_frame.calls {
        extract_create_addresses_from_call_frame(call, addresses, false)?;
    }
    Ok(())
}

// Returns create addresses of internal calls, if the initial call is a create, then it is not included
pub fn get_internal_create_addresses(
    config: &DVFConfig,
    tx_id: &str,
) -> Result<Vec<Address>, ValidationError> {
    let mut addresses: Vec<Address> = vec![];
    match get_tx_trace(config, tx_id) {
        Ok(traces) => {
            for trace in &traces[1..] {
                if let Action::Create(_) = trace.action {
                    if let Some(TraceOutput::Create(create_res)) = &trace.result {
                        addresses.push(create_res.address);
                    } else {
                        return Err(ValidationError::from(format!(
                            "Fatal: Trace for {tx_id} has a create without a create result."
                        )));
                    }
                }
            }
        }
        Err(e) => {
            debug!("Tracing failed with {:?}, trying backup.", e);
            let call_frame = get_eth_debug_call_trace(config, tx_id)?;
            extract_create_addresses_from_call_frame(&call_frame, &mut addresses, true)?;
        }
    };
    debug!("Create addresses for {} are: {:?}", tx_id, addresses);
    Ok(addresses)
}

#[derive(Debug, Serialize, Deserialize)]
struct OtsContractCreator {
    #[serde(rename = "creator")]
    pub contract_creator: String,
    #[serde(rename = "hash")]
    pub tx_hash: String,
}

fn get_ots_contract_creator(
    config: &DVFConfig,
    address: &Address,
) -> Result<OtsContractCreator, ValidationError> {
    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "ots_getContractCreator",
        "params": [address],
        "id": 1
    });
    let result = send_blocking_web3_post(config, &request_body)?;
    // Parse the response as a JSON list
    let result: OtsContractCreator = serde_json::from_value(result)?;

    Ok(result)
}

fn get_tx_trace(config: &DVFConfig, tx_id: &str) -> Result<Vec<TransactionTrace>, ValidationError> {
    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "trace_transaction",
        "params": [tx_id],
        "id": 1
    });
    let result = send_blocking_web3_post(config, &request_body)?;
    // Parse the response as a JSON list
    let trace: Vec<TransactionTrace> = serde_json::from_value(result)?;
    Ok(trace)
}

#[derive(Debug, Serialize, Deserialize)]
struct EtherscanCreationTransaction {
    #[serde(rename = "contractCreator")]
    pub contract_creator: String,
    #[serde(rename = "txHash")]
    pub tx_hash: String,
    // ... much more we don't care about: https://docs.etherscan.io/api-endpoints/contracts
}

#[derive(Debug, Deserialize)]
struct BlockscoutApiResponse {
    status: String,
    message: String,
    result: serde_json::Value,
}

// https://docs.blockscout.com/developer-support/api/rpc-endpoints/contract#get-contract-creator-address-hash-and-creation-transaction-hash
#[derive(Debug, Deserialize)]
struct ContractCreation {
    #[serde(alias = "txHash")]
    transaction_hash: String,
}

#[derive(Debug, Deserialize, Eq)]
struct TransactionDetail {
    #[serde(rename = "transactionHash")]
    #[serde(alias = "hash")]
    transaction_hash: String,
    #[serde(rename = "transactionIndex")]
    #[serde(alias = "index")]
    #[serde(deserialize_with = "deserialize_dec_u64")]
    transaction_index: u64,
    #[serde(rename = "blockNumber")]
    #[serde(deserialize_with = "deserialize_dec_u64")]
    block_number: u64,
}

impl PartialOrd for TransactionDetail {
    fn partial_cmp(&self, other: &TransactionDetail) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TransactionDetail {
    fn cmp(&self, other: &Self) -> Ordering {
        self.block_number
            .cmp(&other.block_number)
            .then_with(|| self.transaction_index.cmp(&other.transaction_index))
    }
}

impl PartialEq for TransactionDetail {
    fn eq(&self, other: &Self) -> bool {
        self.transaction_hash.to_lowercase() == other.transaction_hash.to_lowercase()
    }
}

fn deserialize_dec_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    struct U64Visitor;

    impl Visitor<'_> for U64Visitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a decimal string")
        }

        fn visit_str<E>(self, v: &str) -> Result<u64, E>
        where
            E: de::Error,
        {
            Ok(u64::from_str(v).unwrap())
        }
    }
    deserializer.deserialize_string(U64Visitor)
}

fn get_deployment_tx_from_etherscan(
    config: &DVFConfig,
    address: &Address,
) -> Result<EtherscanCreationTransaction, ValidationError> {
    let url = format!(
        "{}?chainid={}&module=contract&action=getcontractcreation&contractaddresses={:?}&apikey={}",
        config.get_etherscan_api_url()?,
        config.active_chain_id.unwrap(),
        address,
        config.get_etherscan_api_key()?
    );
    debug!("Etherscan URL: {}", url);

    // Send the GET request
    let mut response = get(&url)?;

    // Read the response into a string
    let mut buffer = String::new();
    response.read_to_string(&mut buffer)?;

    let result: EtherscanResult = serde_json::from_str(&buffer)?;
    debug!("Etherscan contract creation response: {}", buffer);
    // Parse the response as a JSON list
    let mut transactions: Vec<EtherscanCreationTransaction> =
        serde_json::from_value(result.result)?;
    let transaction = transactions.remove(0);

    Ok(transaction)
}

fn send_blocking_blockscout_get(
    config: &DVFConfig,
    request: &str,
) -> Result<serde_json::Value, ValidationError> {
    let client = Client::builder()
        .timeout(Duration::from_secs(config.web3_timeout))
        .build()
        .unwrap();

    let full_url = format!(
        "{}{}&apikey={}",
        config.get_blockscout_api_url()?,
        request,
        config.get_blockscout_api_key()?
    );
    debug!("Blockscout URL: {}", full_url);

    let res = client
        .get(&full_url)
        .send()?
        .json::<BlockscoutApiResponse>()?;

    if res.status == "0"
        && res.message.starts_with("No")
        && res.message.ends_with("transactions found")
    {
        return Ok(json!([]));
    }
    if res.message != "OK" || res.status != "1" {
        debug!("Blockscout Error: {}, {}", res.message, res.status);
        return Err(ValidationError::from(format!(
            "Blockscout Error: {}, {}",
            res.message, res.status
        )));
    };

    Ok(res.result)
}

fn send_blocking_web3_post(
    config: &DVFConfig,
    request_body: &serde_json::Value,
) -> Result<serde_json::Value, ValidationError> {
    let client = Client::builder()
        .timeout(Duration::from_secs(config.web3_timeout))
        .build()
        .unwrap();

    let node_url = config.get_rpc_url()?;

    debug!("Web3 request_body: {:?}", request_body);
    let res = client
        .post(node_url)
        .json(&request_body)
        .send()?
        .json::<Web3Response>()?;

    if let Some(error) = res.error {
        return Err(ValidationError::from(format!("Web3Error: {:?}", error)));
    };

    debug!("Web3 response: {:?}", res.result);
    match res.result {
        Some(result) => Ok(result),
        None => Err(ValidationError::Error(
            "No result for web3 request.".to_string(),
        )),
    }
}

pub fn get_block_number_for_tx(
    config: &DVFConfig,
    transaction_hash: &str,
) -> Result<u64, ValidationError> {
    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "eth_getTransactionByHash",
        "params": [transaction_hash],
        "id": 1
    });
    let result = send_blocking_web3_post(config, &request_body)?;

    if let Some(block_number) = result.get("blockNumber") {
        let block_number =
            u64::from_str_radix(block_number.as_str().unwrap().trim_start_matches("0x"), 16)?;
        return Ok(block_number);
    }
    Err(ValidationError::Error(
        "Invalid response from eth_getTransactionByHash".to_string(),
    ))
}

// Not every rpc supports eth_getAccount.
// So we have to retrieve the account by querying an empty storage proof
pub fn get_eth_account_at_block(
    config: &DVFConfig,
    account: &Address,
    block: u64,
) -> Result<B256, ValidationError> {
    let block_hex = format!("{:#x}", block);
    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "eth_getProof",
        "params": [
            account,
            [], // slots
            block_hex,
            ],
        "id": 1
    });

    let result = send_blocking_web3_post(config, &request_body)?;

    let proof_resp: EIP1186AccountProofResponse = serde_json::from_value(result)?;

    Ok(proof_resp.storage_hash)
}

fn get_deployment_tx_from_blockscout(
    config: &DVFConfig,
    address: &Address,
) -> Result<String, ValidationError> {
    let url = format!(
        "?module=contract&action=getcontractcreation&contractaddresses={:?}",
        address
    );

    let result = send_blocking_blockscout_get(config, &url)?;
    let creation: ContractCreation = serde_json::from_value(result)?;

    Ok(creation.transaction_hash.clone())
}

pub fn get_deployment_block(config: &DVFConfig, address: &Address) -> Result<u64, ValidationError> {
    let deployment: Result<(u64, String), ValidationError> = get_deployment(config, address);
    match deployment {
        Ok((block_num, _tx_hash)) => Ok(block_num),
        Err(e) => Err(e),
    }
}

// Search between start_block_num and end_block_num (inclusive)
// Iterates through those blocks
// Returns block number and tx hash
fn get_deployment_from_parity_trace(
    config: &DVFConfig,
    address: &Address,
    start_block_num: u64,
    end_block_num: u64,
) -> Result<(u64, String), ValidationError> {
    debug!("Searching parity traces for deployment tx");
    for i in start_block_num..end_block_num + 1 {
        let block_traces = get_block_traces(config, i)?;
        for trace in block_traces {
            // Filter reverted
            if trace.trace.error.is_none() {
                // Look Through creates
                if let Some(TraceOutput::Create(create_res)) = &trace.trace.result {
                    if create_res.address == *address {
                        if let Some(tx_hash) = trace.transaction_hash {
                            debug!("Searched Deployment Tx: {:?}", tx_hash);
                        }
                        let tx_hash = format!("{:#x}", trace.transaction_hash.unwrap());
                        return Ok((i, tx_hash));
                    }
                }
            }
        }
    }
    Err(ValidationError::from(
        "Could not find deployment transaction.",
    ))
}

// Search between start_block_num and end_block_num (inclusive)
// Iterates through those blocks
// Returns block number and tx hash
fn get_deployment_from_geth_trace(
    config: &DVFConfig,
    address: &Address,
    start_block_num: u64,
    end_block_num: u64,
) -> Result<(u64, String), ValidationError> {
    debug!("Searching geth traces for deployment tx of {:?}", address);
    for i in start_block_num..end_block_num + 1 {
        let block = get_eth_block_by_num(config, i, true)?;
        if let Some(txs) = block.transactions.as_transactions() {
            for tx in txs {
                let tx_hash = format!("{:#x}", tx.inner.tx_hash());
                let call_frame = get_eth_debug_call_trace(config, &tx_hash)?;
                let mut addresses: Vec<Address> = vec![];
                extract_create_addresses_from_call_frame(&call_frame, &mut addresses, false)?;
                debug!("Found {:?}", addresses);
                if addresses.contains(address) {
                    return Ok((i, tx_hash));
                }
            }
        }
    }
    Err(ValidationError::from(
        "Could not find deployment transaction.",
    ))
}

pub fn get_deployment(
    config: &DVFConfig,
    address: &Address,
) -> Result<(u64, String), ValidationError> {
    // First try etherscan
    if let Ok(deployment_tx) = get_deployment_tx_from_etherscan(config, address) {
        let deployment_tx_hash = deployment_tx.tx_hash;
        debug!("Etherscan Deployment Tx: {}", deployment_tx_hash);
        let deployment_block_num = get_block_number_for_tx(config, deployment_tx_hash.as_str())?;
        return Ok((deployment_block_num, deployment_tx_hash));
    } else if let Ok(deployment_tx_hash) = get_deployment_tx_from_blockscout(config, address) {
        debug!("Blockscout Deployment Tx: {}", deployment_tx_hash);
        let deployment_block_num = get_block_number_for_tx(config, deployment_tx_hash.as_str())?;
        return Ok((deployment_block_num, deployment_tx_hash));
    } else if let Ok(creator) = get_ots_contract_creator(config, address) {
        debug!("Otterscan Deployment Tx: {}", creator.tx_hash);
        let deployment_block_num = get_block_number_for_tx(config, creator.tx_hash.as_str())?;
        return Ok((deployment_block_num, creator.tx_hash));
    } else {
        debug!("No deployment tx found in etherscan or blockscout, searching traces. ");
        let current_block_num = get_eth_block_number(config)?;
        let start_block_num = if current_block_num > 10 {
            get_deployment_block_from_binary_search(config, address, current_block_num)?
        } else {
            1
        };

        if let Ok((deployment_block_num, deployment_tx_hash)) =
            get_deployment_from_parity_trace(config, address, start_block_num, current_block_num)
        {
            return Ok((deployment_block_num, deployment_tx_hash));
        }
        if let Ok((deployment_block_num, deployment_tx_hash)) =
            get_deployment_from_geth_trace(config, address, start_block_num, current_block_num)
        {
            return Ok((deployment_block_num, deployment_tx_hash));
        }
    }

    Err(ValidationError::from(
        "Could not find deployment transaction.",
    ))
}

pub fn get_deployment_block_from_binary_search(
    config: &DVFConfig,
    address: &Address,
    current_block_num: u64,
) -> Result<u64, ValidationError> {
    let mut low: u64 = 0;
    let mut high = current_block_num;

    while high - low > 1 {
        let mid = (low + high) / 2;

        let code = get_eth_code(config, address, mid)?;

        if code.trim_start_matches("0x").is_empty() {
            low = mid;
        } else {
            high = mid;
        }
    }

    if !(get_eth_code(config, address, high)?
        .trim_start_matches("0x")
        .is_empty())
    {
        return Ok(high);
    }

    Err(ValidationError::from(
        "Could not find deployment transaction.",
    ))
}

#[derive(Debug, Serialize, Deserialize)]
struct Web3Result {
    pub jsonrpc: String,
    pub id: u64,
    pub result: Value,
}

#[derive(Debug, Serialize, Deserialize)]
struct Web3Response {
    pub jsonrpc: String,
    pub id: u64,
    pub result: Option<Value>,
    pub error: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize)]
struct EtherscanResult {
    pub status: String,
    pub message: String,
    pub result: Value,
    // ... much more we don't care about: https://docs.etherscan.io/api-endpoints/accounts
}

// Inclusive for start_block and end_block
pub fn get_all_txs_for_contract(
    config: &DVFConfig,
    address: &Address,
    start_block: u64,
    end_block: u64,
) -> Result<Vec<String>, ValidationError> {
    if let Ok(all_txs) =
        get_combined_txs_for_contract_from_etherscan(config, address, start_block, end_block)
    {
        return Ok(all_txs);
    } else if let Ok(all_txs) =
        get_all_txs_for_contract_from_blockscout(config, address, start_block, end_block)
    {
        return Ok(all_txs);
    } else if end_block - start_block <= 100 {
        if let Ok(all_txs) =
            get_all_txs_for_contract_from_parity_traces(config, address, start_block, end_block)
        {
            return Ok(all_txs);
        } else if let Ok(all_txs) =
            get_all_txs_for_contract_from_geth_traces(config, address, start_block, end_block)
        {
            return Ok(all_txs);
        }
    }
    Err(ValidationError::from(format!(
        "Could not find transactions for {:?} from {} to {}.",
        address, start_block, end_block
    )))
}

// Checks if an address is used in this call frame (or subcalls)
// Ignores reverting executions
fn call_frame_contains(call_frame: &CallFrame, address: &Address) -> bool {
    if call_frame.error.is_none() && call_frame.to.as_ref() == Some(address) {
        return true;
    }

    for call in &call_frame.calls {
        if call_frame_contains(call, address) {
            return true;
        }
    }
    false
}

fn tx_geth_trace_contains(
    config: &DVFConfig,
    tx_hash: &str,
    address: &Address,
) -> Result<bool, ValidationError> {
    let call_frame = get_eth_debug_call_trace(config, tx_hash)?;
    Ok(call_frame_contains(&call_frame, address))
}

// Inclusive for start_block and end_block
fn get_all_txs_for_contract_from_geth_traces(
    config: &DVFConfig,
    address: &Address,
    start_block: u64,
    end_block: u64,
) -> Result<Vec<String>, ValidationError> {
    let mut res: Vec<String> = Vec::new();
    for i in start_block..end_block + 1 {
        let block = get_eth_block_by_num(config, i, true)?;
        if let Some(txs) = block.transactions.as_transactions() {
            for tx in txs {
                let tx_hash = format!("{:#x}", tx.inner.tx_hash());
                if tx_geth_trace_contains(config, &tx_hash, address)? {
                    res.push(tx_hash);
                }
            }
        }
    }
    Ok(res)
}

// Inclusive for start_block and end_block
fn get_all_txs_for_contract_from_parity_traces(
    config: &DVFConfig,
    address: &Address,
    start_block: u64,
    end_block: u64,
) -> Result<Vec<String>, ValidationError> {
    let mut res: Vec<B256> = Vec::new();
    // TODO: Use trace_filter
    for block_num in start_block..end_block + 1 {
        let block_traces = get_block_traces(config, block_num)?;
        // Search for relevant traces
        debug!("{:?}", block_traces);
        for trace in block_traces {
            // See if contract was created here
            if let Some(TraceOutput::Create(create_res)) = &trace.trace.result {
                if create_res.address == *address {
                    if let Some(tx_hash) = trace.transaction_hash {
                        if !res.contains(&tx_hash) {
                            res.push(tx_hash);
                        }
                    }
                }
            } else if let Action::Call(call) = &trace.trace.action {
                if call.to == *address {
                    if let Some(tx_hash) = trace.transaction_hash {
                        if !res.contains(&tx_hash) {
                            res.push(tx_hash);
                        }
                    }
                }
            } else if let Action::Selfdestruct(suicide) = &trace.trace.action {
                if suicide.refund_address == *address {
                    if let Some(tx_hash) = trace.transaction_hash {
                        if !res.contains(&tx_hash) {
                            res.push(tx_hash);
                        }
                    }
                }
            } else if let Action::Reward(reward) = &trace.trace.action {
                if reward.author == *address {
                    if let Some(tx_hash) = trace.transaction_hash {
                        if !res.contains(&tx_hash) {
                            res.push(tx_hash);
                        }
                    }
                }
            }
        }
    }
    Ok(res.iter().map(|tx| format!("{:?}", tx)).collect())
}

/*
// Inclusive for start_block and end_block
fn get_first_tx_for_contract_from_blockscout(
    config: &DVFConfig,
    address: &Address,
    start_block: u64,
    end_block: u64,
) -> Result<String, ValidationError> {
    let mut txs: Vec<String> = vec![];

    // Parameters for the query
    let page = 1;
    let offset = 1;
    let sort = "asc";
    // Build the full URL with query parameters
    let url = format!(
            "?module=account&action=txlistinternal&address={:?}&startblock={}&endblock={}&page={}&offset={}&sort={}",
            address, start_block, end_block, page, offset, sort
        );

    let result = send_blocking_blockscout_get(config, &url)?;
    let internal_txs: Vec<TransactionDetail> = serde_json::from_value(result)?;
    for internal_tx in internal_txs {
        if !txs.contains(&internal_tx.transaction_hash) {
            txs.push(internal_tx.transaction_hash);
        }
    }

    if txs.len() != 1 {
        return Err(ValidationError::from("Blockscout could not find first tx."));
    }

    Ok(txs[0].clone())
}*/

// Inclusive for start_block and end_block
fn get_some_txs_for_contract_from_blockscout(
    config: &DVFConfig,
    address: &Address,
    start_block: u64,
    end_block: u64,
    internal: bool,
) -> Result<Vec<TransactionDetail>, ValidationError> {
    let mut txs: Vec<TransactionDetail> = vec![];

    // Parameters for the query
    let mut page = 1;
    let offset = 50;
    let sort = "asc";
    let internal_str = match internal {
        true => String::from("internal"),
        false => String::from(""),
    };

    loop {
        // Build the full URL with query parameters
        let url = format!(
            "?module=account&action=txlist{}&address={:?}&startblock={}&endblock={}&page={}&offset={}&sort={}",
            internal_str, address, start_block, end_block, page, offset, sort
        );

        let result = send_blocking_blockscout_get(config, &url)?;
        debug!("Trying to parse");
        let internal_txs: Vec<TransactionDetail> = serde_json::from_value(result).unwrap();
        debug!("Parsing worked.");
        let num_internal_txs = internal_txs.len();
        for internal_tx in internal_txs {
            if !txs.contains(&internal_tx) {
                txs.push(internal_tx);
            }
        }
        if num_internal_txs < offset {
            break;
        } else {
            page += 1;
        }
    }

    debug!("Found {} {} transactions.", txs.len(), internal_str);
    if txs.is_empty() {
        if internal {
            println!("{}", "Warning: 0 internal transactions found".yellow());
        } else {
            println!("{}", "Warning: 0 external transactions found".yellow());
        }
    }
    Ok(txs)
}

// Inclusive for start_block and end_block
fn get_all_txs_for_contract_from_blockscout(
    config: &DVFConfig,
    address: &Address,
    start_block: u64,
    end_block: u64,
) -> Result<Vec<String>, ValidationError> {
    let mut combined =
        get_some_txs_for_contract_from_blockscout(config, address, start_block, end_block, true)?;
    let external_txs =
        get_some_txs_for_contract_from_blockscout(config, address, start_block, end_block, false)?;

    // Combine the two lists of external and internal transactions
    combined.extend(external_txs);

    // Sort the combined Vec
    combined.sort();

    // Remove potential duplicates
    combined.dedup();

    let txs: Vec<String> = combined
        .iter()
        .map(|tx| tx.transaction_hash.clone())
        .collect();
    debug!("Found {} total transactions: {:?}", txs.len(), txs);
    Ok(txs)
}

// Inclusive for start_block and end_block
// WILL ACCEPT FAILURE AS IT ASSUMES THIS HAPPENS ONLY FOR MAPPING SLOTS
// Failures are most likely due to timeouts in big TXs
pub fn get_all_traces_for_contract(
    config: &DVFConfig,
    address: &Address,
    start_block: u64,
    end_block: u64,
) -> Result<Vec<TraceWithAddress>, ValidationError> {
    let tx_hashes: Vec<String> = get_all_txs_for_contract(config, address, start_block, end_block)?;
    let mut traces: Vec<TraceWithAddress> = vec![];

    let pb = ProgressBar::new(tx_hashes.len().try_into().unwrap());

    let mut seen_transactions = HashSet::new();
    for tx_hash in &tx_hashes {
        if seen_transactions.contains(tx_hash) {
            continue;
        }
        seen_transactions.insert(tx_hash);
        info!("Getting trace for {}", tx_hash);
        match get_eth_debug_trace(config, tx_hash){
            Ok(trace) => traces.push(trace),
            Err(_) => info!("Warning. The trace for {tx_hash} cannot be obtained. Some mapping slots might not be decodable. You can try to increase the timeout in the config."),
        };
        pb.inc(1);
    }
    pb.finish_and_clear();
    debug!("Found {} traces.", traces.len());
    Ok(traces)
}

pub fn get_eth_block_number(config: &DVFConfig) -> Result<u64, ValidationError> {
    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "eth_blockNumber",
        "params": [],
        "id": 1
    });

    let result = send_blocking_web3_post(config, &request_body)?;

    let block_num: u64 = u64::from_str_radix(result.as_str().unwrap().trim_start_matches("0x"), 16)
        .expect("Couldn't parse hex from eth_blockNumber");

    Ok(block_num)
}

pub fn get_eth_chain_id(config: &DVFConfig) -> Result<u64, ValidationError> {
    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "eth_chainId",
        "params": [],
        "id": 1
    });
    let result = send_blocking_web3_post(config, &request_body)?;

    let chain_id: u64 =
        u64::from_str_radix(result.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();

    Ok(chain_id)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Web3Event {
    pub topics: Vec<String>,
    pub data: String,
    #[serde(rename = "blockNumber")]
    pub block_number: String,
    #[serde(rename = "transactionIndex")]
    transaction_index: String,
}

// Fetches events, does multiple calls if necessary
// Inclusive for from_block and to_block
pub fn get_eth_events(
    config: &DVFConfig,
    address: &Address,
    from_block: u64,
    to_block: u64,
    topics: &Vec<B256>,
) -> Result<Vec<Log>, ValidationError> {
    if to_block - from_block > config.max_blocks_per_event_query {
        let pb = ProgressBar::new(to_block - from_block);
        if to_block - from_block > LARGE_BLOCK_RANGE {
            let mut num_events = String::new();
            if topics.is_empty() {
                num_events.push_str("all");
            } else {
                num_events.push_str(&topics.len().to_string());
            }
            info!(
                "You are querying {} event(s) for a range of {} blocks. This will take some time.",
                num_events,
                to_block - from_block + 1
            );
        }
        let mut last_block = from_block + config.max_blocks_per_event_query;
        let mut events = get_eth_events(config, address, from_block, last_block, topics)?;
        while last_block < to_block {
            let next_last_block =
                std::cmp::min(last_block + config.max_blocks_per_event_query - 1, to_block);
            let mut next_events =
                get_eth_events(config, address, last_block + 1, next_last_block, topics)?;
            last_block = next_last_block;
            pb.set_position(next_last_block - from_block);
            events.append(&mut next_events);
        }
        pb.finish_and_clear();
        return Ok(events);
    }
    let from_block_hex = format!("{:#x}", from_block);
    let to_block_hex = format!("{:#x}", to_block);
    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "eth_getLogs",
        "params": [{"address": address, "fromBlock": from_block_hex, "toBlock": to_block_hex, "topics": topics}],
        "id": 1
    });
    let result = send_blocking_web3_post(config, &request_body)?;
    let events: Vec<Log> = serde_json::from_value(result)?;
    debug!("Found {} events.", events.len());
    debug!("{:?}", events);
    Ok(events)
}

#[derive(Debug, Serialize, Deserialize)]
struct StorageRangeEntry {
    pub key: B256,
    pub value: B256,
}

#[derive(Debug, Serialize, Deserialize)]
struct StorageRange {
    pub storage: HashMap<String, StorageRangeEntry>,
    #[serde(rename = "nextKey")]
    pub next_key: Value,
}

fn get_eth_storage_range_response(
    config: &DVFConfig,
    address: &Address,
    init_block_hash: &str,
    offset: String,
) -> Result<StorageRange, ValidationError> {
    debug!(
        "Querying storage range of {:?} @ {} starting from {}.",
        address, init_block_hash, offset
    );

    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "debug_storageRangeAt",
        "params": [init_block_hash, 0, address, offset, NUM_STORAGE_QUERIES],
        "id": 1
    });
    let result = send_blocking_web3_post(config, &request_body)?;
    let storage_range: StorageRange = serde_json::from_value(result)?;
    debug!("Received storage range: {:?}", storage_range);
    Ok(storage_range)
}

pub fn get_eth_code(
    config: &DVFConfig,
    address: &Address,
    block_num: u64,
) -> Result<String, ValidationError> {
    let block_num_hex = format!("{:#x}", block_num);

    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "eth_getCode",
        "params": [address, block_num_hex],
        "id": 1
    });
    let result = send_blocking_web3_post(config, &request_body)?;
    let code: String = serde_json::from_value(result).unwrap_or_default();
    Ok(code)
}

pub fn get_eth_storage_at(
    config: &DVFConfig,
    address: &Address,
    slot: &U256,
    block_num: u64,
) -> Result<[u8; 32], ValidationError> {
    let block_num_hex = format!("{:#x}", block_num);

    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "eth_getStorageAt",
        "params": [address, slot, block_num_hex],
        "id": 1
    });
    let result = send_blocking_web3_post(config, &request_body)?;

    let val: B256 = serde_json::from_value(result).unwrap_or_default();
    debug!(
        "The storage value of the contract {} at {} in {} is {}",
        address, block_num, slot, val
    );
    Ok(val.0)
}

pub fn get_eth_block_timestamp(config: &DVFConfig, block_num: u64) -> Result<u64, ValidationError> {
    Ok(get_eth_block_by_num(config, block_num, false)?
        .header
        .inner
        .timestamp)
}

fn get_eth_blockhash_by_num(config: &DVFConfig, block_num: u64) -> Result<String, ValidationError> {
    Ok(format!(
        "{:?}",
        get_eth_block_by_num(config, block_num, false)?.header.hash
    ))
}

fn get_eth_block_by_num(
    config: &DVFConfig,
    block_num: u64,
    include_tx: bool,
) -> Result<Block<Transaction>, ValidationError> {
    let block_num_hex = format!("{:#x}", block_num);

    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "eth_getBlockByNumber",
        "params": [block_num_hex, include_tx],
        "id": 1
    });
    let result = send_blocking_web3_post(config, &request_body)?;

    let block: Block<Transaction> = serde_json::from_value(result)?;

    Ok(block)
}

pub fn get_eth_codehash(
    config: &DVFConfig,
    address: &Address,
    block_num: u64,
) -> Result<String, ValidationError> {
    let code = get_eth_code(config, address, block_num)?;
    let code_bytes = hex::decode(code.trim_start_matches("0x"))?;

    // Hashing the contract code
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(&code_bytes);
    hasher.finalize(&mut output);

    let code_hash = format!("0x{}", hex::encode(output));

    info!("The codehash of the contract is {}", code_hash);

    Ok(code_hash)
}

fn u256_to_bytes(u: &U256) -> [u8; 32] {
    u.to_be_bytes::<32>()
}
fn commit_storage_to_snapshot(
    last_storage: &HashMap<u64, HashMap<U256, U256>>,
    depth: u64,
    snapshot: &mut HashMap<U256, [u8; 32]>,
) {
    if let Some(storage) = last_storage.get(&depth) {
        // Commit when execution ended successfully
        debug!("Last Storage found: {:?}", storage);
        for (slot, value) in storage.iter() {
            if value.is_zero() {
                snapshot.remove(slot);
            } else {
                snapshot.insert(*slot, u256_to_bytes(value));
            }
        }
    }
}

pub struct UnusedStoragePart {
    pub slot: U256,
    pub offset: usize,
    pub value: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StorageSnapshot {
    pub snapshot: HashMap<U256, [u8; 32]>,
    // Remember which parts have been used
    unused_parts: HashMap<U256, [bool; 32]>,
}

impl StorageSnapshot {
    pub fn from_api(
        config: &DVFConfig,
        address: &Address,
        deployment_block_num: u64,
        init_block_num: u64,
    ) -> Result<Self, ValidationError> {
        // First try special call
        let snapshot: HashMap<U256, [u8; 32]> = if let Ok(storage_snapshot) =
            get_eth_storage_snapshot(config, address, init_block_num)
        {
            /*
            Self::validate_snapshot_with_mpt_root(
                config,
                &storage_snapshot,
                address,
                init_block_num,
            );
            */
            storage_snapshot
        } else {
            // Alternatively, get all txs
            let tx_hashes =
                get_all_txs_for_contract(config, address, deployment_block_num, init_block_num)?;
            debug!("Tx Hashes: {:?}", tx_hashes);
            // And diffs for all txs
            if let Ok(all_diffs) = get_many_diff_traces(config, &tx_hashes) {
                // And compute snapshot from there
                Self::snapshot_from_diff_traces(&all_diffs, address)
                // verify snapshot with account storage merkle root
                //Self::validate_snapshot_with_mpt_root(config, &snapshot, address, init_block_num);
            } else {
                Self::snapshot_from_tx_ids(config, address, &tx_hashes)?
                // verify snapshot with account storage merkle root
                //Self::validate_snapshot_with_mpt_root(config, &snapshot, address, init_block_num);
            }
        };
        debug!("Storage Snapshot: {:?}", snapshot);
        let unused_parts = Self::init_unused_parts(&snapshot);
        Ok(StorageSnapshot {
            snapshot,
            unused_parts,
        })
    }

    // Reconstruct and verify the account storage root
    pub fn validate_snapshot_with_mpt_root(
        config: &DVFConfig,
        snapshot: &HashMap<U256, [u8; 32]>,
        address: &Address,
        block_num: u64,
    ) {
        // retrieve account info from rpc
        let account_storage_root = match get_eth_account_at_block(config, address, block_num) {
            Ok(storage_root) => storage_root,
            Err(_) => {
                warn!("Failed to retrieve account storage root from RPC. Skipping validation.");
                return;
            }
        };

        // snapshot type casting
        let snapshot: HashMap<B256, U256> = snapshot
            .iter()
            .map(|(k, v)| (B256::from(*k), U256::from_be_slice(v.as_slice())))
            .collect();

        let reconstructed_root = root::storage_root_unhashed(snapshot);

        assert_eq!(reconstructed_root, account_storage_root);
    }

    fn init_unused_parts(snapshot: &HashMap<U256, [u8; 32]>) -> HashMap<U256, [bool; 32]> {
        let mut unused_parts: HashMap<U256, [bool; 32]> = HashMap::new();
        for slot in snapshot.keys() {
            unused_parts.insert(*slot, [true; 32]);
        }
        unused_parts
    }

    fn snapshot_from_diff_traces(
        diff_traces: &[DiffMode],
        address: &Address,
    ) -> HashMap<U256, [u8; 32]> {
        let mut snapshot: HashMap<U256, [u8; 32]> = HashMap::new();
        for diff_trace in diff_traces.iter() {
            if let Some(diff) = diff_trace.pre.get(address) {
                for (slot, value) in &diff.storage {
                    // a non-zero value in the `pre` field means that the value will be 0 after
                    // the transaction
                    if !value.is_zero() {
                        snapshot.remove(&(*slot).into());
                    }
                }
            }
            if let Some(diff) = diff_trace.post.get(address) {
                for (slot, value) in &diff.storage {
                    // a non-zero value in the `post` field means that the value will change after
                    // the transaction
                    if !value.is_zero() {
                        snapshot.insert((*slot).into(), value.0);
                    }
                }
            }
        }
        snapshot
    }

    fn snapshot_from_tx_ids(
        config: &DVFConfig,
        address: &Address,
        tx_hashes: &Vec<String>,
    ) -> Result<HashMap<U256, [u8; 32]>, ValidationError> {
        debug!("Constructing snapshot from TX Ids.");
        let mut snapshot: HashMap<U256, [u8; 32]> = HashMap::new();
        for tx_hash in tx_hashes {
            let trace_w_a = get_eth_debug_trace(config, tx_hash)?;
            Self::add_trace(&mut snapshot, config, address, &trace_w_a)?;
        }
        Ok(snapshot)
    }

    fn snapshot_from_traces(
        config: &DVFConfig,
        address: &Address,
        traces_w_a: &Vec<TraceWithAddress>,
    ) -> Result<HashMap<U256, [u8; 32]>, ValidationError> {
        let mut snapshot: HashMap<U256, [u8; 32]> = HashMap::new();
        for trace_w_a in traces_w_a {
            Self::add_trace(&mut snapshot, config, address, trace_w_a)?;
        }
        Ok(snapshot)
    }

    fn add_trace(
        snapshot: &mut HashMap<U256, [u8; 32]>,
        config: &DVFConfig,
        address: &Address,
        trace_w_a: &TraceWithAddress,
    ) -> Result<(), ValidationError> {
        if trace_w_a.trace.failed {
            return Ok(());
        }
        // Track which contract we are in
        let mut depth_to_address: HashMap<u64, Address> = HashMap::new();
        depth_to_address.insert(1, trace_w_a.address);
        // depth -> last_storage
        let mut last_storage: HashMap<u64, HashMap<U256, U256>> = HashMap::new();

        let last_depth = 1_u64;

        let mut create_addresses: Option<Vec<Address>> = None;

        for log in &trace_w_a.trace.struct_logs {
            // Boring state
            if log.stack.is_none() {
                continue;
            }
            // Fine because we checked
            let stack = log.stack.clone().unwrap();

            if log.op == "CREATE" || log.op == "CREATE2" {
                if create_addresses.is_none() {
                    // Fetch call trace lazily if we need it
                    create_addresses =
                        Some(get_internal_create_addresses(config, &trace_w_a.tx_id)?);
                }
                if let Some(ref mut create_ref) = create_addresses {
                    depth_to_address.insert(log.depth + 1, create_ref.remove(0));
                }
            }

            if log.op == "CALL" || log.op == "STATICCALL" {
                let address_bytes = stack[stack.len() - 2].to_be_bytes::<32>();
                let a = Address::from_slice(&address_bytes[12..]);
                depth_to_address.insert(log.depth + 1, a);
            }

            // As we care about storage, the address stays the same during DELEGATECALL
            if log.op == "DELEGATECALL" || log.op == "CALLCODE" {
                depth_to_address.insert(log.depth + 1, depth_to_address[&log.depth]);
            }

            // We don't care about SELFDESTRUCT/SUICIDE here

            if &depth_to_address[&log.depth] == address && log.op == "SSTORE" {
                let last_store = last_storage.entry(log.depth).or_default();
                let value = stack[stack.len() - 2];
                let slot = stack[stack.len() - 1];
                last_store.insert(slot, value);
                //last_storage.insert(log.depth, last_store);
            }

            // Save upon successful return
            if log.op == "STOP" || log.op == "RETURN" {
                commit_storage_to_snapshot(&last_storage, log.depth, snapshot);
            }
            // Clean failed storages
            if log.depth < last_depth {
                for depth in log.depth..last_depth + 1 {
                    if last_storage.contains_key(&depth) {
                        last_storage.remove(&depth);
                    }
                }
            }
        }
        // We know that depth 1 succeeded so write back depth 1 here
        commit_storage_to_snapshot(&last_storage, 0u64, snapshot);

        // Check that we used all addresses
        if let Some(addrs) = create_addresses {
            assert_eq!(addrs.len(), 0);
        }

        Ok(())
    }

    pub fn from_trace(
        config: &DVFConfig,
        address: &Address,
        trace_w_a: &TraceWithAddress,
    ) -> Result<Self, ValidationError> {
        let snapshot = Self::snapshot_from_traces(config, address, &vec![trace_w_a.clone()])?;
        let unused_parts = Self::init_unused_parts(&snapshot);
        Ok(StorageSnapshot {
            snapshot,
            unused_parts,
        })
    }

    pub fn from_tx_id(
        config: &DVFConfig,
        address: &Address,
        tx_hash: &str,
    ) -> Result<Self, ValidationError> {
        let snapshot = Self::snapshot_from_tx_ids(config, address, &vec![tx_hash.to_string()])?;
        let unused_parts = Self::init_unused_parts(&snapshot);
        Ok(StorageSnapshot {
            snapshot,
            unused_parts,
        })
    }

    /*
        #[cfg(test)]
        fn from_test_strings(slots: &Vec<String>, values: &Vec<String>) -> Self {
            let mut u_s: Vec<U256> = vec![];
            for s in slots {
                u_s.push(U256::from_str_radix(s, 16).unwrap());
            }
            return Self::from_test_data(&u_s, values);
        }
    */

    #[cfg(test)]
    fn from_test_data(slots: &Vec<U256>, values: &Vec<[u8; 32]>) -> Self {
        let mut snapshot: HashMap<U256, [u8; 32]> = HashMap::new();
        for i in 0..slots.len() {
            snapshot.insert(slots[i], values[i]);
        }
        let unused_parts = Self::init_unused_parts(&snapshot);
        StorageSnapshot {
            snapshot,
            unused_parts,
        }
    }

    /*
        #[cfg(test)]
        fn helper_test_snapshot1_correctness(
            config: &DVFConfig,
            address: &Address,
            init_block_num: u64,
        ) {
            let snapshot = get_eth_storage_snapshot(config, address, init_block_num).unwrap();
            assert!(Self::check_snapshot_correct(
                config,
                address,
                init_block_num,
                snapshot
            ));
        }
    */

    #[cfg(test)]
    fn helper_test_snapshot2_correctness(
        config: &DVFConfig,
        address: &Address,
        deployment_block_num: u64,
        init_block_num: u64,
    ) {
        info!("Testing snapshot correctness using diff-traces.");
        let tx_hashes =
            get_all_txs_for_contract(config, address, deployment_block_num, init_block_num)
                .unwrap();
        // And diffs for all txs
        let all_diffs = get_many_diff_traces(config, &tx_hashes).unwrap();
        // And compute snapshot from there
        let snapshot = Self::snapshot_from_diff_traces(&all_diffs, address);
        assert!(Self::check_snapshot_correct(
            config,
            address,
            init_block_num,
            snapshot
        ))
    }

    #[cfg(test)]
    fn helper_test_snapshot3_correctness(
        config: &DVFConfig,
        address: &Address,
        deployment_block_num: u64,
        init_block_num: u64,
    ) {
        info!("Testing snapshot correctness using debug traces.");
        let tx_hashes =
            get_all_txs_for_contract(config, address, deployment_block_num, init_block_num)
                .unwrap();
        // Work with raw traces
        let snapshot = Self::snapshot_from_tx_ids(config, address, &tx_hashes).unwrap();
        assert!(Self::check_snapshot_correct(
            config,
            address,
            init_block_num,
            snapshot,
        ))
    }

    #[cfg(test)]
    fn helper_test_snapshot_equality(
        config: &DVFConfig,
        address: &Address,
        deployment_block_num: u64,
        init_block_num: u64,
    ) {
        // TODO: Fix this
        // let first_snapshot = get_eth_storage_snapshot(config, address, init_block_num).unwrap();
        let tx_hashes =
            get_all_txs_for_contract(config, address, deployment_block_num, init_block_num)
                .unwrap();
        // And diffs for all txs
        let all_diffs = get_many_diff_traces(config, &tx_hashes).unwrap();
        // And compute snapshot from there
        let second_snapshot = Self::snapshot_from_diff_traces(&all_diffs, address);
        // Work with raw traces
        let third_snapshot = Self::snapshot_from_tx_ids(config, address, &tx_hashes).unwrap();
        // assert_eq!(first_snapshot, second_snapshot);
        assert_eq!(second_snapshot, third_snapshot);
    }

    // Returns true iff the snapshot provided conforms to the output of eth_getStorageAt
    pub fn check_snapshot_correct(
        config: &DVFConfig,
        address: &Address,
        init_block_num: u64,
        snapshot: HashMap<U256, [u8; 32]>,
    ) -> bool {
        for (slot, value) in snapshot.iter() {
            let expected_value =
                &get_eth_storage_at(config, address, slot, init_block_num).unwrap();
            if value != expected_value {
                debug!(
                    "{:?} != {:?} for {:?}:{}@{}",
                    value, expected_value, address, slot, init_block_num
                );
                return false;
            }
        }
        true
    }

    // Returns true iff entire area is set and unused
    pub fn check_if_set_and_unused(&mut self, slot: &U256, offset: usize, size: usize) -> bool {
        if !self.snapshot.contains_key(slot) {
            return false;
        }
        self.check_all_unused(slot, offset, size)
    }

    // Get Storage entry and mark it as used
    pub fn get_slot_and_mark(&mut self, slot: &U256, offset: usize, size: usize) -> Vec<u8> {
        if self.snapshot.contains_key(slot) {
            self.add_usage(slot, offset, size);
        }
        self.get_slot(slot, offset, size)
    }

    // Get Storage entry
    pub fn get_slot(&self, slot: &U256, offset: usize, size: usize) -> Vec<u8> {
        match self.snapshot.get(slot) {
            Some(val) => val[32 - offset - size..32 - offset].to_vec(),
            None => vec![0; size],
        }
    }

    // Get Storage entry
    pub fn get_full_slot(&self, slot: &U256) -> [u8; 32] {
        match self.snapshot.get(slot) {
            Some(val) => *val,
            None => [0u8; 32],
        }
    }

    // Get Storage entry
    pub fn get_u8_from_slot(&self, slot: &U256, offset: usize) -> u8 {
        match self.snapshot.get(slot) {
            Some(val) => val[32 - offset - 1],
            None => 0u8,
        }
    }

    fn check_all_unused(&mut self, slot: &U256, offset: usize, size: usize) -> bool {
        if let Some(s) = self.unused_parts.get(slot) {
            #[allow(clippy::needless_range_loop)]
            for i in 32 - offset - size..32 - offset {
                if !s[i] {
                    return false;
                }
            }
        };
        true
    }

    fn add_usage(&mut self, slot: &U256, offset: usize, size: usize) {
        if let Some(s) = self.unused_parts.get_mut(slot) {
            #[allow(clippy::needless_range_loop)]
            for i in 32 - offset - size..32 - offset {
                s[i] = false;
            }
        };
    }

    // Related to: https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html#bytes-and-string
    pub fn is_final_bit_set(&self, slot: &U256) -> bool {
        match self.snapshot.get(slot) {
            Some(val) => {
                let final_byte = val[31];
                final_byte % 2 == 1
            }
            None => false,
        }
    }

    // Collect all storage slots that have not previously been queried
    pub fn get_unused_nonzero_storage_slots(&self) -> Vec<UnusedStoragePart> {
        let mut unused_storage_parts: Vec<UnusedStoragePart> = vec![];

        // Get a Vec of all keys
        let mut keys: Vec<U256> = self.unused_parts.keys().cloned().collect();

        // Sort the keys
        keys.sort();

        for slot in keys {
            let unused = self.unused_parts[&slot];
            let mut startindex: usize = 0;
            let mut prev_unused: bool = false;
            for (i, is_i_unused) in unused.iter().enumerate() {
                if *is_i_unused && prev_unused {
                    // Continue to collect unused part
                } else if *is_i_unused && !prev_unused {
                    // Start new unused part
                    startindex = i;
                    prev_unused = true;
                } else if !is_i_unused && prev_unused {
                    // Finish unused part
                    let val = self.get_slot(&slot, 32 - i, i - startindex);
                    if val != vec![0u8; i - startindex] {
                        unused_storage_parts.push(UnusedStoragePart {
                            slot,
                            offset: 32 - i,
                            value: val,
                        });
                    }
                    prev_unused = false;
                } else {
                    // All used
                    assert!(!is_i_unused && !prev_unused);
                }
            }
            // Handle final one
            if prev_unused {
                // Finish unused part
                let val = self.get_slot(&slot, 0, 32 - startindex);
                if val.iter().any(|b| *b != 0u8) {
                    unused_storage_parts.push(UnusedStoragePart {
                        slot,
                        offset: 0,
                        value: val,
                    });
                }
            }
        }
        unused_storage_parts
    }
}

pub fn get_eth_storage_snapshot(
    config: &DVFConfig,
    address: &Address,
    init_block_num: u64,
) -> Result<HashMap<U256, [u8; 32]>, ValidationError> {
    let mut snapshot: HashMap<U256, [u8; 32]> = HashMap::new();

    //`init_block_num` + 1 is needed because debug_storageRangeAt queries at the beginning of the block while other methods query at the end of the block
    let init_block_hash = get_eth_blockhash_by_num(config, init_block_num + 1)?;
    debug!(
        "Blockhash of {} is {}.",
        init_block_num + 1,
        init_block_hash
    );

    // Mapping of hash -> {'key': 0x00, 'value': 0x01}
    let mut next_key: String =
        "0x0000000000000000000000000000000000000000000000000000000000000000".to_string();
    loop {
        let storage_range =
            get_eth_storage_range_response(config, address, &init_block_hash, next_key)?;
        for hash in storage_range.storage.keys() {
            let key: U256 = storage_range.storage[hash].key.into();
            let value: [u8; 32] = storage_range.storage[hash].value.0;
            snapshot.insert(key, value);
        }
        if storage_range.next_key.is_null() {
            break;
        }
        next_key = serde_json::from_value(storage_range.next_key).unwrap();
    }
    Ok(snapshot)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EtherscanCommonTransactionData {
    #[serde(rename = "hash")]
    pub transaction_hash: String,
    #[serde(rename = "blockNumber")]
    #[serde(deserialize_with = "deserialize_dec_u64")]
    pub block_number: u64,
    #[serde(rename = "timeStamp")]
    #[serde(deserialize_with = "deserialize_dec_u64")]
    pub timestamp: u64,
    #[serde(rename = "from")]
    pub from_address: String,
    #[serde(rename = "to")]
    pub to_address: String,
    #[serde(rename = "value")]
    pub value: String,
    #[serde(rename = "contractAddress")]
    pub contract_address: Option<String>,
    #[serde(rename = "input")]
    pub input: String,
    #[serde(rename = "type")]
    pub transaction_type: Option<String>,
    #[serde(rename = "gas")]
    #[serde(deserialize_with = "deserialize_dec_u64")]
    pub gas: u64,
    #[serde(rename = "isError")]
    pub is_error: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EtherscanTransaction {
    #[serde(flatten)]
    pub common: EtherscanCommonTransactionData,
    #[serde(rename = "gasPrice")]
    #[serde(deserialize_with = "deserialize_dec_u64")]
    pub gas_price: u64,
    #[serde(rename = "gasUsed")]
    #[serde(deserialize_with = "deserialize_dec_u64")]
    pub gas_used: u64,
    #[serde(rename = "cumulativeGasUsed")]
    #[serde(deserialize_with = "deserialize_dec_u64")]
    pub cumulative_gas_used: u64,
    #[serde(rename = "nonce")]
    #[serde(deserialize_with = "deserialize_dec_u64")]
    pub nonce: u64,
    #[serde(rename = "confirmations")]
    #[serde(deserialize_with = "deserialize_dec_u64")]
    pub confirmations: u64,
    #[serde(rename = "txreceipt_status")]
    pub txreceipt_status: String,
    #[serde(rename = "transactionIndex")]
    #[serde(deserialize_with = "deserialize_dec_u64")]
    pub transaction_index: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EtherscanInternalTransaction {
    #[serde(flatten)]
    pub common: EtherscanCommonTransactionData,
    #[serde(rename = "gasUsed")]
    #[serde(deserialize_with = "deserialize_dec_u64")]
    pub gas_used: u64,
    #[serde(rename = "traceId")]
    pub trace_id: String,
    #[serde(rename = "errCode")]
    pub err_code: String,
}

pub enum TransactionType {
    Normal,
    Internal,
}

pub fn get_all_transactions_from_etherscan<T>(
    config: &DVFConfig,
    address: &Address,
    start_block: u64,
    end_block: u64,
    sort: &str,
    tx_type: TransactionType,
) -> Result<Vec<T>, ValidationError>
where
    T: for<'de> Deserialize<'de>,
{
    let mut all_transactions: Vec<T> = Vec::new();
    let mut current_start_block = start_block;
    let mut current_end_block = end_block;
    let mut block_range_adjusted = false;

    let action = match tx_type {
        TransactionType::Normal => "txlist",
        TransactionType::Internal => "txlistinternal",
    };

    while current_start_block <= current_end_block {
        let mut page = 1;
        let offset = 10000; // Maximum allowed by Etherscan
        let mut has_more = true;
        let mut api_call_successful = false;

        while has_more {
            let url = format!(
                "{}?chainid={}&module=account&action={}&address={:?}&startblock={}&endblock={}&page={}&offset={}&sort={}&apikey={}",
                config.get_etherscan_api_url()?,
                config.active_chain_id.unwrap(),
                action,
                address,
                current_start_block,
                current_end_block,
                page,
                offset,
                sort,
                config.get_etherscan_api_key()?
            );

            debug!("Etherscan URL: {}", url);

            let mut response = match get(&url) {
                Ok(resp) => {
                    api_call_successful = true;
                    resp
                }
                Err(_) => {
                    // Keep halving the block range until we get a successful call
                    let mid_block = (current_start_block + current_end_block) / 2;
                    if mid_block == current_start_block {
                        return Err(ValidationError::from("Failed to fetch transactions from Etherscan - block range too small"));
                    }
                    current_end_block = mid_block;
                    block_range_adjusted = true;
                    break; // Break the inner loop to retry with new block range
                }
            };

            let mut buffer = String::new();
            response.read_to_string(&mut buffer)?;

            let result: EtherscanResult = serde_json::from_str(&buffer)?;
            let transactions: Vec<T> = serde_json::from_value(result.result)?;

            if transactions.is_empty() {
                has_more = false;
            } else {
                if transactions.len() < offset {
                    has_more = false;
                } else {
                    page += 1;
                }
                all_transactions.extend(transactions);
            }
        }

        if block_range_adjusted && api_call_successful {
            // If we've adjusted the block range and had a successful call, move to next block and reset end block
            current_start_block = current_end_block + 1;
            current_end_block = end_block;
            block_range_adjusted = false;
        } else if !block_range_adjusted {
            // If we haven't adjusted the range yet, just move to next block
            current_start_block = current_end_block + 1;
        }
        // If block_range_adjusted is true but api_call_successful is false, we'll retry with the halved range
    }

    Ok(all_transactions)
}

#[derive(Debug, Serialize, Deserialize)]
struct TransactionWithIndex {
    transaction_hash: String,
    block_number: u64,
    transaction_index: u64,
}

impl PartialOrd for TransactionWithIndex {
    fn partial_cmp(&self, other: &TransactionWithIndex) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TransactionWithIndex {
    fn cmp(&self, other: &Self) -> Ordering {
        self.block_number
            .cmp(&other.block_number)
            .then_with(|| self.transaction_index.cmp(&other.transaction_index))
    }
}

impl PartialEq for TransactionWithIndex {
    fn eq(&self, other: &Self) -> bool {
        self.transaction_hash.to_lowercase() == other.transaction_hash.to_lowercase()
    }
}

impl Eq for TransactionWithIndex {}

pub fn get_combined_txs_for_contract_from_etherscan(
    config: &DVFConfig,
    address: &Address,
    start_block: u64,
    end_block: u64,
) -> Result<Vec<String>, ValidationError> {
    // Get normal transactions
    let normal_txs = get_all_transactions_from_etherscan::<EtherscanTransaction>(
        config,
        address,
        start_block,
        end_block,
        "asc",
        TransactionType::Normal,
    )?;

    // Get internal transactions
    let internal_txs = get_all_transactions_from_etherscan::<EtherscanInternalTransaction>(
        config,
        address,
        start_block,
        end_block,
        "asc",
        TransactionType::Internal,
    )?;

    // Group transactions by block number
    let mut block_to_txs: HashMap<u64, Vec<TransactionWithIndex>> = HashMap::new();

    // Add normal transactions with their actual indices
    for tx in normal_txs {
        let tx_with_index = TransactionWithIndex {
            transaction_hash: tx.common.transaction_hash,
            block_number: tx.common.block_number,
            transaction_index: tx.transaction_index,
        };
        block_to_txs
            .entry(tx.common.block_number)
            .or_default()
            .push(tx_with_index);
    }

    // Add internal transactions with placeholder indices
    for tx in internal_txs {
        let tx_with_index = TransactionWithIndex {
            transaction_hash: tx.common.transaction_hash,
            block_number: tx.common.block_number,
            transaction_index: u64::MAX, // Placeholder index
        };
        block_to_txs
            .entry(tx.common.block_number)
            .or_default()
            .push(tx_with_index);
    }

    // For blocks with multiple transactions, get the correct indices for internal transactions
    for (_, transactions) in block_to_txs.iter_mut() {
        if transactions.len() > 1 {
            // Only need to get indices for internal transactions (those with placeholder index)
            for tx in transactions.iter_mut() {
                if tx.transaction_index == u64::MAX {
                    let request_body = json!({
                        "jsonrpc": "2.0",
                        "method": "eth_getTransactionByHash",
                        "params": [tx.transaction_hash],
                        "id": 1
                    });
                    let result = send_blocking_web3_post(config, &request_body)?;
                    
                    if let Some(idx) = result.get("transactionIndex") {
                        tx.transaction_index = u64::from_str_radix(
                            idx.as_str().unwrap().trim_start_matches("0x"),
                            16,
                        )?;
                    }
                }
            }
        }
    }

    // Combine all transactions and sort
    let mut combined_txs: Vec<TransactionWithIndex> = block_to_txs
        .into_values()
        .flat_map(|txs| txs)
        .collect();
    
    combined_txs.sort();
    combined_txs.dedup();

    // Extract just the transaction hashes
    let tx_hashes: Vec<String> = combined_txs
        .into_iter()
        .map(|tx| tx.transaction_hash)
        .collect();

    Ok(tx_hashes)
}

#[cfg(test)]
mod tests {
    //use reth_trie::root;
    use std::str::FromStr;

    use super::*;
    use env_logger;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn test_snapshots_correctness() {
        init();
        let address = Address::from_str("0x27dab51C2c5B6AF23DF64143c61ffCFa36F35E6d").unwrap();
        let mut config = match DVFConfig::from_env(None) {
            Ok(config) => config,
            Err(err) => {
                println!("{}", err);
                assert!(false);
                return;
            }
        };
        config.set_chain_id(1).unwrap();

        let deployment_block_num = 19012544;
        let block_num_with_tx = 19012829;

        for init_block_num in block_num_with_tx - 3..block_num_with_tx {
            // TODO: Fix this
            // StorageSnapshot::helper_test_snapshot1_correctness(&config, &address, init_block_num);
            StorageSnapshot::helper_test_snapshot2_correctness(
                &config,
                &address,
                deployment_block_num,
                init_block_num,
            );
            StorageSnapshot::helper_test_snapshot3_correctness(
                &config,
                &address,
                deployment_block_num,
                init_block_num,
            );
        }
        // This is because it currently only works for recent blocks
        // TODO: Also doesn't work, too slow...
        // let current_block_num = get_eth_block_number(&config).unwrap();
        // StorageSnapshot::helper_test_snapshot1_correctness(&config, &address, current_block_num);
    }

    #[test]
    fn test_snapshot_equality() {
        // TODO: add more traces with reverts and stuff
        init();
        let address = Address::from_str("0x27dab51C2c5B6AF23DF64143c61ffCFa36F35E6d").unwrap();
        let mut config = match DVFConfig::from_env(None) {
            Ok(config) => config,
            Err(err) => {
                println!("{}", err);
                panic!();
            }
        };
        config.set_chain_id(1).unwrap();

        let deployment_block_num = 19012544;
        //let init_block_num = get_eth_block_number(&config).unwrap() - 1;
        let init_block_num = 22088076; // can't use latest block as this won't work with the cache

        StorageSnapshot::helper_test_snapshot_equality(
            &config,
            &address,
            deployment_block_num,
            init_block_num,
        );
    }

    /*
    #[test]
    fn test_validate_snapshot_with_merkle_root() {
        init();
        let address = Address::from_str("0x27dab51C2c5B6AF23DF64143c61ffCFa36F35E6d").unwrap();
        let mut config = match DVFConfig::from_env(None) {
            Ok(config) => config,
            Err(err) => {
                println!("{}", err);
                panic!();
            }
        };
        config.set_chain_id(1).unwrap();

        let init_block_num = get_eth_block_number(&config).unwrap() - 1;

        let account_storage_root =
            get_eth_account_at_block(&config, &address, init_block_num).unwrap();

        let snapshot: HashMap<ruint::Uint<256, 4>, [u8; 32]> =
            get_eth_storage_snapshot(&config, &address, init_block_num).unwrap();
        let snapshot: HashMap<B256, U256> = snapshot
            .into_iter()
            .map(|(k, v)| (B256::from(k), U256::from_be_slice(v.as_slice())))
            .collect();

        let reconstructed_root = root::storage_root_unhashed(snapshot);

        println!("expected: {:?}", account_storage_root);
        println!("reconstructed: {:?}", reconstructed_root);

        assert_eq!(account_storage_root, reconstructed_root);
    }
    */

    #[test]
    fn test_snapshot_get() {
        init();
        let slots: Vec<U256> = vec![
            U256::from_str_radix(
                "0000000000000000000000000000000000000000000000000000000000000002",
                16,
            )
            .unwrap(),
            U256::from_str_radix(
                "0000000000000000000000000000000000000000000000000000000000000000",
                16,
            )
            .unwrap(),
            U256::from_str_radix(
                "000000000000000000000000000000000000000000000000000000000000000a",
                16,
            )
            .unwrap(),
        ];
        let mut val0 = [0u8; 32];
        val0[31] = 42;
        let mut val1 = [0u8; 32];
        val1[0] = 0x2a;
        val1[31] = 0x2b;
        let mut val2 = [0u8; 32];
        val2[0] = 0x11;
        val2[31] = 0x22;
        let values: Vec<[u8; 32]> = vec![val0, val1, val2];
        let snapshot = StorageSnapshot::from_test_data(&slots, &values);
        assert_eq!(snapshot.get_slot(&slots[0], 0, 32), values[0]);
        assert_eq!(snapshot.get_slot(&slots[1], 0, 32), values[1]);
        assert_eq!(snapshot.get_slot(&slots[2], 0, 32), values[2]);
        assert_eq!(snapshot.get_slot(&slots[1], 0, 1), vec![0x2b]);
        assert_eq!(snapshot.get_slot(&slots[1], 31, 1), vec![0x2a]);
        // Check non-existing slot
        assert_eq!(
            snapshot.get_slot(
                &U256::from_str_radix(
                    "0000000000000000000000000000000000000000000000000000000000000123",
                    16
                )
                .unwrap(),
                0,
                32
            ),
            vec![0; 32]
        );
        assert_eq!(
            snapshot.get_slot(
                &U256::from_str_radix(
                    "0000000000000000000000000000000000000000000000000000000000000123",
                    16
                )
                .unwrap(),
                2,
                30
            ),
            vec![0; 30]
        );
        assert_eq!(
            snapshot.get_slot(
                &U256::from_str_radix(
                    "0000000000000000000000000000000000000000000000000000000000000123",
                    16
                )
                .unwrap(),
                5,
                2
            ),
            vec![0; 2]
        );
    }

    #[test]
    fn test_get_eth_debug_init_code_create_opcode() {
        init();
        let tx = "0x495402df7d45fe36329b0bd94487f49baee62026d50f654600f6771bd2a596ab".to_string(); // dai deployment tx
        let address = Address::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap(); // dai address
        let mut config = match DVFConfig::from_env(None) {
            Ok(config) => config,
            Err(err) => {
                println!("{}", err);
                panic!();
            }
        };
        config.set_chain_id(1).unwrap();

        let init_code = get_init_code(&config, &tx, &address).unwrap();

        assert!(init_code.starts_with("0x608060405234801561001057600080fd5b506040516120d33803806120d38339818101604052602081101"))
    }

    #[test]
    fn test_get_eth_debug_init_code_to_to_address_zero() {
        init();
        let tx = "0x8b36720344797ed57f2e22cf2aa56a09662165567a6ade701259cde560cc4a9d".to_string(); // frax deployment tx
        let address = Address::from_str("0x5e8422345238f34275888049021821e8e08caa1f").unwrap(); // frax address
        let mut config = match DVFConfig::from_env(None) {
            Ok(config) => config,
            Err(err) => {
                println!("{}", err);
                panic!();
            }
        };
        config.set_chain_id(1).unwrap();

        let init_code = get_init_code(&config, &tx, &address).unwrap();

        assert!(init_code.starts_with("0x61014060405234"))
    }

    /*
    // TODO: Test against separate endpoint, current endpoint does not support it
    #[test]
    fn test_ots_contract_creator() {
        init();
        let address = Address::from_str("0x5e8422345238f34275888049021821e8e08caa1f").unwrap(); // frax address
        let mut config = match DVFConfig::from_env(None) {
            Ok(config) => config,
            Err(err) => {
                println!("{}", err);
                assert!(false);
                return;
            }
        };
        config.set_chain_id(1).unwrap();

        let creator = get_ots_contract_creator(&config, &address).unwrap();

        assert_eq!(
            creator.contract_creator,
            "0x4600d3b12c39af925c2c07c487d31d17c1e32a35".to_string()
        );
        assert_eq!(
            creator.tx_hash,
            "0x8b36720344797ed57f2e22cf2aa56a09662165567a6ade701259cde560cc4a9d"
        );
    }*/

    #[test]
    fn test_get_deployment_block_from_binary_search() {
        init();
        let address = Address::from_str("0x5e8422345238f34275888049021821e8e08caa1f").unwrap(); // frax address
        let mut config = match DVFConfig::from_env(None) {
            Ok(config) => config,
            Err(err) => {
                println!("{}", err);
                panic!();
            }
        };
        config.set_chain_id(1).unwrap();

        let block_num = get_eth_block_number(&config).unwrap();
        let deployment_block =
            get_deployment_block_from_binary_search(&config, &address, block_num).unwrap();

        assert_eq!(deployment_block, 15686046);
    }

    /*
        pub fn get_transaction_by_block(
            config: &DVFConfig,
            slot: &U256,
            block_num: u64,
        ) -> Result<String, ValidationError> {
            let block_num_hex = format!("{:#x}", block_num);
            let slot_hex = format!("{:#x}", slot);

            let request_body = json!({
                "jsonrpc": "2.0",
                "method": "eth_getTransactionByBlockNumberAndIndex",
                "params": [block_num_hex, slot_hex],
                "id": 1
            });

            let result = send_blocking_web3_post(config, &request_body)?;
            let val: Transaction = serde_json::from_value(result).unwrap_or_default();

            let tx_hash = format!("{:#?}", val.hash);
            debug!(
                "The transaction hash of the first transaction of the last block is {} at {} in slot {}",
                tx_hash, block_num, slot
            );
            Ok(tx_hash)
        }
    */

    // #[derive(Debug, PartialEq)]
    // enum Traces {
    //     ParityAndGeth,
    //     ParityOnly,
    //     GethOnly,
    //     None,
    // }

    // cargo test --package dv --lib -- web3::tests::test_debug_api --exact --show-output
    // #[test]
    // fn test_debug_api() {
    //     let mut config = DVFConfig::from_path(Path::new("examples/rpc_testing.json")).unwrap();

    //     const NETWORKS: &[(&str, u64)] = &[
    //         ("Ethereum", 1),
    //         ("Blast", 81457),
    //         ("BSC", 56),
    //         ("Polygon", 137),
    //         ("Optimism", 10),
    //         // ("Gnosis", 100), removed it
    //         ("Arbitrum", 42161),
    //         ("Base", 8453),
    //         // Uncomment these if needed
    //         // ("Avalanche", 43114),
    //         // ("ZKSync", 324),
    //         // ("Mantle", 5000),
    //     ];
    //     for (network_name, chain_id) in NETWORKS {
    //         // set chain id
    //         let _chain_id = chain_id.clone();
    //         config.set_chain_id(_chain_id).unwrap();

    //         // get first transaction one of the last blocks
    //         let mut block_num = get_eth_block_number(&config).unwrap() - 10;
    //         let tx_hash = loop {
    //             let block = get_eth_block_by_num(&config, block_num, true).unwrap();
    //             if block.transactions.len() > 0 {
    //                 let tx_hash = format!("{:#x}", block.transactions[0].hash);
    //                 break tx_hash;
    //             }
    //             block_num += 1;
    //         };
    //         // parity trace / geth trace api for last transaction
    //         let parity_traces = get_tx_trace(&config, &tx_hash);
    //         let geth_traces = get_eth_debug_call_trace(&config, &tx_hash);

    //         let traces = match (parity_traces, geth_traces) {
    //             (Ok(_), Ok(_)) => Traces::ParityAndGeth,
    //             (Ok(_), Err(_)) => Traces::ParityOnly,
    //             (Err(_), Ok(_)) => Traces::GethOnly,
    //             (Err(_), Err(_)) => Traces::None,
    //         };

    //         println!(
    //             "Network: {} with chain id {} supports traces {:?}",
    //             network_name, chain_id, traces
    //         );

    //         assert_ne!(traces, Traces::None);
    //     }
    // }

    #[test]
    fn test_compare_transaction_sources() {
        let mut config = match DVFConfig::from_env(None) {
            Ok(config) => config,
            Err(err) => {
                println!("{}", err);
                assert!(false);
                return;
            }
        };
        config.set_chain_id(1).unwrap();

        let address = Address::from_str("0xdac17f958d2ee523a2206206994597c13d831ec7").unwrap();
        let start_block = 22475000;
        let end_block = 22475017;

        // Get transactions from both sources
        let etherscan_txs = get_combined_txs_for_contract_from_etherscan(
            &config,
            &address,
            start_block,
            end_block,
        ).unwrap();

        let blockscout_txs = get_all_txs_for_contract_from_blockscout(
            &config,
            &address,
            start_block,
            end_block,
        ).unwrap();

        // Convert to sets for comparison
        let etherscan_set: std::collections::HashSet<_> = etherscan_txs.into_iter().collect();
        let blockscout_set: std::collections::HashSet<_> = blockscout_txs.into_iter().collect();

        // Compare the results
        println!("Etherscan transactions: {}", etherscan_set.len());
        println!("Blockscout transactions: {}", blockscout_set.len());

        // Find transactions unique to each source
        let only_etherscan: Vec<_> = etherscan_set.difference(&blockscout_set).collect();
        let only_blockscout: Vec<_> = blockscout_set.difference(&etherscan_set).collect();

        println!("Transactions only in Etherscan: {}", only_etherscan.len());
        println!("Transactions only in Blockscout: {}", only_blockscout.len());

        // Print some example differences if any exist
        if !only_etherscan.is_empty() {
            println!("Example Etherscan-only transaction: {}", only_etherscan[0]);
        }
        if !only_blockscout.is_empty() {
            println!("Example Blockscout-only transaction: {}", only_blockscout[0]);
        }

        // Assert that both sources found some transactions
        assert!(!etherscan_set.is_empty(), "Etherscan returned no transactions");
        assert!(!blockscout_set.is_empty(), "Blockscout returned no transactions");
        assert!(false);
    }
}
