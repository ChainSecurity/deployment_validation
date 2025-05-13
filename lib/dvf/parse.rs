use std::env::VarError;
use std::fmt;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Write;
use std::num::ParseIntError;
use std::path::Path;

use ruint;

use crate::bytecode_verification::parse_json::ProjectInfo;
use crate::utils::pretty::convert_bytes_to_i256;
use crate::utils::pretty::PrettyPrinter;
use clap::ArgMatches;

use foundry_compilers;

use alloy::primitives::{Address, Bytes, Signature, B256, U256};
use alloy::signers::Signer;
use alloy_dyn_abi;
use alloy_signer_ledger::LedgerError;
use alloy_signer_local::LocalSignerError;

use reqwest;
use semver::Version;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::cmp::Ordering;
use tiny_keccak::{Hasher, Keccak};
use tracing::debug;
use zip::result::ZipError;

use crate::dvf::abstract_wallet::AbstractError;
use crate::dvf::config::DVFConfig;

pub const CURRENT_VERSION: Version = Version::new(0, 9, 1);
pub const CURRENT_VERSION_STRING: &str = "0.9.1";
const LOWEST_SUPPORTED_VERSION: Version = Version::new(0, 9, 0);
const HIGHEST_SUPPORTED_VERSION: Version = Version::new(0, 9, 1);

#[derive(Debug)]
pub enum ValidationError {
    Insecure(String),
    Invalid(String),
    NoDVFFound(String),
    Error(String),
}

impl From<AbstractError> for ValidationError {
    fn from(error: AbstractError) -> Self {
        match error {
            AbstractError::LedgerError(e) => ValidationError::from(e),
            AbstractError::WalletError(e) => ValidationError::from(e),
            AbstractError::GeneralError(e) => ValidationError::from(e),
        }
    }
}

impl From<rustc_hex::FromHexError> for ValidationError {
    fn from(error: rustc_hex::FromHexError) -> Self {
        ValidationError::Error(format!("Error Decoding Hex: {}", error))
    }
}

impl From<alloy_dyn_abi::Error> for ValidationError {
    fn from(error: alloy_dyn_abi::Error) -> Self {
        ValidationError::Error(format!("Alloy Dyn Abi Error: {}", error))
    }
}

impl From<ruint::ParseError> for ValidationError {
    fn from(error: ruint::ParseError) -> Self {
        ValidationError::Error(format!("Uint Parse Error: {}", error))
    }
}

impl From<foundry_compilers::error::SolcError> for ValidationError {
    fn from(error: foundry_compilers::error::SolcError) -> Self {
        ValidationError::Error(format!("Solc Error: {}", error))
    }
}

impl From<alloy::signers::Error> for ValidationError {
    fn from(error: alloy::signers::Error) -> Self {
        ValidationError::Error(format!("Signer Error: {}", error))
    }
}

impl From<alloy::hex::FromHexError> for ValidationError {
    fn from(error: alloy::hex::FromHexError) -> Self {
        ValidationError::Error(format!("Alloy Hex Parse Error: {}", error))
    }
}

impl From<hex::FromHexError> for ValidationError {
    fn from(error: hex::FromHexError) -> Self {
        ValidationError::Error(format!("Hex Parse Error: {}", error))
    }
}

impl From<LocalSignerError> for ValidationError {
    fn from(error: LocalSignerError) -> Self {
        ValidationError::Error(format!("Error in with Local Wallet: {}", error))
    }
}

impl From<LedgerError> for ValidationError {
    fn from(error: LedgerError) -> Self {
        ValidationError::Error(format!("Error in Ledger Communication: {}", error))
    }
}

impl From<io::Error> for ValidationError {
    fn from(error: io::Error) -> Self {
        ValidationError::Error(format!("IO error occurred: {}", error))
    }
}

impl From<serde_json::Error> for ValidationError {
    fn from(error: serde_json::Error) -> Self {
        ValidationError::Error(format!("JSON error occurred: {}", error))
    }
}

impl From<reqwest::Error> for ValidationError {
    fn from(error: reqwest::Error) -> Self {
        ValidationError::Error(format!("Communication error occurred: {}", error))
    }
}

impl From<ZipError> for ValidationError {
    fn from(error: ZipError) -> Self {
        ValidationError::Error(format!("Communication error occurred: {}", error))
    }
}

impl From<ParseIntError> for ValidationError {
    fn from(error: ParseIntError) -> Self {
        ValidationError::Error(format!("Could not parse hex: {}", error))
    }
}

impl From<String> for ValidationError {
    fn from(s: String) -> Self {
        ValidationError::Error(s)
    }
}

impl From<&str> for ValidationError {
    fn from(s: &str) -> Self {
        ValidationError::Error(s.to_string())
    }
}

impl From<VarError> for ValidationError {
    fn from(error: VarError) -> Self {
        ValidationError::Error(format!("Could not parse env var: {}", error))
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::Error(s) => write!(f, "Validation failed because of an error: {}", s),
            ValidationError::Insecure(s) => {
                write!(f, "Validation failed. Insecure Contract found: {}", s)
            }
            ValidationError::Invalid(s) => {
                write!(f, "Validation failed. Deployment invalid: {}", s)
            }
            ValidationError::NoDVFFound(s) => write!(f, "Validation failed. DVF(s) missing: {}", s),
        }
    }
}

fn bytes_to_hex<T, S>(bytes: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: AsRef<[u8]>,
    S: Serializer,
{
    serializer.serialize_str(&format!("0x{}", hex::encode(bytes)))
}

fn hex_to_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    hex::decode(s.trim_start_matches("0x")).map_err(|err| serde::de::Error::custom(err.to_string()))
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum DVFStorageComparisonOperator {
    Equal,
    NotEqual,
    GreaterThan,
    LessThan,
    GreaterThanOrEqual,
    LessThanOrEqual,
}

impl std::fmt::Display for DVFStorageComparisonOperator {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            DVFStorageComparisonOperator::Equal => write!(f, "=="),
            DVFStorageComparisonOperator::NotEqual => write!(f, "!="),
            DVFStorageComparisonOperator::GreaterThan => write!(f, ">"),
            DVFStorageComparisonOperator::LessThan => write!(f, "<"),
            DVFStorageComparisonOperator::GreaterThanOrEqual => write!(f, ">="),
            DVFStorageComparisonOperator::LessThanOrEqual => write!(f, "<="),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct DVFStorageEntry {
    pub slot: U256,       // EVM Storage Slot
    pub offset: usize,    // Offset in bytes, Range 0 - 30
    pub var_name: String, // Decoded Variable Name, e.g. balances[0x1234] or owner
    pub var_type: Option<String>,
    #[serde(deserialize_with = "hex_to_bytes", serialize_with = "bytes_to_hex")]
    pub value: Vec<u8>, // Byte-String of variable size according to variable length
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_hint: Option<String>, // Unvalidated extra information about the value
    pub comparison_operator: DVFStorageComparisonOperator,
}

impl DVFStorageEntry {
    pub fn is_zero(&self) -> bool {
        self.value.iter().all(|b| *b == 0u8)
    }

    pub fn compare(&self, cur_value: &[u8]) -> bool {
        match self.comparison_operator {
            DVFStorageComparisonOperator::Equal => self.value == cur_value,
            DVFStorageComparisonOperator::NotEqual => self.value != cur_value,
            DVFStorageComparisonOperator::GreaterThan => match self.get_ordering(cur_value) {
                Ordering::Less => false,
                Ordering::Equal => false,
                Ordering::Greater => true,
            },
            DVFStorageComparisonOperator::LessThan => match self.get_ordering(cur_value) {
                Ordering::Less => true,
                Ordering::Equal => false,
                Ordering::Greater => false,
            },
            DVFStorageComparisonOperator::GreaterThanOrEqual => {
                match self.get_ordering(cur_value) {
                    Ordering::Less => false,
                    Ordering::Equal => true,
                    Ordering::Greater => true,
                }
            }
            DVFStorageComparisonOperator::LessThanOrEqual => match self.get_ordering(cur_value) {
                Ordering::Less => true,
                Ordering::Equal => true,
                Ordering::Greater => false,
            },
        }
    }

    fn get_ordering(&self, cur_value: &[u8]) -> Ordering {
        if let Some(var_type) = self.var_type.clone() {
            if var_type.starts_with("t_int") {
                let val1 = convert_bytes_to_i256(cur_value, var_type.as_str());
                let val2 = convert_bytes_to_i256(&self.value, var_type.as_str());
                return val1.cmp(&val2);
            }
        } else {
            println!("Warning: {} comparison on variable {} which does not have an associated type. The comparison might yield unexpected results", self.comparison_operator, self.var_name);
        }
        Iterator::cmp(cur_value.iter(), self.value.iter())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DVFEventOccurrence {
    pub topics: Vec<B256>,
    pub data: Bytes,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DVFEventEntry {
    pub sig: String,  // Event signature, e.g. "Transfer(address,address,uint256)"
    pub topic0: B256, // Event Topic 0
    pub occurrences: Vec<DVFEventOccurrence>, // Where the event has legitimately occurred
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DVFFunctionEntry {
    pub sig: String, // Function Signature, e.g. "transfer(address,address,uint256)"
    pub four_bytes: String, // 4-Byte signature, e.g. "0x12345678"
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DVFImmutableEntry {
    pub var_name: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_hint: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DVFConstructorArg {
    pub var_name: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_hint: Option<String>,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Unvalidated {
    #[serde(skip_serializing_if = "Option::is_none")]
    author_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hardfork: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    audit_report: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    security_contact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    implementation_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    implementation_address: Option<Address>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DVFSignature {
    pub sig_data: Option<String>,
    pub signer: Address,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NamedReference {
    pub id: String,
    pub contract_name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CompleteDVF {
    pub version: Version,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub contract_name: String,
    pub address: Address,
    pub chain_id: u64,
    pub deployment_block_num: u64,
    pub init_block_num: u64,
    pub deployment_tx: String,
    pub codehash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub insecure: Option<bool>,
    pub immutables: Vec<DVFImmutableEntry>,
    pub constructor_args: Vec<DVFConstructorArg>,
    pub critical_storage_variables: Vec<DVFStorageEntry>,
    pub critical_events: Vec<DVFEventEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry_in_epoch_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub references: Option<Vec<NamedReference>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unvalidated_metadata: Option<Unvalidated>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<DVFSignature>,
}

impl CompleteDVF {
    pub fn from_path(path: &Path) -> Result<Self, ValidationError> {
        let mut file = File::open(path)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        debug!("{}", content);

        let filled: CompleteDVF = serde_json::from_str(&content)?;
        filled.check_version()?;

        Ok(filled)
    }

    pub fn from_cli(matches: &ArgMatches) -> Result<Self, ValidationError> {
        let immutables: Vec<DVFImmutableEntry> = vec![];
        let critical_storage_variables: Vec<DVFStorageEntry> = vec![];
        let critical_events: Vec<DVFEventEntry> = vec![];
        let constructor_args: Vec<DVFConstructorArg> = vec![];
        let implementation_name = matches.get_one::<String>("implementation").cloned();
        let dumped = CompleteDVF {
            version: CURRENT_VERSION,
            id: None,
            contract_name: matches.get_one::<String>("contractname").unwrap().clone(),
            address: *matches.get_one::<Address>("address").unwrap(),
            chain_id: *matches.get_one("chainid").unwrap(),
            codehash: String::new(),
            deployment_tx: String::new(),
            deployment_block_num: 0,
            init_block_num: 0,
            insecure: Some(false),
            immutables,
            constructor_args,
            critical_storage_variables,
            critical_events,
            expiry_in_epoch_seconds: None,
            references: None,
            unvalidated_metadata: Some(Unvalidated {
                author_name: Some(String::from("Author")),
                description: Some(String::from("System Description")),
                hardfork: Some(vec![String::from("paris"), String::from("shanghai")]),
                audit_report: Some(String::from("https://example.org/report.pdf")),
                source_url: Some(String::from("https://github.com/source/code")),
                security_contact: Some(String::from("security@example.org")),
                implementation_name,
                implementation_address: None, // currently no source for this
            }),
            signature: None,
        };
        dumped.check_version()?;
        Ok(dumped)
    }

    pub fn copy_immutables(&mut self, project_info: &ProjectInfo, pretty_printer: &PrettyPrinter) {
        self.immutables = project_info
            .immutables
            .iter()
            .map(|x| -> DVFImmutableEntry {
                let translated_type = format!("t_{}", &x.type_string);
                DVFImmutableEntry {
                    var_name: x.name.clone(),
                    value: x.value.clone(),
                    value_hint: match pretty_printer
                        .pretty_value_short(&translated_type, &x.value, true)
                        .as_str()
                    {
                        "" => None,
                        other => Some(other.to_string()),
                    },
                }
            })
            .collect::<Vec<DVFImmutableEntry>>();
    }

    pub fn copy_constructor_args(
        &mut self,
        project_info: &ProjectInfo,
        pretty_printer: &PrettyPrinter,
    ) {
        self.constructor_args = project_info
            .constructor_args
            .iter()
            .map(|x| -> DVFConstructorArg {
                // TODO: This is wrong. Hotfixed for now
                // Needs a proper translation, e.g. uint[] => t_array_uint...
                // Then those types might be unknown
                let translated_type = format!("t_{}", &x.type_string);
                DVFConstructorArg {
                    var_name: x.name.clone(),
                    value: x.value.clone(),
                    value_hint: match pretty_printer
                        .pretty_value_short(&translated_type, &x.value, true)
                        .as_str()
                    {
                        "" => None,
                        other => Some(other.to_string()),
                    },
                }
            })
            .collect::<Vec<DVFConstructorArg>>();
    }

    pub fn add_reference(&mut self, new_ref_id: &str, new_ref_name: &str) {
        let named_ref = NamedReference {
            id: new_ref_id.to_owned(),
            contract_name: new_ref_name.to_owned(),
        };
        if let Some(refs) = self.references.as_mut() {
            refs.push(named_ref);
        } else {
            let references: Vec<NamedReference> = vec![named_ref];
            self.references = Some(references);
        }
    }

    pub fn validate_signature(&self, require_sig: bool) -> Result<(), ValidationError> {
        match &self.signature {
            Some(sig) => match &sig.sig_data {
                Some(sig_data) => {
                    // let signature = Signature::from_str(sig_data).unwrap();
                    let signature: Signature = serde_json::from_str(sig_data).unwrap();
                    let sig_message = self.get_sig_message()?;
                    debug!("sig_message: {:?}", sig_message);
                    let rec_address =
                        signature
                            .recover_address_from_msg(sig_message)
                            .map_err(|_| {
                                ValidationError::Error(String::from(
                                    "Error. Signature validation failed.",
                                ))
                            })?;
                    debug!("Provided Address: {:?}", &sig.signer);
                    debug!("Recovered address {:?}", rec_address);
                    if sig.signer != rec_address {
                        return Err(ValidationError::Error(
                            "Incorrect signature detected.".to_string(),
                        ));
                    }
                    Ok(())
                }
                None => Err(ValidationError::Error(
                    "Signature field present but without signature data.".to_string(),
                )),
            },
            None => {
                if require_sig {
                    Err(ValidationError::Error(
                        "Signature required, but none present.".to_string(),
                    ))
                } else {
                    Ok(())
                }
            }
        }
    }

    pub fn validate_id(&self) -> Result<(), ValidationError> {
        let mut cloned_self = self.clone();
        let new_id = cloned_self.generate_id()?;
        let ids_equal = self.id == Some(new_id);
        debug!("Id validation result: {:?}", ids_equal,);
        if ids_equal {
            Ok(())
        } else {
            Err(ValidationError::Error(
                "Error. Id validation failed.".to_string(),
            ))
        }
    }

    pub fn set_signer(&mut self, new_signer: &Address) {
        if let Some(sig) = self.signature.as_mut() {
            sig.signer = *new_signer;
        } else {
            self.signature = Some(DVFSignature {
                signer: *new_signer,
                sig_data: None,
            });
        }
    }

    pub fn check_valid_signer(&self) -> Result<(), ValidationError> {
        if self.signature.is_none() {
            return Err(ValidationError::Error(
                "Signer needs to be set.".to_string(),
            ));
        }
        Ok(())
    }

    pub fn clear_signature_data(&mut self) {
        if let Some(sig) = self.signature.as_mut() {
            sig.sig_data = None;
        }
    }

    pub fn clear_signature(&mut self) {
        self.signature = None;
    }

    pub fn clear_references(&mut self) {
        self.references = None;
    }

    pub fn clear_id(&mut self) {
        self.id = None;
    }

    pub fn generate_id(&mut self) -> Result<String, ValidationError> {
        self.id = None;
        let mut hasher = Keccak::v256();
        let mut cloned = self.clone();
        cloned.clear_signature_data();
        cloned.clear_references();
        let canonical_json: Value = serde_json::to_value(cloned)?;
        let json_as_string = canonical_json.to_string();
        hasher.update(json_as_string.as_bytes());
        // Prepare the output array.
        let mut output = [0u8; 32];
        hasher.finalize(&mut output);
        let raw_id = format!("0x{}", &hex::encode(output));
        self.id = Some(raw_id.clone());
        Ok(raw_id)
    }

    // The message that the signature is computed over
    fn get_sig_message(&self) -> Result<String, ValidationError> {
        let mut cloned = self.clone();
        cloned.clear_signature_data();
        let canonical_json: Value = serde_json::to_value(cloned)?;
        let to_be_signed_data = canonical_json.to_string();
        Ok(to_be_signed_data)
    }

    pub fn sign(&mut self, config: &DVFConfig) -> Result<(), ValidationError> {
        let signature = match &config.signer {
            None => {
                return Err(ValidationError::from(
                    "No signer set in config. Cannot sign DVF.",
                ))
            }
            Some(signer) => {
                self.clear_signature_data();
                self.set_signer(&signer.wallet_address);
                self.generate_id()?;
                let to_be_signed_data = self.get_sig_message()?;
                debug!("Sig message: {}", to_be_signed_data);
                // Chain ID should not matter here
                let wallet = config.get_abstract_wallet(1)?;
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(wallet.sign_message(to_be_signed_data.as_bytes()))?
            }
        };
        if let Some(sig) = self.signature.as_mut() {
            let signature_str = serde_json::to_string(&signature).unwrap();
            sig.sig_data = Some(signature_str);
        };
        Ok(())
    }

    pub fn get_fname(&self) -> String {
        match &self.id {
            Some(id) => {
                let fname = format!("{}_{:?}.dvf.json", id, &self.address);
                fname
            }
            None => String::from("generated.dvf.json"),
        }
    }

    fn check_version(&self) -> Result<(), ValidationError> {
        let version = self.get_version();
        if version < &LOWEST_SUPPORTED_VERSION {
            return Err(ValidationError::Error("DV Version too old.".to_string()));
        }
        if version > &HIGHEST_SUPPORTED_VERSION {
            return Err(ValidationError::Error("DV Version too new.".to_string()));
        }
        Ok(())
    }

    pub fn write_to_file(&self, path: &Path) -> Result<(), ValidationError> {
        let output = serde_json::to_string_pretty(&self)?;

        let mut file = File::create(path)?;
        file.write_all(output.as_bytes())?;
        Ok(())
    }

    fn get_version(&self) -> &Version {
        &self.version
    }
}
