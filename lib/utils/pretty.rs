use std::collections::HashMap;
use std::ops::BitAnd;
use std::str::FromStr;

use alloy::json_abi::Event;
use alloy::primitives::{Address, Sign, I256, U256};

use alloy_chains::NamedChain;
use alloy_dyn_abi::{DecodedEvent, DynSolValue};
use prettytable::Table;
use serde::Deserialize;
use tracing::debug;
use tracing::info;

// Watch out for other Log types
use crate::dvf::config::DVFConfig;
use crate::dvf::registry::Registry;
use crate::state::contract_state::ContractState;

#[derive(Deserialize, Debug)]
pub enum AddressType {
    Token,
    Contract,
    Registry,
    Local,
    Eoa,
}

#[derive(Debug, Deserialize)]
pub struct ResolvedAddress {
    pub address_type: AddressType,
    pub name: String,
}

// The PrettyPrinter is always bound to a particular chain ID
#[derive(Debug)]
pub struct PrettyPrinter {
    ns: HashMap<Address, ResolvedAddress>,
    chain_id: u64,
}

const KNOWN_ADDRS: &str = include_str!("../../addresses/known.json");
const CHARS_PER_LINE: usize = 70;

impl PrettyPrinter {
    pub fn new(config: &DVFConfig, registry: Option<&Registry>) -> Self {
        let chain_id = config
            .active_chain_id
            .expect("Pretty Printing requires a Chain ID.");
        let mut ns: HashMap<Address, ResolvedAddress> = HashMap::new();
        let mut new_names: HashMap<u64, HashMap<Address, ResolvedAddress>> =
            match serde_json::from_str(KNOWN_ADDRS) {
                Ok(n) => n,
                Err(e) => {
                    info!("Could not parse provided JSON addresses: {:?}", e);
                    HashMap::new()
                }
            };
        if let Some(some_names) = new_names.remove(&chain_id) {
            ns.extend(some_names);
        }
        if let Some(registry) = registry {
            ns.extend(registry.collect_name_resolution(chain_id));
        }
        debug!("Name Resolution has {} entries.", ns.keys().len());
        PrettyPrinter { ns, chain_id }
    }

    pub fn event_to_string(event: &Event) -> String {
        event.signature()
    }

    pub fn pretty_event_params(
        &self,
        abi_event: &Event,
        decoded_event: &DecodedEvent,
        newlines: bool,
    ) -> String {
        let mut decoded_params: Vec<String> = vec![];
        let mut next_index = 0;
        let mut next_body = 0;
        for param in &abi_event.inputs {
            let current_val: &DynSolValue = if param.indexed {
                next_index += 1;
                &decoded_event.indexed[next_index - 1]
            } else {
                next_body += 1;
                &decoded_event.body[next_body - 1]
            };
            decoded_params.push(format!(
                "{} = {}",
                &param.name,
                Self::insert_newline_every_n_chars(
                    &self.pretty_token(current_val),
                    CHARS_PER_LINE,
                    param.name.len() + 4
                ),
            ));
        }
        if newlines {
            format!("({})", decoded_params.join(",\n "))
        } else {
            format!("({})", decoded_params.join(", "))
        }
    }

    pub fn pretty_token(&self, dyn_val: &DynSolValue) -> String {
        match dyn_val {
            DynSolValue::Address(addr) => self.pretty_address(addr, false, false),
            DynSolValue::FixedBytes(fbytes, _num_bytes) => format!("0x{}", hex::encode(fbytes)),
            DynSolValue::Bytes(bytes) => format!("0x{}", hex::encode(bytes)),
            DynSolValue::Int(int, _num_bits) => Self::pretty_int(int),
            DynSolValue::Uint(uint, _num_bits) => Self::pretty_uint(uint),
            DynSolValue::Bool(b) => Self::pretty_bool(*b),
            DynSolValue::String(s) => s.clone(),
            DynSolValue::FixedArray(arr) | DynSolValue::Array(arr) => {
                let decoded: Vec<String> = arr.iter().map(|a| self.pretty_token(a)).collect();
                format!("[{}]", decoded.join(", "))
            }
            DynSolValue::Tuple(arr) => {
                let decoded: Vec<String> = arr.iter().map(|a| self.pretty_token(a)).collect();
                format!("({})", decoded.join(", "))
            }
            DynSolValue::Function(func) => {
                format!("function {:?}", func)
            }
            DynSolValue::CustomStruct {
                name: _name,
                prop_names: _prop_name,
                tuple,
            } => {
                let decoded: Vec<String> = tuple.iter().map(|a| self.pretty_token(a)).collect();
                format!("({})", decoded.join(", "))
            }
        }
    }

    fn pretty_uint(u256: &U256) -> String {
        // TODO Timestamps
        if u256 == &U256::MAX {
            return String::from("uint256 Max Value");
        }
        let u256_str = u256.to_string();
        let decimals = u256_str.len() - 1;

        if decimals > 3 {
            format!(
                "{}.{} * 10^{}",
                &u256_str[0..1],
                u256_str[1..].to_string().trim_end_matches('0'),
                decimals
            )
        } else {
            u256_str.to_string()
        }
    }

    fn pretty_int(i256: &I256) -> String {
        let i256_str = i256.to_string();
        let s_offset = match i256.sign() {
            Sign::Negative => 2,
            Sign::Positive => 1,
        };
        let decimals = i256_str.len() - s_offset;

        if decimals > 3 {
            format!(
                "{}.{} * 10^{}",
                &i256_str[0..s_offset],
                i256_str[s_offset..].to_string().trim_end_matches('0'),
                decimals
            )
        } else {
            i256_str.to_string()
        }
    }

    fn pretty_bool(b: bool) -> String {
        if b {
            String::from("true")
        } else {
            String::from("false")
        }
    }

    fn pretty_address(&self, a: &Address, long: bool, leave_empty: bool) -> String {
        if let Some(resolved) = self.ns.get(a) {
            match resolved.address_type {
                AddressType::Contract | AddressType::Token | AddressType::Registry => {
                    if long {
                        if let Ok(chain) = NamedChain::try_from(self.chain_id) {
                            if let Some(urls) = chain.etherscan_urls() {
                                return format!(
                                    "{}\nLink:\n{}/address/{:?}",
                                    resolved.name, urls.0, a
                                );
                            };
                        }
                        resolved.name.clone()
                    } else {
                        resolved.name.clone()
                    }
                }
                _ => resolved.name.clone(),
            }
        } else if leave_empty {
            String::new()
        } else {
            format!("{:?}", &a)
        }
    }

    pub fn pretty_value_long_from_bytes(
        &self,
        var_type: &String,
        value: &Vec<u8>,
        leave_empty: bool,
    ) -> String {
        self.pretty_value_from_bytes(var_type, value, true, leave_empty)
    }

    pub fn pretty_value_short_from_bytes(
        &self,
        var_type: &String,
        value: &Vec<u8>,
        leave_empty: bool,
    ) -> String {
        self.pretty_value_from_bytes(var_type, value, false, leave_empty)
    }

    pub fn pretty_value_long(
        &self,
        var_type: &String,
        value: &String,
        leave_empty: bool,
    ) -> String {
        self.pretty_value(var_type, value, true, leave_empty)
    }

    pub fn pretty_value_short(
        &self,
        var_type: &String,
        value: &String,
        leave_empty: bool,
    ) -> String {
        self.pretty_value(var_type, value, false, leave_empty)
    }

    fn pretty_value_from_bytes(
        &self,
        var_type: &String,
        value: &Vec<u8>,
        long: bool,
        leave_empty: bool,
    ) -> String {
        if ContractState::is_int(var_type) {
            let i256 = convert_bytes_to_i256(value, var_type);
            return Self::pretty_int(&i256);
        } else if ContractState::is_uint(var_type) {
            let u256 = U256::from_be_slice(value);
            return Self::pretty_uint(&u256);
        } else if ContractState::is_address(var_type) {
            let a = Address::from_slice(&value[value.len() - 20..]);
            return self.pretty_address(&a, long, leave_empty);
        } else if ContractState::is_bool(var_type) {
            let last_byte: u8 = *value.last().unwrap();
            if last_byte == 0u8 {
                return String::from("false");
            } else if last_byte == 1u8 {
                return String::from("true");
            } else {
                return format!("Invalid Boolean: {}", last_byte);
            }
        }
        debug!("No pretty printing for: {var_type}.");
        if leave_empty {
            String::new()
        } else {
            format!("0x{}", hex::encode(value))
        }
    }

    fn pretty_value(
        &self,
        var_type: &String,
        value: &String,
        long: bool,
        leave_empty: bool,
    ) -> String {
        if ContractState::is_int(var_type) {
            debug!("Int: {}", value);
            let bytes = hex::decode(value.trim_start_matches("0x")).unwrap();
            let i256 = convert_bytes_to_i256(&bytes, var_type);
            return Self::pretty_int(&i256);
        } else if ContractState::is_uint(var_type) {
            let u256 = U256::from_str_radix(value.trim_start_matches("0x"), 16).unwrap();
            return Self::pretty_uint(&u256);
        } else if ContractState::is_address(var_type) {
            match Address::from_str(&value[value.len() - 40..]) {
                Ok(a) => return self.pretty_address(&a, long, leave_empty),
                Err(_e) => {
                    todo!("This is bad");
                }
            };
        } else if ContractState::is_bool(var_type) {
            if value.ends_with("00") {
                return String::from("false");
            } else if value.ends_with("01") {
                return String::from("true");
            } else {
                return format!("Invalid Boolean: 0x{}", &value[value.len() - 2..]);
            }
        }
        debug!("No pretty printing for: {var_type}.");
        if leave_empty {
            String::new()
        } else {
            value.clone()
        }
    }

    fn insert_newline_every_n_chars(s: &str, n: usize, indent: usize) -> String {
        let mut result = String::with_capacity(s.len() + (s.len() / n) * (1 + indent));
        for (idx, char) in s.chars().enumerate() {
            result.push(char);
            if (idx + 1) % n == 0 {
                result.push('\n');
                result.push_str(&" ".repeat(indent));
            }
        }
        result
    }

    // Add a row to the table and make sure it isn't too long
    pub fn add_formatted_to_table(col1: &str, col2: &str, table: &mut Table) {
        table.add_row(row![
            Self::insert_newline_every_n_chars(col1, CHARS_PER_LINE, 0),
            Self::insert_newline_every_n_chars(col2, CHARS_PER_LINE, 0)
        ]);
    }

    // Decodes a value of the given type, adds it to the table and returns it
    pub fn add_decoded_to_table_from_bytes(
        &self,
        var_type: &String,
        value: &Vec<u8>,
        table: &mut Table,
    ) {
        assert!(ContractState::is_basic_type(var_type));
        let pretty_value = self.pretty_value_long_from_bytes(var_type, value, true);

        if !pretty_value.is_empty() {
            Self::add_formatted_to_table(" [+] Decoded:", &pretty_value, table);
        }
    }

    // Decodes a value of the given type, adds it to the table and returns it
    pub fn add_decoded_to_table(&self, var_type: &String, value: &String, table: &mut Table) {
        // TODO: Add support for user defined types
        if ContractState::is_user_defined_type(var_type) {
            return;
        }
        if !ContractState::is_basic_type(var_type) {
            // TODO: Fix this
            debug!("Skipping non-basic type: {}", var_type);
            return;
        }
        let pretty_value = self.pretty_value_long(var_type, value, true);

        if !pretty_value.is_empty() {
            Self::add_formatted_to_table(" [+] Decoded:", &pretty_value, table);
        }
    }
}

pub fn convert_bytes_to_i256(bytes: &[u8], var_type: &str) -> I256 {
    if var_type != "t_int256" {
        // Skip "t_int"
        let num_int_bits = var_type[5..]
            .parse::<usize>()
            .unwrap_or_else(|_| panic!("Fatal error: Unknown type: {}", var_type));
        let msb_set: bool = bytes[bytes.len() - 1 - (num_int_bits - 1) / 8usize]
            .bitand(1u8 << ((num_int_bits - 1) % 8usize))
            != 0;

        let mut full_bytes = match msb_set {
            true => [255u8; 32],
            false => [0u8; 32],
        };
        let num_used_bytes = num_int_bits / 8;
        let num_unused_bytes = 32 - num_used_bytes;
        for i in 0..num_used_bytes {
            full_bytes[i + num_unused_bytes] = bytes[bytes.len() - num_used_bytes + i];
        }
        let u256 = U256::from_be_slice(&full_bytes);
        I256::from_raw(u256)
    } else {
        let u256 = U256::from_be_slice(bytes);
        I256::from_raw(u256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_bytes_to_i256() {
        let b = vec![0xff];
        assert_eq!(I256::MINUS_ONE, convert_bytes_to_i256(&b, "t_int8"));
        let b2 = vec![0xff, 0xff];
        assert_eq!(I256::MINUS_ONE, convert_bytes_to_i256(&b2, "t_int16"));
        let b3 = vec![0xff, 0xfe];
        assert_eq!(
            I256::MINUS_ONE + I256::MINUS_ONE,
            convert_bytes_to_i256(&b3, "t_int16")
        );
        let b4 = vec![0, 0xff, 0xfe];
        assert_eq!(
            I256::MINUS_ONE + I256::MINUS_ONE,
            convert_bytes_to_i256(&b4, "t_int16")
        );
        let b5 = vec![0x00];
        assert_eq!(I256::ZERO, convert_bytes_to_i256(&b5, "t_int8"));
        let b6 = vec![0x00, 0x00];
        assert_eq!(I256::ZERO, convert_bytes_to_i256(&b6, "t_int16"));
        let b7 = vec![0x00, 0x01];
        assert_eq!(I256::ONE, convert_bytes_to_i256(&b7, "t_int16"));
        let b8 = vec![0, 0x00, 0x02];
        assert_eq!(I256::ONE + I256::ONE, convert_bytes_to_i256(&b8, "t_int16"));
        let b9 = vec![0u8; 32];
        assert_eq!(I256::ZERO, convert_bytes_to_i256(&b9, "t_int256"));
        for i in vec![I256::ZERO, I256::ONE, I256::MINUS_ONE, I256::MAX, I256::MAX] {
            let bytes: [u8; 32] = i.to_be_bytes();
            assert_eq!(i, convert_bytes_to_i256(&bytes.to_vec(), "t_int256"));
        }
        for i in vec![I256::ZERO, I256::ONE, I256::MINUS_ONE] {
            let bytes: [u8; 32] = i.to_be_bytes();
            assert_eq!(i, convert_bytes_to_i256(&bytes.to_vec(), "t_int128"));
        }
        let b10 = vec![0x80];
        assert_eq!(
            I256::from_dec_str("-128").unwrap(),
            convert_bytes_to_i256(&b10, "t_int8")
        );
    }
}
