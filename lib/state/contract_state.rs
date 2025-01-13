use std::cmp;
use std::collections::{HashMap, HashSet};
use std::ops::Add;
use std::str::FromStr;

use alloy::primitives::{keccak256, Address, B256, U256};
use prettytable::Table;
use tracing::{debug, info};

use crate::dvf::config::DVFConfig;
use crate::dvf::parse;
use crate::dvf::parse::DVFStorageEntry;
use crate::dvf::parse::ValidationError;
use crate::state::contract_state::parse::DVFStorageComparisonOperator;
use crate::state::forge_inspect::{ForgeInspect, StateVariable, TypeDescription};
use crate::utils::pretty::PrettyPrinter;
use crate::web3::{get_internal_create_addresses, StorageSnapshot, TraceWithAddress};

fn hash_u256(u: &U256) -> B256 {
    keccak256(u.to_be_bytes::<32>())
}

// Take a hex-string with leading 0x and
// return the hash as a hex-string with leading 0x
pub fn hex_keccak_hex(input: &str) -> String {
    assert!(input.len() == 66);
    let bytes = hex::decode(&input[2..]).unwrap();
    let res = keccak256(bytes);
    format!("0x{}", hex::encode(res))
}

#[derive(Debug)]
pub struct ContractState<'a> {
    // The state variables from the storage layout
    pub state_variables: Vec<StateVariable>,
    // Records types in this contract
    pub types: HashMap<String, TypeDescription>,
    // Storage Index of Mapping -> (Key, derived storage slot)
    pub mapping_usages: HashMap<U256, HashSet<(String, U256)>>,
    // The contract address
    pub address: Address,
    // Print human readable
    pub pretty_printer: &'a PrettyPrinter,
}

impl<'a> ContractState<'a> {
    pub fn new(address: &str, pretty_printer: &'a PrettyPrinter) -> Self {
        ContractState {
            state_variables: vec![],
            types: HashMap::new(),
            mapping_usages: HashMap::new(),
            address: Address::from_str(address).unwrap(),
            pretty_printer,
        }
    }

    pub fn new_with_address(address: &Address, pretty_printer: &'a PrettyPrinter) -> Self {
        ContractState {
            state_variables: vec![],
            types: HashMap::new(),
            mapping_usages: HashMap::new(),
            address: *address,
            pretty_printer,
        }
    }

    fn add_state_variable(&mut self, sv: &StateVariable) {
        let mut found = false;
        for existing_sv in &self.state_variables {
            if existing_sv.slot == sv.slot
                && ((existing_sv.offset <= sv.offset
                    && existing_sv.offset + self.get_number_of_bytes(&existing_sv.var_type)
                        > sv.offset)
                    || (sv.offset <= existing_sv.offset
                        && sv.offset + self.get_number_of_bytes(&sv.var_type) > existing_sv.offset))
            {
                info!(
                    "Warning! Conflicting variable definitions for {} and {}",
                    existing_sv.label, sv.label
                );
                found = true;
                break;
            }
        }
        if !found {
            self.state_variables.push(sv.clone());
        }
    }

    fn add_type(&mut self, var_type: &String, type_desc: &TypeDescription) {
        if self.types.contains_key(var_type) {
            if &self.types[var_type] != type_desc {
                info!("Warning! Conflicting type definitions for: {}", var_type);
            }
        } else {
            self.types.insert(var_type.clone(), type_desc.clone());
        }
    }

    pub fn add_forge_inspect(&mut self, fi: &ForgeInspect) {
        for (var_type, type_desc) in fi.types.iter() {
            self.add_type(var_type, type_desc);
        }

        for sv in &fi.storage {
            self.add_state_variable(sv);
        }
    }

    fn memory_as_string(memory: &Vec<String>) -> String {
        let mut mem_string = String::new();
        for mem in memory {
            mem_string += mem;
        }

        mem_string
    }

    fn fetch_memory_slice(start_idx: &U256, length: &U256, memory: &Vec<String>) -> String {
        let mem_str = Self::memory_as_string(memory);
        let start_idx = start_idx.to::<usize>() * 2;
        let length = length.to::<usize>() * 2;

        mem_str[start_idx..(start_idx + length)].to_string()
    }

    pub fn record_traces(
        &mut self,
        config: &DVFConfig,
        traces: Vec<TraceWithAddress>,
    ) -> Result<(), ValidationError> {
        debug!("recording traces");
        let mut first_trace = true;
        for trace_w_a in traces {
            if trace_w_a.trace.failed {
                continue;
            }

            // Track which contract we are in
            let mut depth_to_address: HashMap<u64, Address> = HashMap::new();
            depth_to_address.insert(1, trace_w_a.address);

            let mut create_addresses: Option<Vec<Address>> = None;

            // Mapping key, Some if previous op was a SHA3
            let mut key: Option<String> = None;
            // Mapping storage index, only meaningful when key is Some
            let mut index: U256 = U256::from(1);
            for log in trace_w_a.trace.struct_logs {
                // Boring state
                if log.stack.is_none() {
                    continue;
                }
                // Fine because we checked
                let stack = log.stack.unwrap();

                if log.op == "CREATE" || log.op == "CREATE2" {
                    if first_trace {
                        if create_addresses.is_none() {
                            // Fetch call trace lazily if we need it
                            create_addresses =
                                Some(get_internal_create_addresses(config, &trace_w_a.tx_id)?);
                        }
                        if let Some(ref mut create_ref) = create_addresses {
                            depth_to_address.insert(log.depth + 1, create_ref.remove(0));
                        }
                    } else {
                        // Insert dummy address as we don't care about this address
                        // That way we avoid fetching it
                        depth_to_address.insert(log.depth + 1, Address::from([0; 20]));
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

                if depth_to_address[&log.depth] == self.address {
                    if let Some(key_in) = key {
                        let target_slot = &stack[stack.len() - 1];
                        if !self.mapping_usages.contains_key(&index) {
                            let mut usage_set = HashSet::new();
                            usage_set.insert((key_in, *target_slot));
                            self.mapping_usages.insert(index, usage_set);
                        } else {
                            let mut current_usages = self.mapping_usages[&index].clone();
                            current_usages.insert((key_in, *target_slot));
                            self.mapping_usages.insert(index, current_usages);
                        }
                        key = None;
                    }
                    if log.op == "KECCAK256" || log.op == "SHA3" {
                        let length_in_bytes = stack[stack.len() - 2];
                        let sha3_input = format!(
                            "0x{}",
                            Self::fetch_memory_slice(
                                &stack[stack.len() - 1],
                                &stack[stack.len() - 2],
                                &log.memory.unwrap(),
                            )
                        );
                        // Look for mapping usages
                        if length_in_bytes > U256::from(32_u64)
                            && length_in_bytes < U256::from(usize::MAX / 2)
                        {
                            let usize_str_length =
                                usize::try_from(length_in_bytes).unwrap() * 2 + 2;
                            assert!(sha3_input.len() == usize_str_length);
                            key = Some(sha3_input[2..usize_str_length - 64].to_string());
                            index = U256::from_str_radix(&sha3_input[usize_str_length - 64..], 16)?;
                            debug!("Found key {} for index {}.", key.clone().unwrap(), index);
                        }
                    }
                }
            }
            // Check that we used all addresses
            if let Some(addrs) = create_addresses {
                assert_eq!(addrs.len(), 0);
            }
            first_trace = false;
        }
        Ok(())
    }

    fn add_to_table(storage_entry: &parse::DVFStorageEntry, table: &mut Table) {
        PrettyPrinter::add_formatted_to_table(
            &storage_entry.var_name,
            &format!("0x{}", hex::encode(&storage_entry.value)),
            table,
        );
    }

    pub fn get_critical_storage_variables(
        &mut self,
        snapshot: &mut StorageSnapshot,
        table: &mut Table,
        pi_storage: &Vec<StateVariable>,
        pi_types: &HashMap<String, TypeDescription>,
    ) -> Result<Vec<parse::DVFStorageEntry>, ValidationError> {
        let default_values = &ForgeInspect::default_values();
        // Add default types as we might need them
        let mut types = default_values.types.clone();
        types.extend(pi_types.to_owned());
        for (var_type, type_desc) in types.iter() {
            self.add_type(var_type, type_desc);
        }

        let mut critical_storage_variables = Vec::<parse::DVFStorageEntry>::new();

        for state_variable in &self.state_variables {
            critical_storage_variables.extend(self.get_critical_variable(
                state_variable,
                snapshot,
                table,
            )?);
        }

        let mut storage = default_values.storage.clone();
        storage.extend(pi_storage.to_owned());
        for sv in &storage {
            // // Skip used slots, assume that the we won't have partial usage in case of structs
            // let min_size = cmp::min(self.get_number_of_bytes(&sv.var_type), 32 - sv.offset);
            // if !snapshot.check_if_set_and_unused(&sv.slot, sv.offset, min_size) {
            //     debug!("Skipping default var {} because it overlaps with existing or is uninitialized.", sv.label);
            //     continue;
            // }

            let new_critical_storage_variables = self.get_critical_variable(sv, snapshot, table)?;
            let mut has_nonzero = false;
            for crit_var in &new_critical_storage_variables {
                if !crit_var.is_zero() {
                    has_nonzero = true;
                    break;
                }
            }
            if has_nonzero {
                critical_storage_variables.extend(new_critical_storage_variables);
            }
        }
        let unused_parts = snapshot.get_unused_nonzero_storage_slots();
        if !unused_parts.is_empty() {
            println!(
                "Warning: {} unknown storage slots found.",
                unused_parts.len()
            );
        }

        for unused_part in unused_parts {
            let crit_var: DVFStorageEntry = DVFStorageEntry {
                slot: unused_part.slot,
                offset: unused_part.offset,
                var_name: String::from("unknown"),
                var_type: None,
                value: unused_part.value.clone(),
                value_hint: None,
                comparison_operator: DVFStorageComparisonOperator::Equal,
            };
            critical_storage_variables.push(crit_var);
        }
        Ok(critical_storage_variables)
    }

    fn get_key_type(&self, var_type: &String) -> String {
        self.types[var_type].key.clone().unwrap()
    }

    fn get_value_type(&self, var_type: &String) -> String {
        self.types[var_type].value.clone().unwrap()
    }

    fn get_base_type(&self, var_type: &String) -> String {
        self.types[var_type].base.clone().unwrap()
    }

    fn get_base_num_bytes(&self, var_type: &String) -> usize {
        let base_type = self.get_base_type(var_type);
        self.get_number_of_bytes(&base_type)
    }

    pub fn get_number_of_bytes(&self, var_type: &String) -> usize {
        self.types[var_type].number_of_bytes
    }

    pub fn get_array_length(
        &self,
        var: &StateVariable,
        snapshot: &StorageSnapshot,
    ) -> Result<usize, ValidationError> {
        assert!(Self::is_any_array(&var.var_type));
        assert!(var.offset == 0);
        let var_type = &self.types[&var.var_type];
        if var_type.encoding == "dynamic_array" {
            // Get slot
            let slot_val: [u8; 32] = snapshot.get_full_slot(&var.slot);
            // Assume that array size is in last 8 bytes
            let arr_size: [u8; 8] = slot_val[24..]
                .try_into()
                .expect("24 + 8 is not 32. Something is very wrong.");
            let arr_usize: usize = usize::from_be_bytes(arr_size);
            // Check that the other bytes are empty
            assert_eq!(
                slot_val[..24],
                vec![0u8; 24],
                "Array with enormous size detected. This is not supported."
            );
            return Ok(arr_usize);
        }
        // For static label looks like uint128[6]
        let start = var_type.label.rfind('[').unwrap() + 1; // add 1 to skip '['
        let end = var_type.label.rfind(']').unwrap();
        Ok(var_type.label.get(start..end).unwrap().parse::<usize>()?)
    }

    fn get_members(&self, var_type: &String) -> Vec<StateVariable> {
        self.types[var_type].members.clone().unwrap_or_default()
    }

    fn get_critical_variable(
        &self,
        state_variable: &StateVariable,
        snapshot: &mut StorageSnapshot,
        table: &mut Table,
    ) -> Result<Vec<DVFStorageEntry>, ValidationError> {
        if Self::is_basic_type(&state_variable.var_type)
            || Self::is_user_defined_type(&state_variable.var_type)
        {
            let value = snapshot.get_slot_and_mark(
                &state_variable.slot,
                state_variable.offset,
                self.get_number_of_bytes(&state_variable.var_type),
            );
            let mut entry = DVFStorageEntry {
                slot: state_variable.slot,
                offset: state_variable.offset,
                var_name: state_variable.label.clone(),
                var_type: state_variable.normalized_var_type(),
                value: value.clone(),
                value_hint: None,
                comparison_operator: DVFStorageComparisonOperator::Equal,
            };
            if !entry.is_zero() {
                Self::add_to_table(&entry, table);
                if !Self::is_user_defined_type(&state_variable.var_type) {
                    self.pretty_printer.add_decoded_to_table_from_bytes(
                        &state_variable.var_type,
                        &value,
                        table,
                    );
                    let short_val = self.pretty_printer.pretty_value_short_from_bytes(
                        &state_variable.var_type,
                        &value,
                        true,
                    );
                    if !short_val.is_empty() {
                        entry.value_hint = Some(short_val);
                    }
                }
            }

            return Ok(vec![entry]);
        }
        if Self::is_struct(&state_variable.var_type) {
            let mut critical_storage_variables = Vec::<DVFStorageEntry>::new();
            for member in self.get_members(&state_variable.var_type) {
                // Compute the adjusted values based on the starting point of the struct
                let adjusted_member = StateVariable {
                    contract: member.contract,
                    label: format!("{}.{}", state_variable.label, member.label),
                    offset: member.offset,
                    slot: state_variable.slot.add(member.slot),
                    var_type: member.var_type,
                };
                critical_storage_variables.extend(self.get_critical_variable(
                    &adjusted_member,
                    snapshot,
                    table,
                )?);
            }
            return Ok(critical_storage_variables);
        }

        if Self::is_any_array(&state_variable.var_type) {
            let mut critical_storage_variables = Vec::<DVFStorageEntry>::new();
            let num: usize = self.get_array_length(state_variable, snapshot)?;
            let base_num_bytes: usize = self.get_base_num_bytes(&state_variable.var_type);
            let mut current_offset = state_variable.offset;
            // Add length field
            if self.is_dynamic_array(&state_variable.var_type) {
                let length_var = StateVariable {
                    contract: state_variable.contract.clone(),
                    label: format!("{}.length", state_variable.label),
                    offset: state_variable.offset,
                    slot: state_variable.slot,
                    var_type: String::from("t_uint256"),
                };
                critical_storage_variables.extend(self.get_critical_variable(
                    &length_var,
                    snapshot,
                    table,
                )?);
            }
            let mut current_slot = match self.is_dynamic_array(&state_variable.var_type) {
                true => U256::from_be_slice(hash_u256(&state_variable.slot).as_slice()),
                false => state_variable.slot,
            };
            for i in 0..num {
                let base = StateVariable {
                    contract: state_variable.contract.clone(),
                    label: format!("{}[{}]", state_variable.label, i),
                    offset: current_offset,
                    slot: current_slot,
                    var_type: self.get_base_type(&state_variable.var_type),
                };
                critical_storage_variables
                    .extend(self.get_critical_variable(&base, snapshot, table)?);
                // Check if we need to skip multiple slots
                if base_num_bytes > 32 {
                    current_slot =
                        current_slot.add(U256::from((current_offset + base_num_bytes + 31) / 32));
                    current_offset = 0;
                // Check if we need to skip one slot
                } else if current_offset + base_num_bytes + base_num_bytes > 32 {
                    current_slot = current_slot.add(U256::from(1));
                    current_offset = 0;
                } else {
                    current_offset += base_num_bytes;
                }
            }
            return Ok(critical_storage_variables);
        }
        if Self::is_mapping(&state_variable.var_type) {
            if !self.mapping_usages.contains_key(&state_variable.slot) {
                debug!("No mapping keys for {}", state_variable.slot);
                return Ok(vec![]);
            }
            let mut critical_storage_variables = Vec::<DVFStorageEntry>::new();

            let mut sorted_keys: Vec<_> = self.mapping_usages[&state_variable.slot]
                .clone()
                .into_iter()
                .collect();
            sorted_keys.sort();
            for (sorted_key, target_slot) in &sorted_keys {
                let key_type = self.get_key_type(&state_variable.var_type);
                let pretty_key: String = match self.has_inplace_encoding(&key_type) {
                    true => self
                        .pretty_printer
                        .pretty_value_short(&key_type, sorted_key, false),
                    false => {
                        if Self::is_string(&key_type) {
                            String::from_utf8(hex::decode(sorted_key).unwrap()).unwrap()
                        } else if Self::is_variable_bytes(&key_type) {
                            format!("0x{}", sorted_key.trim_start_matches("0x"))
                        } else {
                            debug!("Unknown mapping key type: {key_type}");
                            format!("0x{}", sorted_key.trim_start_matches("0x"))
                        }
                    }
                };

                let label = format!("{}[{}]", state_variable.label, pretty_key);

                let base = StateVariable {
                    contract: state_variable.contract.clone(),
                    label,
                    offset: 0,
                    slot: *target_slot,
                    var_type: self.get_value_type(&state_variable.var_type),
                };
                critical_storage_variables
                    .extend(self.get_critical_variable(&base, snapshot, table)?);
            }
            return Ok(critical_storage_variables);
        }
        if Self::is_string(&state_variable.var_type)
            || Self::is_variable_bytes(&state_variable.var_type)
        {
            assert!(state_variable.offset == 0);
            let mut string_length =
                snapshot.get_u8_from_slot(&state_variable.slot, state_variable.offset);
            // Assume that strings get a fresh slot
            assert!(state_variable.offset == 0);
            if string_length % 2 == 0 {
                // Decode as inline

                // Actual length
                string_length /= 2;
                let raw_string = snapshot.get_slot(
                    &state_variable.slot,
                    (32 - string_length).into(),
                    string_length.into(),
                );
                let mut full_string = String::new();
                if Self::is_string(&state_variable.var_type) {
                    full_string = String::from_utf8(raw_string).unwrap();
                } else if Self::is_variable_bytes(&state_variable.var_type) {
                    full_string = hex::encode(raw_string);
                }
                let value = snapshot.get_slot_and_mark(&state_variable.slot, 0, 32);

                let entry = DVFStorageEntry {
                    slot: state_variable.slot,
                    offset: 0,
                    var_name: format!("{} (length={})", state_variable.label, string_length),
                    var_type: state_variable.normalized_var_type(),
                    value: value.clone(),
                    value_hint: Some(full_string.clone()),
                    comparison_operator: DVFStorageComparisonOperator::Equal,
                };

                if string_length > 0 {
                    Self::add_to_table(&entry, table);
                    PrettyPrinter::add_formatted_to_table(
                        &format!(" [+] Decoded {}:", state_variable.label),
                        &full_string,
                        table,
                    );
                }
                return Ok(vec![entry]);
            } else {
                // Decode multiple slots
                let mut critical_storage_variables = Vec::<DVFStorageEntry>::new();
                // Decode length
                let length_var = StateVariable {
                    contract: state_variable.contract.clone(),
                    label: format!("{}.length", state_variable.label),
                    offset: state_variable.offset,
                    slot: state_variable.slot,
                    var_type: String::from("t_uint256"),
                };
                critical_storage_variables.extend(self.get_critical_variable(
                    &length_var,
                    snapshot,
                    table,
                )?);
                let mut string_length = U256::from_be_slice(&snapshot.get_slot(
                    &length_var.slot,
                    length_var.offset,
                    32,
                ));
                // We skip the -1 as we round down anyway
                string_length /= U256::from_limbs([2, 0, 0, 0]);
                let mut string_index = U256::ZERO;
                let mut current_slot =
                    U256::from_be_slice(hash_u256(&state_variable.slot).as_slice());
                let mut raw_string: Vec<u8> = vec![];
                let u256_32 = U256::from_limbs([32, 0, 0, 0]);
                loop {
                    let value_length = cmp::min(string_length.as_limbs()[0] as usize, 32); //@note take the least significant limbs
                    let value =
                        snapshot.get_slot_and_mark(&current_slot, 32 - value_length, value_length);
                    raw_string.extend_from_slice(&value);
                    let entry = DVFStorageEntry {
                        slot: current_slot,
                        offset: 32 - value_length,
                        var_name: format!("{}[part_{}]", state_variable.label, string_index),
                        var_type: state_variable.normalized_var_type(),
                        value: value.clone(),
                        value_hint: None,
                        comparison_operator: DVFStorageComparisonOperator::Equal,
                    };
                    Self::add_to_table(&entry, table);
                    critical_storage_variables.push(entry);

                    if string_length <= u256_32 {
                        break;
                    }
                    string_length -= u256_32;
                    string_index += U256::from(1);
                    current_slot += U256::from(1);
                }
                let mut full_string = String::new();
                if Self::is_string(&state_variable.var_type) {
                    full_string = String::from_utf8(raw_string).unwrap();
                    // Skip first because it is the length
                    for i in 1..critical_storage_variables.len() {
                        let end_of_slice = cmp::min(i * 32, full_string.len());
                        let slice = full_string[(i - 1) * 32..end_of_slice].to_string();
                        critical_storage_variables[i].value_hint = Some(slice);
                        if i * 32 >= full_string.len() {
                            break;
                        }
                    }
                } else if Self::is_variable_bytes(&state_variable.var_type) {
                    full_string = hex::encode(raw_string);
                }
                PrettyPrinter::add_formatted_to_table(
                    &format!(" [+] Decoded {}:", state_variable.label),
                    &full_string,
                    table,
                );
                return Ok(critical_storage_variables);
            }
        }
        panic!(
            "Unknown solidity type: {state_variable:?}, {:?}",
            self.types[&state_variable.var_type]
        );
    }

    pub fn is_uint(var_type: &str) -> bool {
        var_type.starts_with("t_uint") && !var_type.contains("[]")
    }

    pub fn is_address(var_type: &str) -> bool {
        (var_type.starts_with("t_address") || var_type.starts_with("t_contract"))
            && !var_type.contains("[]")
    }

    pub fn is_int(var_type: &str) -> bool {
        var_type.starts_with("t_int") && !var_type.contains("[]")
    }

    pub fn is_bool(var_type: &str) -> bool {
        var_type.starts_with("t_bool") && !var_type.contains("[]")
    }

    pub fn is_fixed_bytes(var_type: &str) -> bool {
        var_type.starts_with("t_bytes")
            && var_type.chars().last().unwrap().is_ascii_digit()
            && !var_type.contains("[]")
    }

    pub fn is_basic_type(var_type: &str) -> bool {
        Self::is_bool(var_type)
            || Self::is_int(var_type)
            || Self::is_uint(var_type)
            || Self::is_enum(var_type)
            || Self::is_address(var_type)
            || Self::is_fixed_bytes(var_type)
    }

    pub fn is_any_array(var_type: &str) -> bool {
        var_type.starts_with("t_array")
    }

    pub fn is_dynamic_array(&self, var_type: &str) -> bool {
        var_type.starts_with("t_array") && self.types[var_type].encoding == "dynamic_array"
    }

    pub fn has_inplace_encoding(&self, var_type: &str) -> bool {
        self.types[var_type].encoding == "inplace"
    }

    pub fn is_struct(var_type: &str) -> bool {
        var_type.starts_with("t_struct")
    }

    pub fn is_enum(var_type: &str) -> bool {
        var_type.starts_with("t_enum")
    }

    pub fn is_string(var_type: &str) -> bool {
        var_type.starts_with("t_string")
    }

    pub fn is_mapping(var_type: &str) -> bool {
        var_type.starts_with("t_mapping")
    }

    pub fn is_variable_bytes(var_type: &str) -> bool {
        var_type.starts_with("t_bytes") && !var_type.chars().last().unwrap().is_ascii_digit()
    }

    pub fn is_user_defined_type(var_type: &str) -> bool {
        var_type.starts_with("t_userDefinedValueType")
    }
}
