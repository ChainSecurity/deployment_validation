use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::process::Command;
use std::str::FromStr;
use tempfile::TempDir;

use alloy::primitives::U256;
use serde::de::{self, Deserializer, Visitor};
use serde::Deserialize;
use tracing::{debug, info};

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct StateVariable {
    pub contract: String, // TODO: remove if not used anywhere
    pub label: String,
    pub offset: usize,
    #[serde(deserialize_with = "deserialize_dec_u256")]
    pub slot: U256,
    #[serde(rename = "type")]
    pub var_type: String,
}

impl StateVariable {
    pub fn normalized_var_type(&self) -> Option<String> {
        let mut var_type = self.var_type.clone();
        if var_type.starts_with("t_enum") {
            var_type = String::from("t_uint8");
        } else if var_type.starts_with("t_contract") {
            var_type = String::from("t_address");
        } else if var_type.starts_with("t_userDefinedValueType") {
            let re = regex::Regex::new(r"t_userDefinedValueType(\$_|\()(.*)(_\$|\))").unwrap();
            //let mut results = vec![];
            let Some(caps) = re.captures(&var_type) else {
                panic!("Failed to extract user defined type: {}", var_type);
            };
            var_type = caps[2].to_string();
        }
        match var_type.as_str() {
            "" => None,
            other => Some(other.to_string()),
        }
    }
}

fn deserialize_dec_usize<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: Deserializer<'de>,
{
    struct USizeVisitor;

    impl Visitor<'_> for USizeVisitor {
        type Value = usize;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a decimal string")
        }

        fn visit_str<E>(self, v: &str) -> Result<usize, E>
        where
            E: de::Error,
        {
            Ok(usize::from_str(v).unwrap())
        }
    }
    deserializer.deserialize_string(USizeVisitor)
}

fn deserialize_dec_u256<'de, D>(deserializer: D) -> Result<U256, D::Error>
where
    D: Deserializer<'de>,
{
    struct U256Visitor;

    impl Visitor<'_> for U256Visitor {
        type Value = U256;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a decimal string")
        }

        fn visit_str<E>(self, v: &str) -> Result<U256, E>
        where
            E: de::Error,
        {
            Ok(U256::from_str_radix(v, 10).unwrap())
        }
    }
    deserializer.deserialize_string(U256Visitor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_state_var() {
        let serialized = "{\"contract\":\"C\",\"label\":\"lab\",\"offset\":42,\"slot\":\"12\",\"type\":\"uint\"}";

        let s: StateVariable = serde_json::from_str(serialized).unwrap();

        assert_eq!(U256::from(12), s.slot);
    }
}

impl StateVariable {}

// Represents information about one type
#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct TypeDescription {
    // inplace or else
    pub encoding: String,
    pub label: String,
    // Number of bytes of base type
    #[serde(rename = "numberOfBytes", deserialize_with = "deserialize_dec_usize")]
    pub number_of_bytes: usize,
    // Type of the base in case this is an array
    pub base: Option<String>,
    // Type of the key in case this is a mapping
    pub key: Option<String>,
    // Type of the value in case this is a mapping
    pub value: Option<String>,
    // Struct members
    pub members: Option<Vec<StateVariable>>,
}

#[derive(Deserialize, Debug, Default)]
pub struct ForgeInspect {
    pub storage: Vec<StateVariable>,
    pub types: HashMap<String, TypeDescription>,
}

impl ForgeInspect {
    pub fn default_values() -> Self {
        let storage: Vec<StateVariable> = vec![];
        let mut types: HashMap<String, TypeDescription> = HashMap::new();
        // Needed because of length fields
        let uint256 = TypeDescription {
            encoding: String::from("inplace"),
            label: String::from("uint256"),
            number_of_bytes: 32,
            base: None,
            key: None,
            value: None,
            members: None,
        };
        types.insert(String::from("t_uint256"), uint256);

        ForgeInspect { storage, types }
    }

    pub fn generate_and_parse_layout(
        project_path: &Path,
        contract_name: &str,
        contract_path: Option<String>,
    ) -> Self {
        // Create a temporary directory
        let temp_dir = TempDir::new().unwrap();
        // Get the path of the temporary directory
        let temp_path = temp_dir.path();

        // get temp path for cache dir so that this does not overwrite hardhat configs
        let temp_cache_dir = TempDir::new().unwrap();
        let temp_cache_path = temp_cache_dir.path();

        info!("Running forge inspect. This might take a while.");
        // hardhat doesn't offer a simple solutipon to get the storage layout
        // but if we pass the full path of a contract, we can still use
        // forge inspect.
        // TODO: If a future version of solidity should ever change the storage
        // layout based on configuration, we might have to revise this.
        let mut contract = contract_name.to_string();
        if let Some(path) = contract_path {
            contract = format!("{}:{}", path, contract_name);
        }
        let forge_inspect = Command::new("forge")
            .current_dir(project_path)
            .arg("inspect")
            .arg("--force")
            .arg("--json")
            .arg("--root") // required because forge will use Git root (not necessarily project root) by default
            .arg(".")
            .arg("--out")
            .arg(temp_path.as_os_str())
            .arg("--cache-path")
            .arg(temp_cache_path.as_os_str())
            .arg(contract)
            .arg("storage-layout")
            .output()
            .expect("Could not create storage layout");

        assert!(
            forge_inspect.status.success(),
            "Failed to run forge inspect:\n{}",
            String::from_utf8_lossy(&forge_inspect.stderr)
        );

        let layout = String::from_utf8(forge_inspect.stdout).unwrap();
        debug!("{}", layout);
        debug!("Parsed forge inspect output.");

        serde_json::from_str::<ForgeInspect>(&layout).unwrap()
    }

    pub fn get_size_for_type(&self, var_type: &String) -> usize {
        self.types[var_type].number_of_bytes
    }
}
