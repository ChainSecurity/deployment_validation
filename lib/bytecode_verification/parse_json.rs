use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use alloy::json_abi::Constructor;
use clap::ValueEnum;
use semver::Version;
use serde_json::Value;
use std::path::Path;
use std::process::Command;
use tempfile::Builder;
use tempfile::TempDir;
use tracing::{debug, info};

use crate::bytecode_verification::types::Types;
use crate::dvf::parse::ValidationError;
use crate::state::forge_inspect::StateVariable;
use crate::state::forge_inspect::TypeDescription;
use crate::types::ConstructorArg;
use crate::types::Immutable;
use colored::Colorize;
use std::str::FromStr;

use alloy::json_abi::Event;
use alloy::primitives::U256;
use foundry_compilers::artifacts::Error as CompilerError;
use foundry_compilers::artifacts::{
    BytecodeHash, BytecodeObject, Contract as ContractArt, DeployedBytecode, Node as EAstNode,
    NodeType, SolcInput, SourceFile,
};
use foundry_compilers::buildinfo::BuildInfo as BInfo;
use foundry_compilers::CompilerOutput;

type BuildInfo = BInfo<SolcInput, CompilerOutput<CompilerError, ContractArt>>;

struct TmpVariableDeclaration {
    name: String,
    type_string: String,
}

#[derive(Debug)]
pub struct ProjectInfo {
    pub compiled_bytecode: String,
    pub init_code: String,
    pub compiler_version: Version,
    pub optimization_enabled: bool,
    pub optimization_runs: usize,
    pub cbor_metadata: Option<BytecodeHash>,
    pub immutables: Vec<Immutable>,
    pub constructor_args: Vec<ConstructorArg>,
    pub constructor: Option<Constructor>,
    pub events: Vec<Event>,
    pub other_bytecodes: Vec<String>,
    pub storage: Vec<StateVariable>,
    pub types: HashMap<String, TypeDescription>,
    pub absolute_path: Option<String>,
}

impl ProjectInfo {
    fn check_forge() -> bool {
        Command::new("forge").arg("--version").output().is_ok()
    }

    fn check_hardhat(project: &Path) -> bool {
        Command::new("npx")
            .current_dir(project)
            .arg("hardhat --version")
            .output()
            .is_ok()
    }

    // build it
    fn forge_build(project: &Path, build_info_path: &Path) -> Result<(), ValidationError> {
        info!(
            "Starting <forge build>. If you had previous builds, it is recommended to <forge clean>."
        );
        let build = Command::new("forge")
            .current_dir(project)
            .arg("build")
            .arg("--build-info")
            .arg("--build-info-path")
            .arg(build_info_path.to_str().unwrap())
            .output()
            .expect("Could not build project");

        if !build.status.success() {
            println!(
                "{} {}",
                "Stdout of <forge build>:".yellow(),
                String::from_utf8(build.stdout).unwrap()
            );
            println!(
                "{}: {}",
                "Stderr of <forge build>".yellow(),
                String::from_utf8(build.stderr).unwrap()
            );
            return Err(ValidationError::from("Failed to run <forge build>"));
        }
        debug!("Finished forge build.");
        Ok(())
    }

    fn hardhat_compile(project: &Path) -> Result<(), ValidationError> {
        info!(
            "Starting <npx hardhat compile>. If you had previous builds, it is recommended to <npx hardhat clean>."
        );
        let build = Command::new("npx")
            .current_dir(project)
            .arg("hardhat")
            .arg("compile")
            .output()
            .expect("Could not build project");

        if !build.status.success() {
            println!(
                "{} {}",
                "Stdout of <npx hardhat compile>:".yellow(),
                String::from_utf8(build.stdout).unwrap()
            );
            println!(
                "{}: {}",
                "Stderr of <npx hardhat compile>".yellow(),
                String::from_utf8(build.stderr).unwrap()
            );
            return Err(ValidationError::from("Failed to run <npx hardhat compile>"));
        }
        debug!("Finished <npx hardhat compile>.");
        Ok(())
    }

    // Recursively find VariableDeclaration nodes in Ast
    fn find_var_defs(node: &EAstNode, id_to_ast: &mut HashMap<usize, TmpVariableDeclaration>) {
        if node.node_type == NodeType::VariableDeclaration && node.id.is_some() {
            id_to_ast.insert(
                node.id.unwrap(),
                TmpVariableDeclaration {
                    name: node.other["name"].as_str().unwrap().to_string(),
                    type_string: node.other["typeDescriptions"]["typeString"]
                        .as_str()
                        .unwrap()
                        .to_string(),
                },
            );
        }

        if let Some(body_node) = &node.body {
            Self::find_var_defs(body_node, id_to_ast);
        }
        for subnode in &node.nodes {
            Self::find_var_defs(subnode, id_to_ast);
        }
    }

    fn extract_bytecode_as_string(
        compiled_bytecode: Option<&BytecodeObject>,
    ) -> Result<String, ValidationError> {
        if compiled_bytecode.is_none() {
            return Err(ValidationError::from("No bytecode found in build output."));
        }

        let compiled_bytecode_str = match compiled_bytecode.unwrap() {
            BytecodeObject::Bytecode(b) => hex::encode(b.clone().0),
            BytecodeObject::Unlinked(s) => s.clone(),
        };

        if compiled_bytecode.unwrap().is_unlinked() {
            panic!("Warning: Unlinked bytecode currently not supported!");
        }
        Ok(compiled_bytecode_str)
    }

    /// Extracts the type definitions of a given AST node (type_name).
    fn find_storage_struct_types(
        sources: &BTreeMap<PathBuf, SourceFile>,
        type_defs: &Types,
        type_name: &Value,
        types: &mut HashMap<String, TypeDescription>,
    ) {
        if type_name["nodeType"] == "ElementaryTypeName" {
            let mut encoding = String::from("inplace");
            if type_name["typeDescriptions"]["typeString"] == "string"
                || type_name["typeDescriptions"]["typeString"] == "bytes"
            {
                encoding = String::from("bytes");
            }
            let identifier = type_name["typeDescriptions"]["typeIdentifier"]
                .as_str()
                .unwrap()
                .to_string();
            types.insert(
                identifier.clone(),
                TypeDescription {
                    encoding,
                    label: type_name["typeDescriptions"]["typeString"]
                        .as_str()
                        .unwrap()
                        .to_string(),
                    number_of_bytes: type_defs.get_number_of_bytes(&identifier),
                    base: None,
                    key: None,
                    value: None,
                    members: None,
                },
            );
        } else if type_name["nodeType"] == "Mapping" {
            // add mapping type
            let identifier = type_name["typeDescriptions"]["typeIdentifier"]
                .as_str()
                .unwrap()
                .to_string();
            types.insert(
                identifier.clone(),
                TypeDescription {
                    encoding: String::from("mapping"),
                    label: type_name["typeDescriptions"]["typeString"]
                        .as_str()
                        .unwrap()
                        .to_string(),
                    number_of_bytes: 32,
                    base: None,
                    key: Some(
                        type_name["keyType"]["typeDescriptions"]["typeIdentifier"]
                            .as_str()
                            .unwrap()
                            .to_string(),
                    ),
                    value: Some(
                        type_name["valueType"]["typeDescriptions"]["typeIdentifier"]
                            .as_str()
                            .unwrap()
                            .to_string(),
                    ),
                    members: None,
                },
            );
            // add key type
            let identifier = type_name["keyType"]["typeDescriptions"]["typeIdentifier"]
                .as_str()
                .unwrap()
                .to_string();
            types.insert(
                identifier.clone(),
                TypeDescription {
                    encoding: String::from("inplace"),
                    label: type_name["keyType"]["typeDescriptions"]["typeString"]
                        .as_str()
                        .unwrap()
                        .to_string(),
                    number_of_bytes: type_defs.get_number_of_bytes(&identifier),
                    base: None,
                    key: None,
                    value: None,
                    members: None,
                },
            );
            // recursively add value types
            Self::find_storage_struct_types(sources, type_defs, &type_name["valueType"], types);
        } else if type_name["nodeType"] == "ArrayTypeName" {
            let base_identifier = type_name["baseType"]["typeDescriptions"]["typeIdentifier"]
                .as_str()
                .unwrap()
                .to_string();
            let mut encoding = String::from("dynamic_array");
            let mut number_of_bytes = 32;
            if type_name.get("length").is_some() {
                let length: usize = type_name["length"]
                    .get("value")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string()
                    .parse()
                    .unwrap();
                number_of_bytes =
                    (length * type_defs.get_number_of_bytes(&base_identifier)).div_ceil(32) * 32;
                encoding = String::from("inplace");
            }
            // add array type
            let identifier = type_name["typeDescriptions"]["typeIdentifier"]
                .as_str()
                .unwrap()
                .to_string();
            types.insert(
                identifier.clone(),
                TypeDescription {
                    encoding,
                    label: type_name["typeDescriptions"]["typeString"]
                        .as_str()
                        .unwrap()
                        .to_string(),
                    number_of_bytes,
                    base: Some(
                        type_name["baseType"]["typeDescriptions"]["typeIdentifier"]
                            .as_str()
                            .unwrap()
                            .to_string(),
                    ),
                    key: None,
                    value: None,
                    members: None,
                },
            );
            // add base type
            types.insert(
                base_identifier.clone(),
                TypeDescription {
                    encoding: String::from("inplace"),
                    label: type_name["baseType"]["typeDescriptions"]["typeString"]
                        .as_str()
                        .unwrap()
                        .to_string(),
                    number_of_bytes: type_defs.get_number_of_bytes(&base_identifier),
                    base: None,
                    key: None,
                    value: None,
                    members: None,
                },
            );
        } else if type_name["nodeType"] == "UserDefinedTypeName" {
            // go deeper to extract inner structs
            let identifier = type_name["typeDescriptions"]["typeIdentifier"]
                .as_str()
                .unwrap()
                .to_string();
            if identifier.starts_with("t_struct") {
                let struct_slots: Vec<(u64, U256, Option<String>)> = vec![(
                    type_name
                        .get("referencedDeclaration")
                        .unwrap()
                        .as_u64()
                        .unwrap(),
                    U256::from_str("0x0").unwrap(), // this won't be used as we only have to add the types
                    None,
                )];
                let mut storage: Vec<StateVariable> = vec![]; // this won't be used as we only have to add the types
                for source in sources.values() {
                    if let Some(ast) = source.ast.clone() {
                        for top_node in &ast.nodes {
                            Self::find_storage_struct_data(
                                sources,
                                top_node,
                                type_defs,
                                &struct_slots,
                                types,
                                &mut storage,
                            );
                        }
                    }
                }
            } else if identifier.starts_with("t_userDefinedValueType") {
                let mut var_type = String::new();
                for source in sources.values() {
                    if let Some(ast) = source.ast.clone() {
                        for top_node in &ast.nodes {
                            Self::find_storage_struct_user_defined_type(
                                top_node,
                                type_name["referencedDeclaration"].as_u64().unwrap(),
                                &mut var_type,
                            );
                        }
                    }
                }
                types.insert(
                    identifier.clone(),
                    TypeDescription {
                        encoding: String::from("inplace"),
                        label: type_name["typeDescriptions"]["typeString"]
                            .as_str()
                            .unwrap()
                            .to_string(),
                        number_of_bytes: type_defs.get_number_of_bytes(&var_type),
                        base: None,
                        key: None,
                        value: None,
                        members: None,
                    },
                );
            } else {
                types.insert(
                    identifier.clone(),
                    TypeDescription {
                        encoding: String::from("inplace"),
                        label: type_name["typeDescriptions"]["typeString"]
                            .as_str()
                            .unwrap()
                            .to_string(),
                        number_of_bytes: type_defs.get_number_of_bytes(&identifier),
                        base: None,
                        key: None,
                        value: None,
                        members: None,
                    },
                );
            }
        }
    }

    /// Gets the underlying type of a user-defined type from a contract's AST.
    fn find_storage_struct_user_defined_type(node: &EAstNode, type_id: u64, var_type: &mut String) {
        if node.node_type == NodeType::UserDefinedValueTypeDefinition
            && node.id.is_some()
            && node.other.contains_key("underlyingType")
        {
            let node_id = node.id.unwrap() as u64;
            if node_id == type_id {
                var_type.push_str(
                    node.other["underlyingType"]["typeDescriptions"]["typeIdentifier"]
                        .as_str()
                        .unwrap(),
                );
                return;
            }
        }
        for subnode in &node.nodes {
            Self::find_storage_struct_user_defined_type(subnode, type_id, var_type);
        }
    }

    /// Checks, whether a given type definition describes a value type.
    fn is_value_type(var_type: &str) -> bool {
        if var_type.starts_with("t_uint")
            || var_type.starts_with("t_int")
            || var_type.starts_with("t_contract")
            || var_type.starts_with("t_address")
            || var_type.starts_with("t_bool")
            || var_type.starts_with("t_enum")
            || (var_type.starts_with("t_bytes") && !var_type.contains("storage"))
        {
            return true;
        }
        false
    }

    /// Parses the AST of a contract for struct definitions of a certain set of struct AST IDs.
    /// Creates a set of StorageVariables and TypeDescriptions describing the structs.
    fn find_storage_struct_data(
        sources: &BTreeMap<PathBuf, SourceFile>,
        node: &EAstNode,
        type_defs: &Types,
        struct_slots: &Vec<(u64, U256, Option<String>)>,
        types: &mut HashMap<String, TypeDescription>,
        storage: &mut Vec<StateVariable>,
    ) {
        if node.node_type == NodeType::StructDefinition && node.id.is_some() {
            let mut storage_var_id: Option<usize> = None;
            // parse all struct definitions for each struct -> slot pair.
            for (struct_id, slot, name) in struct_slots {
                let struct_id = *struct_id;
                let node_id = node.id.unwrap() as u64;
                if node_id == struct_id {
                    let struct_name: String;
                    // add variable name of storage location if possible
                    if name.is_some() && node.other.contains_key("canonicalName") {
                        let parts: Vec<String> = node.other["canonicalName"]
                            .as_str()
                            .unwrap()
                            .split('.')
                            .map(str::to_string)
                            .collect();
                        // try to move the contract name to first position.
                        // canonicalName = ContractName.StructName.
                        // we want: ContractName.SlotVariableName.StructName.
                        if parts.len() > 1 {
                            struct_name = format!(
                                "{}.{}.{}",
                                parts[0],
                                name.clone().unwrap(),
                                parts[1..].join(".")
                            );
                        } else {
                            struct_name = format!("{}.{}", parts[0], name.clone().unwrap());
                        }
                    } else {
                        struct_name = node.other["canonicalName"].as_str().unwrap().to_string();
                    }
                    // multiple slots can refer to the same struct.
                    // if the struct has already been parsed before, just change the slot.
                    if storage_var_id.is_some() {
                        let mut storage_var = storage[storage_var_id.unwrap()].clone();
                        storage_var.slot = *slot;
                        storage_var.label = struct_name;
                        storage.push(storage_var);
                        continue;
                    }
                    // iterate over all members of a struct and create StateVariables for them.
                    let mut struct_members: Vec<StateVariable> = vec![];
                    if let Some(members) = node.other.get("members") {
                        let mut slots: usize = 0;
                        let mut current_offset: usize = 0;
                        for member in members.as_array().unwrap().iter() {
                            let var_type = member["typeDescriptions"]["typeIdentifier"]
                                .as_str()
                                .unwrap()
                                .to_string();
                            Self::find_storage_struct_types(
                                sources,
                                type_defs,
                                &member["typeName"],
                                types,
                            );
                            let t = &types[&var_type];
                            let number_of_bytes = t.number_of_bytes;

                            // compute the slot and offset inside the struct.
                            if Self::is_value_type(&var_type) {
                                // value types start a new slot if they do not fit in the
                                // remaining slot space.
                                // value types do not occupy more than 32 bytes.
                                if current_offset + number_of_bytes > 32 {
                                    current_offset = 0;
                                    slots += 1;
                                }
                            } else {
                                // arrays, structs, mappings always start a new slot if
                                // the current slot is not empty.
                                if current_offset != 0 {
                                    current_offset = 0;
                                    slots += 1;
                                }
                            }

                            struct_members.push(StateVariable {
                                contract: String::from(""),
                                label: member["name"].as_str().unwrap().to_string(),
                                offset: current_offset,
                                slot: U256::from(slots),
                                var_type: var_type.clone(),
                            });

                            if Self::is_value_type(&var_type) {
                                // this cannot become bigger than 32 bytes as otherwise a new slot would have been started before
                                current_offset += number_of_bytes;
                            } else {
                                // after arrays, structs, mappings a new slot is started
                                current_offset = 0;
                                slots += number_of_bytes.div_ceil(32);
                            }
                        }
                        let struct_type = format!(
                            "t_struct$_{}_${}_storage_ptr",
                            node.other["name"].as_str().unwrap(),
                            struct_id
                        );
                        types.insert(
                            struct_type.clone(),
                            TypeDescription {
                                encoding: String::from("inplace"),
                                label: node.other["canonicalName"].as_str().unwrap().to_string(),
                                number_of_bytes: (slots + 1) * 32,
                                base: None,
                                key: None,
                                value: None,
                                members: Some(struct_members),
                            },
                        );
                        storage.push(StateVariable {
                            contract: String::from(""),
                            label: struct_name,
                            offset: 0,
                            slot: *slot,
                            var_type: struct_type,
                        });
                        storage_var_id = Some(storage.len() - 1);
                    }
                }
            }
        }
        for subnode in &node.nodes {
            Self::find_storage_struct_data(
                sources,
                subnode,
                type_defs,
                struct_slots,
                types,
                storage,
            );
        }
    }

    /// Parses the AST of a contract for structs that are used in storage but not defined
    /// as storage variables (i.e., assembly storage writes). This is required because the
    /// Solidity compiler does not create a storage layout for variables that are not
    /// explicitly defined as storage variables.
    /// Creates a set of StorageVariables and TypeDescriptions that can be used by ContractState.
    fn find_storage_structs(
        sources: &BTreeMap<PathBuf, SourceFile>,
        type_defs: &Types,
        exported_ids: &Vec<usize>,
        storage: &mut Vec<StateVariable>,
        types: &mut HashMap<String, TypeDescription>,
    ) {
        // Tuple: (struct AST ID, slot, name of variable containing the slot)
        let mut struct_slots: Vec<(u64, U256, Option<String>)> = vec![];
        // find pairs (storage slot => struct AST ID)
        for source in sources.values() {
            if let Some(ast) = source.ast.clone() {
                for node in &ast.nodes {
                    Self::find_storage_struct_slots(sources, node, exported_ids, &mut struct_slots);
                }
            }
        }
        // parse the struct members + types
        for source in sources.values() {
            if let Some(ast) = source.ast.clone() {
                for node in &ast.nodes {
                    Self::find_storage_struct_data(
                        sources,
                        node,
                        type_defs,
                        &struct_slots,
                        types,
                        storage,
                    );
                }
            }
        }
    }

    /// Parses the AST of a contract for any assignments of a storage slot to a struct
    /// storage pointer.
    /// Creates a set of tuples mapping struct AST IDs to the respective storage slots.
    fn find_storage_struct_slots(
        sources: &BTreeMap<PathBuf, SourceFile>,
        node: &EAstNode,
        exported_ids: &Vec<usize>,
        struct_slots: &mut Vec<(u64, U256, Option<String>)>,
    ) {
        if node.node_type == NodeType::ContractDefinition
            && node.id.is_some()
            && !exported_ids.contains(&node.id.unwrap())
        {
            return;
        }
        if node.node_type == NodeType::FunctionDefinition && node.id.is_some() {
            if let Some(body_node) = &node.body {
                if let Some(stmts) = body_node.other.get("statements") {
                    for stmt in stmts.as_array().unwrap().iter() {
                        if stmt["nodeType"] != "InlineAssembly" {
                            continue;
                        }
                        // search for any assignments in assembly
                        if let Some(yul_stmts) = stmt["AST"].get("statements") {
                            for yul_stmt in yul_stmts.as_array().unwrap().iter() {
                                if yul_stmt["nodeType"] == "YulAssignment" {
                                    if let Some(variables) = yul_stmt.get("variableNames") {
                                        for variable in variables.as_array().unwrap().iter() {
                                            // specifically look for an assignment to the slot of a storage
                                            // pointer that is returned by the function.
                                            if variable["name"].to_string().contains(".slot")
                                                && node.other.contains_key("returnParameters")
                                            {
                                                if let Some(parameters) =
                                                    node.other["returnParameters"].get("parameters")
                                                {
                                                    for parameter in
                                                        parameters.as_array().unwrap().iter()
                                                    {
                                                        if parameter["storageLocation"] == "storage"
                                                        {
                                                            let struct_id = parameter["typeName"]
                                                                ["pathNode"]
                                                                ["referencedDeclaration"]
                                                                .as_u64()
                                                                .unwrap();
                                                            // if a variable is assigned to the slot, follow the
                                                            // path.
                                                            if yul_stmt["value"]["nodeType"]
                                                                == "YulIdentifier"
                                                            {
                                                                if let Some(stmt_refs) =
                                                                    stmt.get("externalReferences")
                                                                {
                                                                    for stmt_ref in stmt_refs
                                                                        .as_array()
                                                                        .unwrap()
                                                                        .iter()
                                                                    {
                                                                        if yul_stmt["value"]["src"]
                                                                            == stmt_ref["src"]
                                                                        {
                                                                            let mut parameter_defs: Vec<(u64, usize)> = vec![];
                                                                            // get the the slot from variable declaration.
                                                                            for source in
                                                                                sources.values()
                                                                            {
                                                                                if let Some(ast) =
                                                                                    source
                                                                                        .ast
                                                                                        .clone()
                                                                                {
                                                                                    for top_node in
                                                                                        &ast.nodes
                                                                                    {
                                                                                        if let Some((var_name, _, var_slot))
                                                                                            = Self::find_variable_declaration(
                                                                                                sources,
                                                                                                top_node,
                                                                                                stmt_ref["declaration"].as_u64().unwrap()
                                                                                            ) {
                                                                                                struct_slots.push((struct_id, var_slot, Some(var_name)));
                                                                                            // if no variable declaration can be found, try to find 
                                                                                            // functions with the variable as parameter.
                                                                                        } else if let Some((_, _, function_id, param_id))
                                                                                            = Self::find_parameter_declaration(
                                                                                                top_node,
                                                                                                stmt_ref["declaration"].as_u64().unwrap()
                                                                                            ) {
                                                                                            parameter_defs.push((function_id, param_id));
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                            // calls can happen in a different contract so we have to check
                                                                            // these separately
                                                                            for (
                                                                                function_id,
                                                                                param_id,
                                                                            ) in parameter_defs
                                                                            {
                                                                                for source in
                                                                                    sources.values()
                                                                                {
                                                                                    if let Some(
                                                                                        ast,
                                                                                    ) = source
                                                                                        .ast
                                                                                        .clone()
                                                                                    {
                                                                                        for top_node in
                                                                                            &ast.nodes
                                                                                        {
                                                                                            // find all calls of the given function and match the
                                                                                            // passed parameters with the variable.
                                                                                            let mut args: Vec<(String, Value)> = vec![];
                                                                                            Self::find_call_args(top_node, function_id, &mut args);
                                                                                            for (
                                                                                                outer_function,
                                                                                                arg,
                                                                                            ) in
                                                                                                args
                                                                                            {
                                                                                                let arg_array = arg.as_array().unwrap();
                                                                                                if arg_array.len() > param_id {
                                                                                                    // if a variable is passed, get the slot from the
                                                                                                    // associated variable declaration.
                                                                                                    if let Some(var_ref_id) = arg[param_id].get("referencedDeclaration") {
                                                                                                        for top_node in &ast.nodes {
                                                                                                            if let Some((var_name, _, var_slot))
                                                                                                                = Self::find_variable_declaration(
                                                                                                                    sources,
                                                                                                                    top_node,
                                                                                                                    var_ref_id.as_u64().unwrap()
                                                                                                                ) {
                                                                                                                    if !struct_slots.iter().any(|(_, slot, _)| slot.eq(&var_slot)) {
                                                                                                                        struct_slots.push((struct_id, var_slot, Some(var_name)));
                                                                                                                    }
                                                                                                            }
                                                                                                        }
                                                                                                    } else if let Some(slot_value) = arg[param_id].get("value") {
                                                                                                        // if a value is passed, use it as slot.
                                                                                                        // as we have no associated variable for the slot,
                                                                                                        // we use the name of the outer function.
                                                                                                        let var_slot = U256::from_str(slot_value.as_str().unwrap()).unwrap();
                                                                                                        if !struct_slots.iter().any(|(_, slot, _)| slot.eq(&var_slot)) {
                                                                                                            struct_slots.push(
                                                                                                                (
                                                                                                                    struct_id,
                                                                                                                    var_slot,
                                                                                                                    Some(format!("[{}]", outer_function))
                                                                                                                )
                                                                                                            );
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                                //
                                                            } else if yul_stmt["value"]["nodeType"]
                                                                == "YulLiteral"
                                                            {
                                                                // if a literal is assigned to the slot,
                                                                // we know the storage location.
                                                                if let Some(slot_value) =
                                                                    yul_stmt["value"].get("value")
                                                                {
                                                                    // only way to distinguish multiple structs
                                                                    // is the function name here.
                                                                    let function_name: Option<
                                                                        String,
                                                                    >;
                                                                    if let Some(fname) =
                                                                        node.other.get("name")
                                                                    {
                                                                        function_name =
                                                                            Some(format!(
                                                                                "[{}]",
                                                                                fname
                                                                                    .as_str()
                                                                                    .unwrap()
                                                                            ));
                                                                    } else {
                                                                        function_name = None;
                                                                    }
                                                                    struct_slots.push((
                                                                        struct_id,
                                                                        U256::from_str(
                                                                            slot_value
                                                                                .as_str()
                                                                                .unwrap(),
                                                                        )
                                                                        .unwrap(),
                                                                        function_name,
                                                                    ));
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        for subnode in &node.nodes {
            Self::find_storage_struct_slots(sources, subnode, exported_ids, struct_slots);
        }
    }

    /// Parses the AST of a contract for direct assembly SSTOREs to find descriptions
    /// (name and type) of storage slots that can not be extracted from the compiler
    /// output.
    /// Creates a set of StorageVariables and TypeDescriptions that can be used by ContractState.
    fn find_direct_storage_writes(
        sources: &BTreeMap<PathBuf, SourceFile>,
        type_defs: &Types,
        exported_ids: &Vec<usize>,
        storage: &mut Vec<StateVariable>,
        types: &mut HashMap<String, TypeDescription>,
    ) {
        for source in sources.values() {
            if let Some(ast) = source.ast.clone() {
                for node in &ast.nodes {
                    Self::find_direct_storage_write_variables(
                        sources,
                        node,
                        type_defs,
                        exported_ids,
                        storage,
                        types,
                    );
                }
            }
        }
    }

    /// Parses part of the AST of a contract to get the literal that a keccak256() call produces
    /// in a variable declaration.
    fn find_keccak_value(value: &Value, binary_op: Option<u64>) -> Option<U256> {
        if value["nodeType"] == "FunctionCall" && value["expression"]["name"] == "keccak256" {
            if let Some(arguments) = value.get("arguments") {
                if !arguments.as_array().unwrap().is_empty() {
                    let mut hex_wo_prefix = arguments[0]["typeDescriptions"]["typeIdentifier"]
                        .as_str()
                        .unwrap()
                        .replace("t_stringliteral_", "");
                    hex_wo_prefix.insert_str(0, "0x");
                    let mut slot = U256::from_str(hex_wo_prefix.as_str()).unwrap();
                    if let Some(binary_op) = binary_op {
                        slot -= U256::from(binary_op);
                    }
                    return Some(slot);
                }
            }
        }
        // support the common use case of subtracting some integer from the keccak value
        let op: Option<u64>;
        if binary_op.is_none() {
            if value["nodeType"] == "BinaryOperation"
                && value["rightExpression"].get("value").is_some()
            {
                if value["operator"] == "-" {
                    op = Some(
                        value["rightExpression"]["value"]
                            .as_str()
                            .unwrap()
                            .parse()
                            .unwrap(),
                    );
                } else {
                    op = None;
                }
            } else {
                op = None;
            }
        } else {
            op = binary_op;
        }
        if value.is_object() {
            for (_, sub_value) in value.as_object().unwrap() {
                let return_val = Self::find_keccak_value(sub_value, op);
                if return_val.is_some() {
                    return return_val;
                }
            }
        } else if value.is_array() {
            for sub_value in value.as_array().unwrap() {
                let return_val = Self::find_keccak_value(sub_value, op);
                if return_val.is_some() {
                    return return_val;
                }
            }
        }
        None
    }

    /// Parses the AST of a contract in order to follow the path of variable declarations
    /// until either a definition with an initial value is found. Finds global and local
    /// variables.
    /// Returns a tuple (variable name, variable type, variable value)
    fn find_variable_declaration(
        sources: &BTreeMap<PathBuf, SourceFile>,
        node: &EAstNode,
        id: u64,
    ) -> Option<(String, String, U256)> {
        if node.id.is_some() {
            // first check for direct variable declarations in the contract body
            if node.node_type == NodeType::VariableDeclaration {
                let node_id = node.id.unwrap() as u64;
                if node_id == id && node.other.contains_key("value") {
                    // return the value if it is set
                    if node.other["value"].get("value").is_some() {
                        return Some((
                            node.other["name"].as_str().unwrap().to_string(),
                            node.other["typeDescriptions"]["typeIdentifier"]
                                .as_str()
                                .unwrap()
                                .to_string(),
                            U256::from_str(node.other["value"]["value"].as_str().unwrap()).unwrap(),
                        ));
                    } else if let Some(slot) =
                        Self::find_keccak_value(node.other.get("value").unwrap(), None)
                    {
                        // try to get the value if it is set via a keccak256() call
                        return Some((
                            node.other["name"].as_str().unwrap().to_string(),
                            node.other["typeDescriptions"]["typeIdentifier"]
                                .as_str()
                                .unwrap()
                                .to_string(),
                            slot,
                        ));
                    }
                }
            } else if node.node_type == NodeType::FunctionDefinition {
                // if the ID cannot be found in a variable declaration, it must have been declared in a function.
                if let Some(body_node) = &node.body {
                    // check variable declarations in the function body.
                    if let Some(stmts) = body_node.other.get("statements") {
                        for stmt in stmts.as_array().unwrap().iter() {
                            if stmt["nodeType"] == "VariableDeclarationStatement" {
                                if let Some(declarations) = stmt.get("declarations") {
                                    for declaration in declarations.as_array().unwrap().iter() {
                                        if !declaration.is_null()
                                            && declaration["id"].as_u64().unwrap() == id
                                        {
                                            // if another variable is assigned to the current variable, follow
                                            // the path
                                            if let Some(referenced_id) =
                                                stmt["initialValue"].get("referencedDeclaration")
                                            {
                                                for source in sources.values() {
                                                    if let Some(ast) = source.ast.clone() {
                                                        for top_node in &ast.nodes {
                                                            if let Some(sv_value) =
                                                                Self::find_variable_declaration(
                                                                    sources,
                                                                    top_node,
                                                                    referenced_id.as_u64().unwrap(),
                                                                )
                                                            {
                                                                return Some(sv_value);
                                                            }
                                                        }
                                                    }
                                                }
                                            } else if stmt["initialValue"].get("value").is_some() {
                                                // if a literal is assigned to the variable, return it.
                                                return Some((
                                                    declaration["name"]
                                                        .as_str()
                                                        .unwrap()
                                                        .to_string(),
                                                    declaration["typeDescriptions"]
                                                        ["typeIdentifier"]
                                                        .as_str()
                                                        .unwrap()
                                                        .to_string(),
                                                    U256::from_str(
                                                        stmt["initialValue"]["value"]
                                                            .as_str()
                                                            .unwrap(),
                                                    )
                                                    .unwrap(),
                                                ));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        for subnode in &node.nodes {
            if let Some(sv_node) = Self::find_variable_declaration(sources, subnode, id) {
                return Some(sv_node);
            }
        }
        None
    }

    /// Parses the AST of a contract in order to find variable declarations in function parameters.
    /// Returns a tuple (variable name, variable type, function id, parameter index)
    fn find_parameter_declaration(
        node: &EAstNode,
        id: u64,
    ) -> Option<(String, String, u64, usize)> {
        if node.node_type == NodeType::FunctionDefinition && node.id.is_some() {
            let node_id = node.id.unwrap() as u64;
            if node.other.contains_key("parameters") {
                if let Some(params) = node.other["parameters"].get("parameters") {
                    for (param_index, param) in params.as_array().unwrap().iter().enumerate() {
                        if param["nodeType"] == "VariableDeclaration"
                            && param["id"].as_u64().unwrap() == id
                        {
                            return Some((
                                param["name"].as_str().unwrap().to_string(),
                                param["typeDescriptions"]["typeIdentifier"]
                                    .as_str()
                                    .unwrap()
                                    .to_string(),
                                node_id,
                                param_index,
                            ));
                        }
                    }
                }
            }
        }
        for subnode in &node.nodes {
            if let Some(sv_node) = Self::find_parameter_declaration(subnode, id) {
                return Some(sv_node);
            }
        }
        None
    }

    /// Parses the AST of a contract to find function calls of a given function ID
    /// Creates a vector containing the arguments of each call.
    fn find_call_args(node: &EAstNode, id: u64, args: &mut Vec<(String, Value)>) {
        if node.node_type == NodeType::FunctionDefinition && node.id.is_some() {
            if let Some(body_node) = &node.body {
                if let Some(stmts) = body_node.other.get("statements") {
                    for stmt in stmts.as_array().unwrap().iter() {
                        Self::find_call_args_helper(
                            stmt,
                            id,
                            &node
                                .other
                                .get("name")
                                .unwrap()
                                .as_str()
                                .unwrap()
                                .to_string(),
                            args,
                        );
                    }
                }
            }
        }
        for subnode in &node.nodes {
            Self::find_call_args(subnode, id, args);
        }
    }

    /// Parses the AST ofg a contract and finds all calls of a given function.
    /// Creates a list of arguments of the calls.
    fn find_call_args_helper(
        value: &Value,
        id: u64,
        function_name: &String,
        args: &mut Vec<(String, Value)>,
    ) {
        if value["nodeType"] == "FunctionCall" && value["expression"]["referencedDeclaration"] == id
        {
            args.push((function_name.clone(), value["arguments"].clone()));
        }
        if value.is_object() {
            for (_, sub_value) in value.as_object().unwrap() {
                Self::find_call_args_helper(sub_value, id, function_name, args);
            }
        } else if value.is_array() {
            for sub_value in value.as_array().unwrap() {
                Self::find_call_args_helper(sub_value, id, function_name, args);
            }
        }
    }

    /// Parses the AST of a contract for descriptions (name and type) of variables that are directly
    /// written to storage using assembly.
    /// Creates a set of StorageVariables and TypeDescriptions that can be used by ContractState.
    fn find_direct_storage_write_variables(
        sources: &BTreeMap<PathBuf, SourceFile>,
        node: &EAstNode,
        type_defs: &Types,
        exported_ids: &Vec<usize>,
        storage: &mut Vec<StateVariable>,
        types: &mut HashMap<String, TypeDescription>,
    ) {
        if node.node_type == NodeType::ContractDefinition
            && node.id.is_some()
            && !exported_ids.contains(&node.id.unwrap())
        {
            return;
        }
        if node.node_type == NodeType::FunctionDefinition && node.id.is_some() {
            if let Some(body_node) = &node.body {
                if let Some(stmts) = body_node.other.get("statements") {
                    // check the assembly part of each function
                    for stmt in stmts.as_array().unwrap().iter() {
                        if stmt["nodeType"] != "InlineAssembly" {
                            continue;
                        }
                        if let Some(yul_stmts) = stmt["AST"].get("statements") {
                            for yul_stmt in yul_stmts.as_array().unwrap().iter() {
                                // check for SSTORE operations
                                if yul_stmt["nodeType"] == "YulExpressionStatement"
                                    && yul_stmt["expression"]["functionName"]["name"] == "sstore"
                                {
                                    if let Some(arguments) = yul_stmt["expression"].get("arguments")
                                    {
                                        let arguments_array = &arguments.as_array().unwrap();
                                        if arguments_array.len() == 2 {
                                            // get the data type of the variable that is written to a slot
                                            // by parsing the type of the variable that is used as the second
                                            // store argument
                                            let data_arg = &arguments.as_array().unwrap()[1];
                                            if data_arg["nodeType"] == "YulIdentifier" {
                                                if let Some(stmt_refs) =
                                                    stmt.get("externalReferences")
                                                {
                                                    for stmt_ref in
                                                        stmt_refs.as_array().unwrap().iter()
                                                    {
                                                        if data_arg["src"] == stmt_ref["src"] {
                                                            // find the variable declaration
                                                            let var_id = stmt_ref["declaration"]
                                                                .as_u64()
                                                                .unwrap();
                                                            for source in sources.values() {
                                                                if let Some(ast) =
                                                                    source.ast.clone()
                                                                {
                                                                    for top_node in &ast.nodes {
                                                                        let var_type = match Self::find_variable_declaration(
                                                                            sources,
                                                                            top_node,
                                                                            var_id,
                                                                        ) {
                                                                            Some((_, vt, _)) => Some(vt),
                                                                            None => Self::find_parameter_declaration(top_node, var_id).map(|(_, vt, _, _)| vt)
                                                                        };
                                                                        if let Some(var_type) =
                                                                            var_type
                                                                        {
                                                                            types.insert(
                                                                                var_type.clone(),
                                                                                TypeDescription {
                                                                                    encoding: String::from(
                                                                                        "inplace",
                                                                                    ),
                                                                                    label: var_type.clone(),
                                                                                    number_of_bytes: type_defs.get_number_of_bytes(&var_type),
                                                                                    base: None,
                                                                                    key: None,
                                                                                    value: None,
                                                                                    members: None,
                                                                                },
                                                                            );

                                                                            // get the slot that is written to by parsing the
                                                                            // value (= slot) and name of the variable used in
                                                                            // the first sstore() argument
                                                                            let slot_arg =
                                                                                &arguments
                                                                                    .as_array()
                                                                                    .unwrap()[0];
                                                                            if slot_arg["nodeType"]
                                                                                == "YulIdentifier"
                                                                            {
                                                                                if let Some(stmt_refs) = stmt
                                                                                    .get("externalReferences")
                                                                                {
                                                                                    for stmt_ref in stmt_refs
                                                                                        .as_array()
                                                                                        .unwrap()
                                                                                        .iter()
                                                                                    {
                                                                                        if slot_arg["src"]
                                                                                            == stmt_ref["src"]
                                                                                        {
                                                                                            // find the variable. this must be
                                                                                            // a variable declaration as we need
                                                                                            // a value.
                                                                                            for source in sources.values() {
                                                                                                if let Some(ast) = source.ast.clone() {
                                                                                                    for top_node in &ast.nodes {
                                                                                                        if let Some((var_name, _, var_slot))
                                                                                                            = Self::find_variable_declaration(
                                                                                                                sources,
                                                                                                                top_node,
                                                                                                                stmt_ref["declaration"].as_u64().unwrap()
                                                                                                            ) {
                                                                                                            storage.push(StateVariable {
                                                                                                                contract: String::from(""),
                                                                                                                label: var_name,
                                                                                                                offset: 0,
                                                                                                                slot: var_slot,
                                                                                                                var_type: var_type.clone(),
                                                                                                            });
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            } else if slot_arg
                                                                                ["nodeType"]
                                                                                == "YulLiteral"
                                                                            {
                                                                                let name: String =
                                                                                    if node.other
                                                                                        ["kind"]
                                                                                        == "constructor"
                                                                                    {
                                                                                        String::from("[constructor].unnamed")
                                                                                    } else {
                                                                                        format!(
                                                                                        "[{}].unnamed",
                                                                                        node.other["name"]
                                                                                            .as_str()
                                                                                            .unwrap()
                                                                                    )
                                                                                    };

                                                                                // if the slot argument is not a variable but a literal,
                                                                                // directly add it. In this case, we don't have a
                                                                                // variable name and thus use the name of the function
                                                                                // to distinguish between different slots.
                                                                                storage
                                                                                    .push(StateVariable {
                                                                                    contract: String::from(
                                                                                        "",
                                                                                    ),
                                                                                    label: name,
                                                                                    offset: 0,
                                                                                    slot: U256::from_str(
                                                                                        slot_arg["value"]
                                                                                            .as_str()
                                                                                            .unwrap(),
                                                                                    )
                                                                                    .unwrap(),
                                                                                    var_type: var_type
                                                                                        .clone(),
                                                                                });
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        for subnode in &node.nodes {
            Self::find_direct_storage_write_variables(
                sources,
                subnode,
                type_defs,
                exported_ids,
                storage,
                types,
            );
        }
    }

    /// Parses the AST for a contract definition.
    fn contains_contract(node: &EAstNode, contract_name: &String) -> bool {
        if node.node_type == NodeType::ContractDefinition {
            if let Some(name) = node.other.get("name") {
                if name == contract_name {
                    return true;
                }
            }
        }
        for subnode in &node.nodes {
            if Self::contains_contract(subnode, contract_name) {
                return true;
            }
        }
        false
    }

    // Parses the AST to find all associated contracts (libraries & parent contracts)
    fn find_exported_ids(
        sources: &BTreeMap<PathBuf, SourceFile>,
        contract_name: &String,
        exported_ids: &mut Vec<usize>,
    ) {
        for source in sources.values() {
            if let Some(new_ast) = source.ast.clone() {
                for node in &new_ast.nodes {
                    if Self::contains_contract(node, contract_name) {
                        for (sub_contract, symbols) in new_ast.exported_symbols {
                            // TODO: what does it mean if there is more than 1 symbol per contract?
                            if symbols.len() == 1 && !exported_ids.contains(&symbols[0]) {
                                exported_ids.extend(symbols);
                                Self::find_exported_ids(sources, &sub_contract, exported_ids);
                            }
                        }
                        break;
                    }
                }
            }
        }
    }

    pub fn compile(
        project: &Path,
        env: Environment,
        artifacts_path: &Path,
    ) -> Result<PathBuf, ValidationError> {
        let build_info_path: PathBuf;
        let build_info_dir: TempDir;

        match env {
            Environment::Foundry => {
                assert!(Self::check_forge());
                build_info_dir = Builder::new().prefix("dvf_bi").tempdir().unwrap();
                // Persist for now
                build_info_path = build_info_dir.keep();
                Self::forge_build(project, &build_info_path)?;
            }
            Environment::Hardhat => {
                assert!(Self::check_hardhat(project));
                // artifacts path only used for hardhat
                build_info_path = artifacts_path.to_path_buf();
                Self::hardhat_compile(project)?;
            }
        }
        Ok(build_info_path)
    }

    pub fn new(
        contract_name: &String,
        project: &Path,
        env: Environment,
        artifacts_path: &Path,
        build_cache: Option<&String>,
    ) -> Result<Self, ValidationError> {
        let build_info_path: PathBuf = match build_cache {
            Some(s) => PathBuf::from(s),
            None => Self::compile(project, env, artifacts_path)?,
        };

        let command = match env {
            Environment::Foundry => "<forge clean>",
            Environment::Hardhat => "<npx hardhat clean>",
        };

        let mut build_infos = Vec::<BuildInfo>::new();
        match build_info_path.read_dir() {
            Ok(read_dir) => {
                for build_info_file in read_dir.flatten() {
                    debug!(
                        "Used build info file: {}",
                        &build_info_file.path().to_str().unwrap()
                    );
                    let bi = BuildInfo::read(&build_info_file.path())?;
                    if bi
                        .output
                        .contracts
                        .values()
                        .flatten()
                        .any(|(name, _)| name == contract_name)
                    {
                        build_infos.push(bi);
                    }
                }
            }
            _ => {
                return Err(ValidationError::from(
                    format!("The build artifacts could not be read. If the artifacts path is set correctly, try running {} in the project folder.", command.green()),
                ));
            }
        };

        // TODO: Understand this better
        if build_infos.is_empty() {
            return Err(ValidationError::from("No build-info files could be found."));
        } else if build_infos.len() != 1 {
            return Err(ValidationError::from(format!(
                "Multiple build-info files found. Try running {} in the project folder.",
                command.green()
            )));
        }

        let build_info = &build_infos[0];

        // let main_out = build_info.output.find(contract_name);

        let mut other_bytecodes: Vec<String> = vec![];
        let mut co: Option<&ContractArt> = None;
        for fname in build_info.output.contracts.keys() {
            for c_name in build_info.output.contracts[fname].keys() {
                if c_name == contract_name {
                    co = Some(&build_info.output.contracts[fname][c_name]);
                } else {
                    let bco = build_info.output.contracts[fname][c_name]
                        .evm
                        .as_ref()
                        .and_then(|evm| evm.deployed_bytecode.as_ref())
                        .and_then(|db| db.bytecode.as_ref())
                        .map(|bc| &bc.object);
                    if let Some(bc) = bco {
                        let compiled_bytecode_str = match bc {
                            BytecodeObject::Bytecode(b) => hex::encode(b.clone().0),
                            BytecodeObject::Unlinked(s) => s.clone(),
                        };
                        if compiled_bytecode_str.len() > 4
                            && !other_bytecodes.contains(&compiled_bytecode_str)
                        {
                            other_bytecodes.push(compiled_bytecode_str);
                        }
                    }
                }
            }
        }
        /*
        build_info.output.contracts_iter().find_map(|(name, contract)| {
            (name == contract_name).then(|| contract)
        });
        */
        if co.is_none() {
            return Err(ValidationError::from("Contract not found in build output."));
        }
        let contract: &ContractArt = co.unwrap();
        let (db_tmp, bc_tmp) = contract
            .evm
            .as_ref()
            .map(|evm| (evm.deployed_bytecode.clone(), evm.bytecode.clone()))
            .unwrap_or_else(|| (None, None));

        if db_tmp.is_none() {
            return Err(ValidationError::from(
                "No deployed bytecode found in build output.",
            ));
        }
        let deployed_bytecode = db_tmp.unwrap();
        let compiled_bytecode = deployed_bytecode.bytecode.as_ref().map(|bc| &bc.object);
        let compiled_bytecode_str = Self::extract_bytecode_as_string(compiled_bytecode)?;

        let init_code_str = Self::extract_bytecode_as_string(bc_tmp.as_ref().map(|bc| &bc.object))?;

        // Collect Events
        let mut events = vec![];
        if let Some(cabi) = &contract.abi {
            for sig in cabi.events.keys() {
                events.extend(cabi.events[sig].clone());
            }
        }

        // Collect Constructor Arguments
        let mut constructor_args: Vec<ConstructorArg> = vec![];
        let mut constructor: Option<Constructor> = None;
        if let Some(cabi) = &contract.abi {
            constructor = cabi.constructor.clone();
            if constructor.is_some() {
                constructor_args = constructor
                    .as_ref()
                    .unwrap()
                    .inputs
                    .iter()
                    .map(|input| ConstructorArg {
                        name: input.name.clone(),
                        type_string: String::new(),
                        value: String::new(),
                    })
                    .collect();
            }
        }

        // Get relevant AST
        let mut id_to_ast = HashMap::<usize, TmpVariableDeclaration>::new();
        let type_defs = Types::new();
        // We do not need all the ASTs, technically we only need the dependencies
        // Currently we go through all
        let mut storage: Vec<StateVariable> = vec![];
        let mut types: HashMap<String, TypeDescription> = HashMap::new();
        let mut exported_ids: Vec<usize> = vec![];
        let mut absolute_path: Option<String> = None;
        for (file, source) in build_info.output.sources.clone() {
            if let Some(new_ast) = source.ast.clone() {
                for node in &new_ast.nodes {
                    if Self::contains_contract(node, contract_name) {
                        absolute_path = Some(new_ast.absolute_path.to_string());
                        break;
                    }
                }
            } else {
                debug!("Empty AST found: {}", file.display());
            }
        }
        // get exported AST IDs of the current contract to prevent parsing storage slots of other contracts
        // in the project
        Self::find_exported_ids(&build_info.output.sources, contract_name, &mut exported_ids);
        if exported_ids.is_empty() {
            return Err(ValidationError::from(format!(
                "Could not find the associated sources of contract {}",
                &contract_name
            )));
        }
        for source in build_info.output.sources.values() {
            // TODO: Error handle here, what though?
            if let Some(new_ast) = source.ast.clone() {
                for node in &new_ast.nodes {
                    Self::find_var_defs(node, &mut id_to_ast);
                }
            }
        }
        // find structs that are used in storage slots but not declared as storage variable
        Self::find_storage_structs(
            &build_info.output.sources,
            &type_defs,
            &exported_ids,
            &mut storage,
            &mut types,
        );
        Self::find_direct_storage_writes(
            &build_info.output.sources,
            &type_defs,
            &exported_ids,
            &mut storage,
            &mut types,
        );

        let immutables = Self::extract_immutables(&deployed_bytecode, &id_to_ast);

        // If we are not using build_cache then delete the tmp files
        if build_cache.is_none() && env == Environment::Foundry {
            fs::remove_dir_all(&build_info_path)?;
        };

        let pi = ProjectInfo {
            compiled_bytecode: compiled_bytecode_str,
            init_code: init_code_str,
            compiler_version: build_info.solc_version.clone(),
            optimization_enabled: build_info.input.settings.optimizer.enabled.unwrap_or(false),
            optimization_runs: build_info.input.settings.optimizer.runs.unwrap_or_default(),
            cbor_metadata: build_info
                .input
                .settings
                .metadata
                .as_ref()
                .and_then(|md| md.bytecode_hash),
            immutables,
            constructor_args,
            constructor,
            events,
            other_bytecodes,
            storage,
            types,
            absolute_path,
        };

        Ok(pi)
    }

    // Extract immutables with extra info from Ast
    fn extract_immutables(
        deployed_bytecode: &DeployedBytecode,
        ast_id_to_info: &HashMap<usize, TmpVariableDeclaration>,
    ) -> Vec<Immutable> {
        let mut immutables = Vec::<Immutable>::new();

        for (sid, immutable_references) in deployed_bytecode.immutable_references.iter() {
            let id: usize = sid.parse().unwrap();
            let mut observed_length: Option<u32> = None;
            let mut observed_starts: Vec<u32> = vec![];

            for immutable_reference in immutable_references {
                assert!(
                    observed_length.is_none()
                        || Some(immutable_reference.length) == observed_length,
                    "An immutable has inconsistent lengths"
                );
                if observed_length.is_none() {
                    observed_length = Some(immutable_reference.length);
                }
                observed_starts.push(immutable_reference.start);
            }

            if observed_length.is_none() {
                info!(
                    "Warning: Immutable {} has no references.",
                    ast_id_to_info[&id].name.clone()
                );
                continue;
            }

            let immutable = Immutable {
                id,
                immutable_starts: observed_starts,
                length: observed_length.unwrap(),
                value: String::new(),
                name: ast_id_to_info[&id].name.clone(),
                type_string: ast_id_to_info[&id].type_string.clone(),
            };

            immutables.push(immutable);
        }
        immutables
    }
}

#[derive(ValueEnum, Copy, Clone, Eq, PartialEq)]
pub enum Environment {
    Foundry,
    Hardhat,
}

impl std::fmt::Display for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_possible_value()
            .expect("no values are skipped")
            .get_name()
            .fmt(f)
    }
}
