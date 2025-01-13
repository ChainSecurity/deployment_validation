#[cfg(test)]

mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::path::Path;

    use dvf_libs::dvf::config::DVFConfig;
    use dvf_libs::dvf::parse::DVFStorageEntry;
    use dvf_libs::state::contract_state::ContractState;
    use dvf_libs::state::forge_inspect;
    use dvf_libs::utils::pretty::PrettyPrinter;
    use dvf_libs::web3::{IntermediateTraceWithAddress, StorageSnapshot, TraceWithAddress};
    use prettytable::Table;

    fn generate_results(
        contract_name: &str,
        snapshot: &mut StorageSnapshot,
        trace_w_a: &TraceWithAddress,
    ) -> Vec<DVFStorageEntry> {
        let mut empty_config = DVFConfig::default();
        empty_config.set_chain_id(1).unwrap();
        let pretty_printer = PrettyPrinter::new(&empty_config, None);
        let mut global_state = ContractState::new_with_address(&trace_w_a.address, &pretty_printer);
        let forge_inspect = forge_inspect::ForgeInspect::generate_and_parse_layout(
            Path::new("tests/Contracts"),
            contract_name,
            None,
        );
        global_state.add_forge_inspect(&forge_inspect);
        global_state
            .record_traces(&empty_config, vec![trace_w_a.clone()])
            .unwrap();
        let mut table = Table::new();

        global_state
            .get_critical_storage_variables(snapshot, &mut table, &vec![], &HashMap::new())
            .unwrap()
    }

    #[test]
    fn test_expected_results() {
        for contract_name in [
            "BytesMapping",
            "CrazyStruct",
            "DynamicArrayOfStaticArray",
            "Enum",
            "NestedMapping",
            "StaticArray",
            "StaticArrayOfDynamicArray",
            "StaticArrayOfStaticArray",
            "StaticArrayOfStruct",
            "StaticInMapping",
            "StringMapping",
            "StructInMapping",
            "StructInStruct",
        ] {
            let path = format!("./tests/data/trace_{}.json", contract_name);
            println!("Reading {}", path);
            let trace_str = fs::read_to_string(&path).unwrap();
            let trace_w_a: IntermediateTraceWithAddress = serde_json::from_str(&trace_str).unwrap();
            let trace_w_a: TraceWithAddress = trace_w_a.into();

            let empty_config = DVFConfig::default();
            let mut snapshot =
                StorageSnapshot::from_trace(&empty_config, &trace_w_a.address, &trace_w_a).unwrap();
            let generated_result = generate_results(contract_name, &mut snapshot, &trace_w_a);

            let res_str =
                fs::read_to_string(format!("./tests/data/result_{}.json", contract_name)).unwrap();
            let expected_result: Vec<DVFStorageEntry> = serde_json::from_str(&res_str).unwrap();

            assert_eq!(generated_result.len(), expected_result.len());
            for i in 0..generated_result.len() {
                assert_eq!(generated_result[i], expected_result[i]);
            }
        }
    }

    /*

    #[test]
    fn test_struct_in_struct() {
        let contract_name = "StructInStruct";

        let names = vec![
            "StructInStruct[0]",
            "StructInStruct[1]",
            "StructInStruct[2]",
            "StructInStruct[3]",
        ];

        let expected_result: Vec<Vec<(&str, &str, usize)>> = vec![
            vec![(
                "StructInStruct.a",
                "0x0000000011111111222222223333333344444444555555556666666677777777",
                0,
            )],
            vec![(
                "StructInStruct.b",
                "0x3333333344444444555555556666666677777777",
                0,
            )],
            vec![(
                "StructInStruct.t.A",
                "0x0000000011111111222222223333333344444444555555556666666677777777",
                0,
            )],
            vec![
                (
                    "StructInStruct.t.B",
                    "0x3333333344444444555555556666666677777777",
                    0,
                ),
                ("StructInStruct.t.C", "0x22", 20),
            ],
        ];

        let generated_result = generate_results(contract_name, names);

        assert!(generated_result == convert_slice_to_string(expected_result));
    }

    #[test]
    fn test_static_mapping() {
        let contract_name = "StaticInMapping";

        let names = vec![
            "static_in_mapping[000000000000000000000000AAAAAAAAAADDDDDDDDDDRRRRRRRRRRXXXXXXXXXX]",
            "static_in_mapping[000000000000000000000000AAAAAAAAAADDDDDDDDDDRRRRRRRRRRXXXXXXXXXX][1]",
        ];

        let expected_result : Vec<Vec<(&str, &str, usize)>> = vec![
            vec![("static_in_mapping[0x000000000000000000000000AAAAAAAAAADDDDDDDDDDRRRRRRRRRRXXXXXXXXXX][0]", "0x44444444555555556666666677777777", 0), ("static_in_mapping[0x000000000000000000000000AAAAAAAAAADDDDDDDDDDRRRRRRRRRRXXXXXXXXXX][1]", "0x00000000111111112222222233333333", 16)],
            vec![("static_in_mapping[0x000000000000000000000000AAAAAAAAAADDDDDDDDDDRRRRRRRRRRXXXXXXXXXX][2]", "0x44444444555555556666666677777777", 0)],
        ];

        let generated_result = generate_results(contract_name, names);

        assert!(generated_result == convert_slice_to_string(expected_result));
    }

    #[test]
    fn test_static_array_of_struct() {
        let contract_name = "StaticArrayOfStruct";

        let names = vec![
            "static_array_of_struct",
            "static_array_of_struct[1]",
            "static_array_of_struct[2]",
            "static_array_of_struct[3]",
        ];

        let expected_result: Vec<Vec<(&str, &str, usize)>> = vec![
            vec![(
                "static_array_of_struct[0].A",
                "0x0000000011111111222222223333333344444444555555556666666677777777",
                0,
            )],
            vec![
                (
                    "static_array_of_struct[0].B",
                    "0x3333333344444444555555556666666677777777",
                    0,
                ),
                ("static_array_of_struct[0].C", "0x22", 20),
            ],
            vec![(
                "static_array_of_struct[1].A",
                "0x0000000011111111222222223333333344444444555555556666666677777777",
                0,
            )],
            vec![
                (
                    "static_array_of_struct[1].B",
                    "0x3333333344444444555555556666666677777777",
                    0,
                ),
                ("static_array_of_struct[1].C", "0x22", 20),
            ],
        ];

        let generated_result = generate_results(contract_name, names);

        assert!(generated_result == convert_slice_to_string(expected_result));
    }

    #[test]
    fn test_static_array_of_static_array() {
        let contract_name = "StaticArrayOfStaticArray";

        let names = vec![
            "StaticStatic",
            "StaticStatic[1]",
            "StaticStatic[2]",
            "StaticStatic[3]",
        ];

        let expected_result: Vec<Vec<(&str, &str, usize)>> = vec![
            vec![
                ("StaticStatic[0][0]", "0x6666666677777777", 0),
                ("StaticStatic[0][1]", "0x4444444455555555", 8),
                ("StaticStatic[0][2]", "0x2222222233333333", 16),
                ("StaticStatic[0][3]", "0x0000000011111111", 24),
            ],
            vec![
                ("StaticStatic[0][4]", "0x6666666677777777", 0),
                ("StaticStatic[0][5]", "0x4444444455555555", 8),
            ],
            vec![
                ("StaticStatic[1][0]", "0x6666666677777777", 0),
                ("StaticStatic[1][1]", "0x4444444455555555", 8),
                ("StaticStatic[1][2]", "0x2222222233333333", 16),
                ("StaticStatic[1][3]", "0x0000000011111111", 24),
            ],
            vec![
                ("StaticStatic[1][4]", "0x6666666677777777", 0),
                ("StaticStatic[1][5]", "0x4444444455555555", 8),
            ],
        ];

        let generated_result = generate_results(contract_name, names);

        assert!(generated_result == convert_slice_to_string(expected_result));
    }

    #[test]
    fn test_static_array_of_dynamic_array() {
        let contract_name = "StaticArrayOfDynamicArray";

        let names = vec![
            "StaticDynamic",
            "StaticDynamic[1]",
            "StaticDynamic[2]",
            "StaticDynamic[0][0]",
            "StaticDynamic[1][10]",
        ];

        let expected_result: Vec<Vec<(&str, &str, usize)>> = vec![
            vec![(
                "StaticDynamic[0].length",
                "0x0000000011111111222222223333333344444444555555556666666677777777",
                0,
            )],
            vec![(
                "StaticDynamic[1].length",
                "0x0000000011111111222222223333333344444444555555556666666677777777",
                0,
            )],
            vec![(
                "StaticDynamic[2].length",
                "0x0000000011111111222222223333333344444444555555556666666677777777",
                0,
            )],
            vec![
                (
                    "StaticDynamic[0][0]",
                    "0x44444444555555556666666677777777",
                    0,
                ),
                (
                    "StaticDynamic[0][1]",
                    "0x00000000111111112222222233333333",
                    16,
                ),
            ],
            vec![
                (
                    "StaticDynamic[1][20]",
                    "0x44444444555555556666666677777777",
                    0,
                ),
                (
                    "StaticDynamic[1][21]",
                    "0x00000000111111112222222233333333",
                    16,
                ),
            ],
        ];

        let generated_result = generate_results(contract_name, names);

        assert!(generated_result == convert_slice_to_string(expected_result));
    }

    #[test]
    fn test_static_array() {
        let contract_name = "StaticArray";

        let names = vec!["Static", "Static[1]"];

        let expected_result: Vec<Vec<(&str, &str, usize)>> = vec![
            vec![
                ("Static[0]", "0x6666666677777777", 0),
                ("Static[1]", "0x4444444455555555", 8),
                ("Static[2]", "0x2222222233333333", 16),
                ("Static[3]", "0x0000000011111111", 24),
            ],
            vec![
                ("Static[4]", "0x6666666677777777", 0),
                ("Static[5]", "0x4444444455555555", 8),
            ],
        ];

        let generated_result = generate_results(contract_name, names);

        assert!(generated_result == convert_slice_to_string(expected_result));
    }

    #[test]
    fn test_nested_mapping() {
        let contract_name = "NestedMapping";

        let names =
            vec!["mp[AAAAAAAADDDDDDDDRRRRRRRRXXXXXXXX1][AAAAAAAADDDDDDDDRRRRRRRRXXXXXXXX2]"];

        let expected_result: Vec<Vec<(&str, &str, usize)>> = vec![vec![(
            "mp[0xAAAAAAAADDDDDDDDRRRRRRRRXXXXXXXX1][0xAAAAAAAADDDDDDDDRRRRRRRRXXXXXXXX2]",
            "0x44444444555555556666666677777777",
            0,
        )]];

        let generated_result = generate_results(contract_name, names);

        assert!(generated_result == convert_slice_to_string(expected_result));
    }

    #[test]
    fn test_dynamic_array_of_static_array() {
        let contract_name = "DynamicArrayOfStaticArray";

        let names = vec![
            "DynamicStatic",
            "DynamicStatic[0]",
            "DynamicStatic[1]",
            "DynamicStatic[2]",
        ];

        let expected_result: Vec<Vec<(&str, &str, usize)>> = vec![
            vec![(
                "DynamicStatic.length",
                "0x0000000011111111222222223333333344444444555555556666666677777777",
                0,
            )],
            vec![
                ("DynamicStatic[0][0]", "0x6666666677777777", 0),
                ("DynamicStatic[0][1]", "0x4444444455555555", 8),
                ("DynamicStatic[0][2]", "0x2222222233333333", 16),
                ("DynamicStatic[0][3]", "0x0000000011111111", 24),
            ],
            vec![
                ("DynamicStatic[0][4]", "0x6666666677777777", 0),
                ("DynamicStatic[0][5]", "0x4444444455555555", 8),
            ],
            vec![
                ("DynamicStatic[1][0]", "0x6666666677777777", 0),
                ("DynamicStatic[1][1]", "0x4444444455555555", 8),
                ("DynamicStatic[1][2]", "0x2222222233333333", 16),
                ("DynamicStatic[1][3]", "0x0000000011111111", 24),
            ],
        ];

        let generated_result = generate_results(contract_name, names);

        assert!(generated_result == convert_slice_to_string(expected_result));
    }

    #[test]
    fn test_crazy_struct() {
        let contract_name = "CrazyStruct";

        let names = vec![
            "CrazyStruct",
            "CrazyStruct[1]",
            "CrazyStruct[2]",
            "CrazyStruct[3]",
            "CrazyStruct[4]",
            "CrazyStruct[5][000000000000000000000000AAAAAAAAAADDDDDDDDDDRRRRRRRRRRXXXXXXXXXX][2]",
            "CrazyStruct[6]",
            "CrazyStruct[6][2]",
        ];

        let expected_result: Vec<Vec<(&str, &str, usize)>> = vec![
            vec![(
                "CrazyStruct.A",
                "0x0000000011111111222222223333333344444444555555556666666677777777",
                0,
            )],
            vec![
                (
                    "CrazyStruct.B",
                    "0x3333333344444444555555556666666677777777",
                    0,
                ),
                ("CrazyStruct.C", "0x22", 20),
            ],
            vec![
                ("CrazyStruct.D[0]", "0x6666666677777777", 0),
                ("CrazyStruct.D[1]", "0x4444444455555555", 8),
                ("CrazyStruct.D[2]", "0x2222222233333333", 16),
                ("CrazyStruct.D[3]", "0x0000000011111111", 24),
            ],
            vec![
                ("CrazyStruct.D[4]", "0x6666666677777777", 0),
                ("CrazyStruct.D[5]", "0x4444444455555555", 8),
            ],
            vec![("CrazyStruct.E", "0x44444444555555556666666677777777", 0)],
            vec![(
                "CrazyStruct.mp[0x000000000000000000000000AAAAAAAAAADDDDDDDDDDRRRRRRRRRRXXXXXXXXXX][0x2]",
                "0x77",
                0,
            )],
            vec![(
                "CrazyStruct.F.length",
                "0x0000000011111111222222223333333344444444555555556666666677777777",
                0,
            )],
            vec![
                ("CrazyStruct.F[4]", "0x44444444555555556666666677777777", 0),
                ("CrazyStruct.F[5]", "0x00000000111111112222222233333333", 16),
            ],
        ];

        let generated_result = generate_results(contract_name, names);

        assert!(generated_result == convert_slice_to_string(expected_result));
    }
    */
}
