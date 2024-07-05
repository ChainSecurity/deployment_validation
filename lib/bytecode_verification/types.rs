use std::collections::HashMap;

pub struct Types {
    map: HashMap<String, usize>,
}

impl Types {
    pub fn new() -> Self {
        let map: HashMap<String, usize> = HashMap::from([
            (String::from("t_uint8"), 1),
            (String::from("t_uint16"), 2),
            (String::from("t_uint24"), 3),
            (String::from("t_uint32"), 4),
            (String::from("t_uint40"), 5),
            (String::from("t_uint48"), 6),
            (String::from("t_uint56"), 7),
            (String::from("t_uint64"), 8),
            (String::from("t_uint72"), 9),
            (String::from("t_uint80"), 10),
            (String::from("t_uint88"), 11),
            (String::from("t_uint96"), 12),
            (String::from("t_uint104"), 13),
            (String::from("t_uint112"), 14),
            (String::from("t_uint120"), 15),
            (String::from("t_uint128"), 16),
            (String::from("t_uint136"), 17),
            (String::from("t_uint144"), 18),
            (String::from("t_uint152"), 19),
            (String::from("t_uint160"), 20),
            (String::from("t_uint168"), 21),
            (String::from("t_uint176"), 22),
            (String::from("t_uint184"), 23),
            (String::from("t_uint192"), 24),
            (String::from("t_uint200"), 25),
            (String::from("t_uint208"), 26),
            (String::from("t_uint216"), 27),
            (String::from("t_uint224"), 28),
            (String::from("t_uint232"), 29),
            (String::from("t_uint240"), 30),
            (String::from("t_uint248"), 31),
            (String::from("t_uint256"), 32),
            (String::from("t_int8"), 1),
            (String::from("t_int16"), 2),
            (String::from("t_int24"), 3),
            (String::from("t_int32"), 4),
            (String::from("t_int40"), 5),
            (String::from("t_int48"), 6),
            (String::from("t_int56"), 7),
            (String::from("t_int64"), 8),
            (String::from("t_int72"), 9),
            (String::from("t_int80"), 10),
            (String::from("t_int88"), 11),
            (String::from("t_int96"), 12),
            (String::from("t_int104"), 13),
            (String::from("t_int112"), 14),
            (String::from("t_int120"), 15),
            (String::from("t_int128"), 16),
            (String::from("t_int136"), 17),
            (String::from("t_int144"), 18),
            (String::from("t_int152"), 19),
            (String::from("t_int160"), 20),
            (String::from("t_int168"), 21),
            (String::from("t_int176"), 22),
            (String::from("t_int184"), 23),
            (String::from("t_int192"), 24),
            (String::from("t_int200"), 25),
            (String::from("t_int208"), 26),
            (String::from("t_int216"), 27),
            (String::from("t_int224"), 28),
            (String::from("t_int232"), 29),
            (String::from("t_int240"), 30),
            (String::from("t_int248"), 31),
            (String::from("t_int256"), 32),
            (String::from("t_bytes1"), 1),
            (String::from("t_bytes2"), 2),
            (String::from("t_bytes3"), 3),
            (String::from("t_bytes4"), 4),
            (String::from("t_bytes5"), 5),
            (String::from("t_bytes6"), 6),
            (String::from("t_bytes7"), 7),
            (String::from("t_bytes8"), 8),
            (String::from("t_bytes9"), 9),
            (String::from("t_bytes10"), 10),
            (String::from("t_bytes11"), 11),
            (String::from("t_bytes12"), 12),
            (String::from("t_bytes13"), 13),
            (String::from("t_bytes14"), 14),
            (String::from("t_bytes15"), 15),
            (String::from("t_bytes16"), 16),
            (String::from("t_bytes17"), 17),
            (String::from("t_bytes18"), 18),
            (String::from("t_bytes19"), 19),
            (String::from("t_bytes20"), 20),
            (String::from("t_bytes21"), 21),
            (String::from("t_bytes22"), 22),
            (String::from("t_bytes23"), 23),
            (String::from("t_bytes24"), 24),
            (String::from("t_bytes25"), 25),
            (String::from("t_bytes26"), 26),
            (String::from("t_bytes27"), 27),
            (String::from("t_bytes28"), 28),
            (String::from("t_bytes29"), 29),
            (String::from("t_bytes30"), 30),
            (String::from("t_bytes31"), 31),
            (String::from("t_bytes32"), 32),
            (String::from("t_address"), 20),
            (String::from("t_bytes_storage_ptr"), 32),
            (String::from("t_string_storage_ptr"), 32),
            (String::from("t_bool"), 1),
        ]);
        Types { map }
    }

    /// Should only be used for value types
    pub fn get_number_of_bytes(&self, type_name: &String) -> usize {
        if type_name.starts_with("t_contract") {
            return 20;
        } else if type_name.starts_with("t_enum") {
            return 1;
        }
        *self.map.get(type_name).unwrap()
    }
}

impl Default for Types {
    fn default() -> Self {
        Self::new()
    }
}
