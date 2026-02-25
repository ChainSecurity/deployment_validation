// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

/// mix of static-type key mapping assignments, dynamic-type key mapping assignments, and others
contract StaticInMapping {
    mapping(address => uint256) static_in_mapping;
    mapping(uint256 => uint256) static_in_mapping2;
    mapping(string => uint256) static_in_mapping3;
    mapping(uint256 => mapping(uint256 => uint256)) static_in_mapping4;
    uint256 someInt;
    uint64[6][] dynamicStatic;
    uint256 constant KEY = 345;

    constructor() {
        // static_in_mapping[address(this)] = 2 ** 128 - 1;

        // compiler computes sha3 of key
        // static_in_mapping[address(1)] = 16;

        static_in_mapping[address(this)] = 2 ** 256 - 1;
        static_in_mapping[msg.sender] = 5;
        static_in_mapping2[2 + 3] = 45;

        if (static_in_mapping2[5] == 45) {
            someInt = 88;
            static_in_mapping[address(23)] = 100;
        }
        uint64[6] memory x = [uint64(1), 2, 3, 4, 5, 6];
        dynamicStatic.push(x);
        uint64[6] memory y = [uint64(0), 0, 10 ** 18, 0, 0, 0];
        dynamicStatic.push(y);
    }

    function assign() external {
        // compiler computes sha3 of key
        static_in_mapping[address(1)] = 16;
        static_in_mapping2[1 + 15] = 42;
        static_in_mapping2[1 + 16] = 81 + 2;
        static_in_mapping2[KEY] = 100;
        static_in_mapping3["hello"] = 200;
        static_in_mapping4[1][2] = 300; // TODO: This currently does not work

        someInt = 100;
    }

    function dummy() external {}
}
