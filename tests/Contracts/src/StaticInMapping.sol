// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract StaticInMapping {
    mapping(address => uint256) static_in_mapping;
    mapping(uint256 => uint256) static_in_mapping2;

    constructor() {
        // static_in_mapping[address(this)] = 2 ** 128 - 1;

        // compiler computes sha3 of key
        // static_in_mapping[address(1)] = 16;

        static_in_mapping[address(this)] = 2 ** 256 - 1;
        static_in_mapping[msg.sender] = 5;
        static_in_mapping2[2 + 3] = 45;
    }

    function assign() external {
        // compiler computes sha3 of key
        static_in_mapping[address(1)] = 16;
        static_in_mapping2[1 + 15] = 42;
        static_in_mapping2[1 + 16] = 81 + 2;
    }

    function dummy() external {}
}
