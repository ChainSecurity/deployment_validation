// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract StaticInMapping {
    mapping(address => uint128[3]) static_in_mapping;

    constructor() {
        static_in_mapping[address(this)][2] = 2 ** 128 - 1;
        static_in_mapping[address(this)][0] = 2 ** 128 - 1;
        static_in_mapping[msg.sender][1] = 5;
    }
}
