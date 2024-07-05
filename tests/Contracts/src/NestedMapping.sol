// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract NestedMapping {
    mapping(address => mapping(address => int128)) mp;
    mapping(int8 => mapping(int128 => int256)) mp2;
    mapping(uint8 => mapping(uint128 => uint256)) mp3;
    int8 x = -2;

    constructor(bool b) {
        mp[address(this)][address(0x1111111254EEB25477B68fb85Ed929f73A960582)] = 10 ** 8;
        address a = address(0x0);
        if (b) {
            a = address(this);
        }
        mp[a][address(this)] = -5;
    }

    function f(bool b) external {
        int8 i = -2;
        int128 i2 = 0;
        uint8 ui = 42;
        uint128 ui2 = 100;
        // Try to prevent caching
        if (b) {
            i = 10;
            i2 = 12;
            ui = 10;
            ui2 = 12;
        }
        mp2[i][i2] = -2;
        mp3[ui][ui2] = 42;
    }

    function g(bool b) external {
        int8 i = 10;
        int128 i2 = -2;
        // Try to prevent caching
        if (b) {
            i = 12;
            i2 = 12;
        }
        mp2[i][i2] = -1000;
    }

    function dummy() external {}
}
