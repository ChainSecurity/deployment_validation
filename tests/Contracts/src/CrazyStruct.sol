// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract CrazyStruct {
    struct CrazyStructType {
        uint256 A;
        address B;
        bool C;
        uint64[6] D;
        uint128 E;
        mapping(address => mapping(uint256 => bool)) mp;
        uint128[] F;
    }

    uint256 x;
    CrazyStructType S;

    constructor() {
        x = 1337;
        S.A = 65;
        S.B = address(0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE);
        S.C = true;
        S.D[1] = 42;
        S.D[5] = 124;
        S.E = 128;
        S.mp[address(this)][42] = false;
        S.mp[address(this)][type(uint256).max] = true;
    }

    function f() external {
        x = 456;
        S.A = 64;
    }

    function g() external {
        S.D[3] = 3;
    }

    function dummy() external {}
}
