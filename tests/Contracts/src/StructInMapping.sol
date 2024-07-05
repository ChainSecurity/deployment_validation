// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract StructInMapping {
    struct T {
        uint256 A;
        address B;
        bool C;
    }

    struct S {
        uint128 a;
        uint128 b;
        T[] t;
    }

    mapping(address => S) struct_in_mapping;

    constructor() {
        struct_in_mapping[address(this)].a = 1;
        struct_in_mapping[address(this)].b = 42;
        struct_in_mapping[address(this)].t.push(T(23, address(0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD), false));
        struct_in_mapping[address(this)].t.push(T(123, address(0x0), true));
    }
}
