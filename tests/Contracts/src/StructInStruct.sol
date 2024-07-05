// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract StructInStruct {
    struct T {
        uint256 A;
        address B;
        bool C;
    }

    struct S {
        uint256 a;
        address b;
        T t;
    }

    S structInStructType;

    constructor() {
        structInStructType.a = 666;
        structInStructType.b = 0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC;
        structInStructType.t.A = 123;
        structInStructType.t.C = true;
    }
}
