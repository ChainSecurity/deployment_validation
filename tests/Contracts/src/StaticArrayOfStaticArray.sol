// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract StaticArrayOfStaticArray {
    uint64[6][3] staticStatic;

    constructor() {
        staticStatic[0][1] = 42;
        staticStatic[2][3] = 142;
        staticStatic[0][0] = 10 ** 18;
        staticStatic[0][0] = 0;
    }
}
