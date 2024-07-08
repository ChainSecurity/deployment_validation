// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract DynamicArrayOfStaticArray {
    uint64[6][] dynamicStatic;

    constructor() {
        uint64[6] memory x = [uint64(1), 2, 3, 4, 5, 6];
        dynamicStatic.push(x);
        uint64[6] memory y = [uint64(0), 0, 10 ** 18, 0, 0, 0];
        dynamicStatic.push(y);
    }
}
