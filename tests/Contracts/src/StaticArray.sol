// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract StaticArray {
    uint64[6] staticArray;
    address[4] addressArray;

    constructor() {
        staticArray[5] = 500;
        staticArray[4] = 100;
        staticArray[5] = 32;
        addressArray[0] = address(0x0);
        addressArray[1] = address(0x1);
        addressArray[2] = address(0x2);
        addressArray[3] = address(0x3);
    }
}
