// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract StaticArrayOfStruct {
    struct T {
        uint256 A;
        address B;
        bool C;
    }

    uint256 buffer;
    T[5] static_array_of_struct;

    constructor() {
        static_array_of_struct[0].A = 2 ** 32 - 1;
        static_array_of_struct[4].C = true;
        static_array_of_struct[3].B = address(this);
    }
}
