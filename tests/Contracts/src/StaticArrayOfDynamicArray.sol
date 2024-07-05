// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract StaticArrayOfDynamicArray {
    uint128[][3] staticDynamic;

    address[][3] staticDynamicAddress;

    event Test1(uint128[][3] x);
    event Test2(uint128[] y);

    constructor() {
        staticDynamic[1].push(10 ** 10);
        staticDynamic[0].push(2 ** 20);
        staticDynamic[2].push(2 ** 20);
        staticDynamic[1].push(2 ** 20);
        staticDynamic[1].push(2 ** 20);
        staticDynamic[1].pop();
        staticDynamicAddress[0].push(address(0x1));
        staticDynamicAddress[0].push(address(0x2));
        staticDynamicAddress[1].push(address(0x11));
        staticDynamicAddress[1].push(address(0x12));
        emit Test1(staticDynamic);
    }

    function f() external {
        staticDynamic[0].push(2 ** 20);
        emit Test2(staticDynamic[0]);
    }

    function g() external {
        staticDynamic[0].push(10 ** 19);
        emit Test1(staticDynamic);
    }

    function dummy() external {}
}
