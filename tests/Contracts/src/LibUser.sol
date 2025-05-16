// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "../src/Lib.sol";

contract LibUser {
    function doSomething() external {
        Lib.doSomething(1, 2);
    }
}
