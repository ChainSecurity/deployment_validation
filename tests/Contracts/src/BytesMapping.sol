// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract BytesMapping {
    mapping(bytes => uint256) x;
    bytes b;

    event X(bytes by);
    event Y(bytes by, uint256 someuint);

    constructor() {
        x[bytes("Hello this is a test")] = 5;
        x[bytes("A veryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryvery long string")] = 42;
        b = bytes("Just some normal bytes.");
    }

    function f() external {
        x[bytes("abc123")] = 456;
    }

    function g() external {
        x[bytes("abc123")] = 678;
        x[bytes("Hello this is a test")] = 6;
        x[bytes("A")] = 100;
        emit Y(b, 42);
    }

    function dummy() external {}
}
