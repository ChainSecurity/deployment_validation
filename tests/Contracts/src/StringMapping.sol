// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract StringMapping {
    mapping(string => uint256) x;
    mapping(string => string) y;

    event SomeE(string s, uint256 indexed u);

    constructor() {
        x["Hello this is a test"] = 5;
        x["A veryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryvery long string"] = 42;
        y["abc"] = "a short string";
        y["a"] = "A veryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryvery long string.";
        emit SomeE("EventData", 1000);
    }

    function f() external {
        x["abc123"] = 456;
        y["b"] = "c";
    }

    function g() external {
        x["abc123"] = 678;
        x["Hello this is a test"] = 6;
        x["A"] = 100;
        x["escapethis\""] = 100;
    }

    function dummy() external {}
}
