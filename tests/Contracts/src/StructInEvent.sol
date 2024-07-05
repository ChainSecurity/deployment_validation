// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract StructInEvent {
    struct SiEType {
        uint256 A;
        address B;
        bool C;
        uint64[6] D;
        uint128 E;
    }

    uint256 x;
    SiEType S;

    event Huh(SiEType s);

    constructor() {
        x = 1337;
        S.A = 65;
        S.B = address(0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE);
        S.C = true;
        S.D[1] = 42;
        S.D[5] = 124;
        S.E = 128;
        emit Huh(S);
    }

    function f() external {
        x = 456;
        S.A = 64;
        emit Huh(S);
    }

    function g() external {
        S.D[3] = 3;
        emit Huh(S);
    }

    function dummy() external {}
}
