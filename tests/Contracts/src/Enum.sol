// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract Enum {
    enum Status {
        Pending,
        Canceled,
        Executed,
        Executing
    }

    enum A {
        B,
        C,
        D
    }

    Status s;
    A[3] a;

    constructor() {
        s = Status.Canceled;
        a[0] = A.B;
        a[2] = A.D;
    }

    function f() external {
        a[1] = A.C;
    }

    function g() external {
        s = Status.Executing;
        a[2] = A.B;
    }

    function dummy() external {}
}
