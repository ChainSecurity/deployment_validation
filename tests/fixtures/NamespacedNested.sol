// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
contract NamespacedNested {
    struct Inner { uint256[] values; }
    struct Layout { Inner inner; uint256 marker; }
    Layout private compilerReference;
    function layout() internal pure returns (Layout storage s) {
        assembly { s.slot := 0 }
    }
}
