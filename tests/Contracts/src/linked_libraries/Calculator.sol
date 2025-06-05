// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./SimpleMath.sol";
import "./SimpleNumber.sol";

contract Calculator {
    /**
     * @dev Calculates the sum of two numbers using the SimpleMath library.
     */
    function calculateSum(uint256 a, uint256 b) public pure returns (uint256) {
        return SimpleMath.add(a, b);
    }

    function getSimpleNumber() public pure returns (uint256) {
        return SimpleNumber.number();
    }
}