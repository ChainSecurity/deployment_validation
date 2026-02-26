// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract Child {
    address public owner;
    uint256 public value;

    constructor(address _owner, uint256 _value) {
        owner = _owner;
        value = _value;
    }

    function setValue(uint256 _value) external {
        value = _value;
    }
}

contract ConstructorFactory {
    address[] public children;

    constructor() {
        Child child = new Child(msg.sender, 42);
        children.push(address(child));
    }

    function createChild(uint256 _value) external returns (address) {
        Child child = new Child(msg.sender, _value);
        children.push(address(child));
        return address(child);
    }

    function getChildrenCount() external view returns (uint256) {
        return children.length;
    }

    function dummy() external {}
}
