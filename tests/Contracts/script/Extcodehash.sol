pragma solidity ^0.8.12;

import "forge-std/Script.sol";

// Run with forge script script/Extcodehash.sol --rpc-url "https:..." -vvvv

contract C is Script {
    event Codehash(bytes32 hash);

    address dai = 0x6B175474E89094C44Da98b954EedeAC495271d0F;

    function run() external {
        bytes32 b;
        address a = dai;
        assembly {
            b := extcodehash(a)
        }
        emit Codehash(b);
    }
}
