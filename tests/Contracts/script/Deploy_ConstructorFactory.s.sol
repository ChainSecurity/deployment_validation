pragma solidity ^0.8.12;

import "forge-std/Script.sol";
import "../src/ConstructorFactory.sol";

contract Deploy is Script {
    function run() external {
        uint256 anvilDefaultKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        vm.startBroadcast(anvilDefaultKey);

        ConstructorFactory factory = new ConstructorFactory();
        factory.createChild(100);
        factory.createChild(200);

        for (uint256 i = 0; i < 5; i++) {
            factory.dummy();
        }

        vm.stopBroadcast();
    }
}
