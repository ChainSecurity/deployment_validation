pragma solidity ^0.8.12;

import "forge-std/Script.sol";
import "../src/BytesMapping.sol";

contract S is Script {
    uint256 x;
    uint256 y;

    function run() external {
        uint256 anvilDefaultKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        //uint256 ganacheDefaultKey = 0x0cc0c2de7e8c30525b4ca3b9e0b9703fb29569060d403261055481df7014f7fa;
        vm.startBroadcast(anvilDefaultKey);
        BytesMapping b = new BytesMapping();
        b.f();
        b.g();
        for (uint256 i = 0; i < 20; i++) {
            b.dummy();
            // Waste some time here
            for (uint256 j = 0; j < 10; j++) {
                y = x;
            }
        }
        vm.stopBroadcast();
    }
}
