pragma solidity ^0.8.12;

import "forge-std/Script.sol";
import "../src/BytesMapping.sol";

contract S is Script {
    uint256 x;
    uint256 y;

    function run() external {
        uint256 anvilSecondKey = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;
        //uint256 ganacheDefaultKey = 0x0cc0c2de7e8c30525b4ca3b9e0b9703fb29569060d403261055481df7014f7fa;
        vm.startBroadcast(anvilSecondKey);
        address payable recipient = payable(0x1234567890AbcdEF1234567890aBcdef12345678);

        // Send exactly 1 wei
        (bool success,) = recipient.call{value: 1 wei}("");
        vm.stopBroadcast();
    }
}
