pragma solidity ^0.8.12;

import "forge-std/Script.sol";
import {TransparentUpgradeableProxy as TransparentUpgradeableProxy2, ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import "../src/MyToken.sol";

contract S is Script {
    uint256 x;
    uint256 y;

    function run() external {
        uint256 anvilDefaultKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        //uint256 ganacheDefaultKey = 0x0cc0c2de7e8c30525b4ca3b9e0b9703fb29569060d403261055481df7014f7fa;
        vm.startBroadcast(anvilDefaultKey);
        MyToken m = new MyToken();
        bytes memory payload = abi.encodeWithSignature("initialize()");
        address admin = vm.addr(anvilDefaultKey);
        TransparentUpgradeableProxy2 p = new TransparentUpgradeableProxy2(address(m), admin, payload);
        MyToken real = MyToken(address(p));
        for (uint256 i = 0; i < 20; i++) {
            real.dummy();
            // Waste some time here
            for (uint256 i = 0; i < 10; i++) {
                y = x;
            }
        }

        // load admin contract from storage slot
        ProxyAdmin proxyAdmin = ProxyAdmin(address(bytes20(vm.load(address(p), ERC1967Utils.ADMIN_SLOT) << 96)));
        MyTokenV2 m2 = new MyTokenV2();
        proxyAdmin.upgradeAndCall(
            ITransparentUpgradeableProxy(address(p)),
            address(m2),
            abi.encodeCall(MyTokenV2.initialize, ())
        );
        real.dummy();
        

        vm.stopBroadcast();
    }
}
