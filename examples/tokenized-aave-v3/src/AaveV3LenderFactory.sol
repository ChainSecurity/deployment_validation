// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.18;

import {AaveV3Lender} from "./AaveV3Lender.sol";

interface IStrategy {
    function setPerformanceFeeRecipient(address) external;

    function setKeeper(address) external;

    function setPendingManagement(address) external;
}

contract AaveV3LenderFactory {
    event NewAaveV3Lender(address indexed strategy, address indexed asset);

    constructor(address _asset, string memory _name) {
        newAaveV3Lender(_asset, _name, msg.sender, msg.sender, msg.sender);
    }

    /**
     * @notice Deploye a new Aave V3 Lender.
     * @dev This will set the msg.sender to all of the permisioned roles.
     * @param _asset The underlying asset for the lender to use.
     * @param _name The name for the lender to use.
     * @return . The address of the new lender.
     */
    function newAaveV3Lender(
        address _asset,
        string memory _name
    ) external returns (address) {
        return
            newAaveV3Lender(_asset, _name, msg.sender, msg.sender, msg.sender);
    }

    /**
     * @notice Deploye a new Aave V3 Lender.
     * @dev This will allow custom roles to be set after deployment.
     * @param _asset The underlying asset for the lender to use.
     * @param _name The name for the lender to use.
     * @param _performanceFeeRecipient The address to receive performance fees.
     * @param _keeper The address to set as the keeper.
     * @param _management The address to own the lender.
     * @return . The address of the new lender.
     */
    function newAaveV3Lender(
        address _asset,
        string memory _name,
        address _performanceFeeRecipient,
        address _keeper,
        address _management
    ) public returns (address) {
        // We need to use the custom interface with the
        // tokenized strategies available setters.
        IStrategy newStrategy = IStrategy(
            address(new AaveV3Lender(_asset, _name))
        );

        newStrategy.setPerformanceFeeRecipient(_performanceFeeRecipient);

        newStrategy.setKeeper(_keeper);

        newStrategy.setPendingManagement(_management);

        emit NewAaveV3Lender(address(newStrategy), _asset);
        return address(newStrategy);
    }
}
