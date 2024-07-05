// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.18;

import {AprOracleBase} from "@periphery/AprOracle/AprOracleBase.sol";

contract StrategyAprOracle is AprOracleBase {
    constructor() AprOracleBase("Strategy Apr Oracle Example") {}

    /**
     * @notice Will return the expected Apr of a strategy post a debt change.
     * @dev _delta is a signed integer so that it can also repersent a debt
     * decrease.
     *
     * This should return the annual expected return at the current timestamp
     * repersented as 1e18.
     *
     *      ie. 10% == 1e17
     *
     * _delta will be == 0 to get the current apr.
     *
     * This will potentially be called during non-view functions so gas
     * effeciency should be taken into account.
     *
     * @param _asset The token to get the apr for.
     * @param _delta The difference in debt.
     * @return . The expected apr for the strategy repersented as 1e18.
     */
    function aprAfterDebtChange(
        address _asset,
        int256 _delta
    ) external view override returns (uint256) {
        // TODO: Implement any neccesary logic to return the most accurate
        //      APR estimation for the strategy.
        return 1e17;
    }
}
