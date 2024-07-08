// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.18;

import {IStrategy} from "@tokenized-strategy/interfaces/IStrategy.sol";
import {IUniswapV3Swapper} from "@periphery/swappers/interfaces/IUniswapV3Swapper.sol";

interface IStrategyInterface is IStrategy, IUniswapV3Swapper {
    function dontSell(address) external view returns (bool);

    function setMinAmountToSell(uint256 _minAmountToSell) external;

    function setDontSell(address _token, bool _sell) external;

    function sellRewardManually(address _token) external;
}
