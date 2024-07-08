// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.18;

import {BaseTokenizedStrategy} from "@tokenized-strategy/BaseTokenizedStrategy.sol";

import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {IAToken} from "./interfaces/Aave/V3/IAtoken.sol";
import {IStakedAave} from "./interfaces/Aave/V3/IStakedAave.sol";
import {IPool} from "./interfaces/Aave/V3/IPool.sol";
import {IProtocolDataProvider} from "./interfaces/Aave/V3/IProtocolDataProvider.sol";
import {IRewardsController} from "./interfaces/Aave/V3/IRewardsController.sol";

import {IUniswapV2Router02} from "./interfaces/uniswap/IUniswapV2Router02.sol";

contract AaveV3Lender is BaseTokenizedStrategy {
    using SafeERC20 for ERC20;

    // WAVAX
    address internal constant BASE = 0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7;
    // The pool to deposit and withdraw through.
    IPool public constant lendingPool =
        IPool(0x794a61358D6845594F94dc1DB02A252b5b4814aD);

    // Uni V2 router to sell rewards through.
    IUniswapV2Router02 public constant router =
        IUniswapV2Router02(0x60aE616a2155Ee3d9A68541Ba4544862310933d4);

    // The a Token specific rewards contract for claiming rewards.
    IRewardsController public immutable rewardsController;

    // The token that we get in return for deposits.
    IAToken public immutable aToken;

    // Mapping to be set by management for any reward tokens
    // that should not or can not be sold. This can be used
    // if selling a reward token is reverting to allow for
    // reports to still work properly.
    mapping(address => bool) public dontSell;

    // Minimum amount of rewards the strategy will try and sell.
    uint256 public minAmountToSell;

    constructor(
        address _asset,
        string memory _name
    ) BaseTokenizedStrategy(_asset, _name) {
        // Set the aToken based on the asset we are using.
        aToken = IAToken(lendingPool.getReserveData(_asset).aTokenAddress);

        // Make sure its a real token.
        require(address(aToken) != address(0), "!aToken");

        // Set the rewards controller
        rewardsController = aToken.getIncentivesController();

        // Make approve the lending pool for cheaper deposits.
        ERC20(_asset).safeApprove(address(lendingPool), type(uint256).max);

        // Set uni swapper values
        minAmountToSell = 1e10;
    }

    /**
     * @notice Set the min amount to sell.
     * @dev External function available to management to set
     * the `minAmountToSell` variable in the `UniswapV3Swapper`.
     *
     * @param _minAmountToSell The min amount of tokens to sell.
     */
    function setMinAmountToSell(
        uint256 _minAmountToSell
    ) external onlyManagement {
        minAmountToSell = _minAmountToSell;
    }

    /*//////////////////////////////////////////////////////////////
                NEEDED TO BE OVERRIDEN BY STRATEGIST
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Should deploy up to '_amount' of 'asset' in the yield source.
     *
     * This function is called at the end of a {deposit} or {mint}
     * call. Meaning that unless a whitelist is implemented it will
     * be entirely permsionless and thus can be sandwhiched or otherwise
     * manipulated.
     *
     * @param _amount The amount of 'asset' that the strategy should attemppt
     * to deposit in the yield source.
     */
    function _deployFunds(uint256 _amount) internal override {
        lendingPool.supply(asset, _amount, address(this), 0);
    }

    /**
     * @dev Will attempt to free the '_amount' of 'asset'.
     *
     * The amount of 'asset' that is already loose has already
     * been accounted for.
     *
     * Should do any needed parameter checks, '_amount' may be more
     * than is actually available.
     *
     * This function is called {withdraw} and {redeem} calls.
     * Meaning that unless a whitelist is implemented it will be
     * entirely permsionless and thus can be sandwhiched or otherwise
     * manipulated.
     *
     * Should not rely on asset.balanceOf(address(this)) calls other than
     * for diff accounting puroposes.
     *
     * @param _amount, The amount of 'asset' to be freed.
     */
    function _freeFunds(uint256 _amount) internal override {
        // We dont check available liquidity because we need the tx to
        // revert if there is not enough liquidity so we dont improperly
        // pass a loss on to the user withdrawing.
        lendingPool.withdraw(
            asset,
            Math.min(aToken.balanceOf(address(this)), _amount),
            address(this)
        );
    }

    /**
     * @dev Internal function to harvest all rewards, redeploy any idle
     * funds and return an accurate accounting of all funds currently
     * held by the Strategy.
     *
     * This should do any needed harvesting, rewards selling, accrual,
     * redepositing etc. to get the most accurate view of current assets.
     *
     * NOTE: All applicable assets including loose assets should be
     * accounted for in this function.
     *
     * Care should be taken when relying on oracles or swap values rather
     * than actual amounts as all Strategy profit/loss accounting will
     * be done based on this returned value.
     *
     * This can still be called post a shutdown, a strategist can check
     * `TokenizedStrategy.isShutdown()` to decide if funds should be
     * redeployed or simply realize any profits/losses.
     *
     * @return _totalAssets A trusted and accurate account for the total
     * amount of 'asset' the strategy currently holds including idle funds.
     */
    function _harvestAndReport()
        internal
        override
        returns (uint256 _totalAssets)
    {
        if (!TokenizedStrategy.isShutdown()) {
            // Claim and sell any rewards to `asset`.
            _claimAndSellRewards();

            // deposit any loose funds
            uint256 looseAsset = ERC20(asset).balanceOf(address(this));
            if (looseAsset > 0) {
                lendingPool.supply(asset, looseAsset, address(this), 0);
            }
        }

        _totalAssets =
            aToken.balanceOf(address(this)) +
            ERC20(asset).balanceOf(address(this));
    }

    /**
     * @notice Used to claim any pending rewards and sell them to asset.
     */
    function _claimAndSellRewards() internal {
        //claim all rewards
        address[] memory assets = new address[](1);
        assets[0] = address(aToken);
        (address[] memory rewardsList, ) = rewardsController
            .claimAllRewardsToSelf(assets);

        //swap as much as possible back to want
        address token;
        for (uint256 i = 0; i < rewardsList.length; ++i) {
            token = rewardsList[i];

            if (token == asset || dontSell[token]) {
                continue;
            } else {
                _swapFrom(
                    token,
                    asset,
                    ERC20(token).balanceOf(address(this)),
                    0
                );
            }
        }
    }

    function _swapFrom(
        address _from,
        address _to,
        uint256 _amountIn,
        uint256 _amountOut
    ) internal {
        if (_amountIn <= minAmountToSell) return;

        _checkAllowance(address(router), _from, _amountIn);

        router.swapExactTokensForTokens(
            _amountIn,
            _amountOut,
            _getTokenOutPath(_from, _to),
            address(this),
            block.timestamp
        );
    }

    function _getTokenOutPath(
        address _tokenIn,
        address _tokenOut
    ) internal pure returns (address[] memory _path) {
        bool isNative = _tokenIn == BASE || _tokenOut == BASE;
        _path = new address[](isNative ? 2 : 3);
        _path[0] = _tokenIn;

        if (isNative) {
            _path[1] = _tokenOut;
        } else {
            _path[1] = BASE;
            _path[2] = _tokenOut;
        }
    }

    function _checkAllowance(
        address _contract,
        address _token,
        uint256 _amount
    ) internal {
        if (ERC20(_token).allowance(address(this), _contract) < _amount) {
            ERC20(_token).approve(_contract, 0);
            ERC20(_token).approve(_contract, _amount);
        }
    }

    /**
     * @notice Allows `management` to manually swap a token the strategy holds.
     * @dev This can be used if the rewards controller has since removed a reward
     * token so the normal harvest flow doesnt work. Or for retroactive airdrops.
     * @param _token The address of the token to sell.
     */
    function sellRewardManually(address _token) external onlyManagement {
        uint256 balance = ERC20(_token).balanceOf(address(this));
        // Swap from will do min check
        _swapFrom(_token, asset, balance, 0);
    }

    /**
     * @notice Set the `dontSell` mapping for a specific `_token`.
     * @dev This can be used by management to adjust wether or not the
     * _calimAndSellRewards() function will attempt to sell a specific
     * reward token. This can be used if liquidity is to low, amounts
     * are to low or any other reason that may cause reverts.
     *
     * @param _token The address of the token to adjust.
     * @param _sell Bool to set the mapping to for `_token`.
     */
    function setDontSell(address _token, bool _sell) external onlyManagement {
        dontSell[_token] = _sell;
    }

    /**
     * @dev Optional function for a strategist to override that will
     * allow management to manually withdraw deployed funds from the
     * yield source if a strategy is shutdown.
     *
     * This should attempt to free `_amount`, noting that `_amount` may
     * be more than is currently deployed.
     *
     * NOTE: This will not realize any profits or losses. A seperate
     * {report} will be needed in order to record any profit/loss. If
     * a report may need to be called after a shutdown it is important
     * to check if the strategy is shutdown during {_harvestAndReport}
     * so that it does not simply re-deploy all funds that had been freed.
     *
     * EX:
     *   if(freeAsset > 0 && !TokenizedStrategy.isShutdown()) {
     *       depositFunds...
     *    }
     *
     * @param _amount The amount of asset to attempt to free.
     */
    function _emergencyWithdraw(uint256 _amount) internal override {
        lendingPool.withdraw(asset, _amount, address(this));
    }
}
