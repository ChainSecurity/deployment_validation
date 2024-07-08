// SPDX-License-Identifier: agpl-3.0
pragma solidity >=0.6.12;

/**
 * @title IRewardsDistributor
 * @author Aave
 * @notice Defines the basic interface for a Rewards Distributor.
 */
interface IRewardsDistributor {
    /**
     * @dev Emitted when the configuration of the rewards of an asset is updated.
     * @param asset The address of the incentivized asset
     * @param reward The address of the reward token
     * @param oldEmission The old emissions per second value of the reward distribution
     * @param newEmission The new emissions per second value of the reward distribution
     * @param oldDistributionEnd The old end timestamp of the reward distribution
     * @param newDistributionEnd The new end timestamp of the reward distribution
     * @param assetIndex The index of the asset distribution
     */
    event AssetConfigUpdated(
        address indexed asset,
        address indexed reward,
        uint256 oldEmission,
        uint256 newEmission,
        uint256 oldDistributionEnd,
        uint256 newDistributionEnd,
        uint256 assetIndex
    );

    /**
     * @dev Emitted when rewards of an asset are accrued on behalf of a user.
     * @param asset The address of the incentivized asset
     * @param reward The address of the reward token
     * @param user The address of the user that rewards are accrued on behalf of
     * @param assetIndex The index of the asset distribution
     * @param userIndex The index of the asset distribution on behalf of the user
     * @param rewardsAccrued The amount of rewards accrued
     */
    event Accrued(
        address indexed asset,
        address indexed reward,
        address indexed user,
        uint256 assetIndex,
        uint256 userIndex,
        uint256 rewardsAccrued
    );

    /**
     * @dev Emitted when the emission manager address is updated.
     * @param oldEmissionManager The address of the old emission manager
     * @param newEmissionManager The address of the new emission manager
     */
    event EmissionManagerUpdated(
        address indexed oldEmissionManager,
        address indexed newEmissionManager
    );

    /**
     * @dev Sets the end date for the distribution
     * @param asset The asset to incentivize
     * @param reward The reward token that incentives the asset
     * @param newDistributionEnd The end date of the incentivization, in unix time format
     **/
    function setDistributionEnd(
        address asset,
        address reward,
        uint32 newDistributionEnd
    ) external;

    /**
     * @dev Sets the emission per second of a set of reward distributions
     * @param asset The asset is being incentivized
     * @param rewards List of reward addresses are being distributed
     * @param newEmissionsPerSecond List of new reward emissions per second
     */
    function setEmissionPerSecond(
        address asset,
        address[] calldata rewards,
        uint88[] calldata newEmissionsPerSecond
    ) external;

    /**
     * @dev Gets the end date for the distribution
     * @param asset The incentivized asset
     * @param reward The reward token of the incentivized asset
     * @return The timestamp with the end of the distribution, in unix time format
     **/
    function getDistributionEnd(
        address asset,
        address reward
    ) external view returns (uint256);

    /**
     * @dev Returns the index of a user on a reward distribution
     * @param user Address of the user
     * @param asset The incentivized asset
     * @param reward The reward token of the incentivized asset
     * @return The current user asset index, not including new distributions
     **/
    function getUserAssetIndex(
        address user,
        address asset,
        address reward
    ) external view returns (uint256);

    /**
     * @dev Returns the configuration of the distribution reward for a certain asset
     * @param asset The incentivized asset
     * @param reward The reward token of the incentivized asset
     * @return The index of the asset distribution
     * @return The emission per second of the reward distribution
     * @return The timestamp of the last update of the index
     * @return The timestamp of the distribution end
     **/
    function getRewardsData(
        address asset,
        address reward
    ) external view returns (uint256, uint256, uint256, uint256);

    /**
     * @dev Returns the list of available reward token addresses of an incentivized asset
     * @param asset The incentivized asset
     * @return List of rewards addresses of the input asset
     **/
    function getRewardsByAsset(
        address asset
    ) external view returns (address[] memory);

    /**
     * @dev Returns the list of available reward addresses
     * @return List of rewards supported in this contract
     **/
    function getRewardsList() external view returns (address[] memory);

    /**
     * @dev Returns the accrued rewards balance of a user, not including virtually accrued rewards since last distribution.
     * @param user The address of the user
     * @param reward The address of the reward token
     * @return Unclaimed rewards, not including new distributions
     **/
    function getUserAccruedRewards(
        address user,
        address reward
    ) external view returns (uint256);

    /**
     * @dev Returns a single rewards balance of a user, including virtually accrued and unrealized claimable rewards.
     * @param assets List of incentivized assets to check eligible distributions
     * @param user The address of the user
     * @param reward The address of the reward token
     * @return The rewards amount
     **/
    function getUserRewards(
        address[] calldata assets,
        address user,
        address reward
    ) external view returns (uint256);

    /**
     * @dev Returns a list all rewards of a user, including already accrued and unrealized claimable rewards
     * @param assets List of incentivized assets to check eligible distributions
     * @param user The address of the user
     * @return The list of reward addresses
     * @return The list of unclaimed amount of rewards
     **/
    function getAllUserRewards(
        address[] calldata assets,
        address user
    ) external view returns (address[] memory, uint256[] memory);

    /**
     * @dev Returns the decimals of an asset to calculate the distribution delta
     * @param asset The address to retrieve decimals
     * @return The decimals of an underlying asset
     */
    function getAssetDecimals(address asset) external view returns (uint8);

    /**
     * @dev Returns the address of the emission manager
     * @return The address of the EmissionManager
     */
    function getEmissionManager() external view returns (address);

    /**
     * @dev Updates the address of the emission manager
     * @param emissionManager The address of the new EmissionManager
     */
    function setEmissionManager(address emissionManager) external;
}

/**
 * @title IRewardsController
 * @author Aave
 * @notice Defines the basic interface for a Rewards Controller.
 */
interface IRewardsController is IRewardsDistributor {
    /**
     * @dev Emitted when a new address is whitelisted as claimer of rewards on behalf of a user
     * @param user The address of the user
     * @param claimer The address of the claimer
     */
    event ClaimerSet(address indexed user, address indexed claimer);

    /**
     * @dev Emitted when rewards are claimed
     * @param user The address of the user rewards has been claimed on behalf of
     * @param reward The address of the token reward is claimed
     * @param to The address of the receiver of the rewards
     * @param claimer The address of the claimer
     * @param amount The amount of rewards claimed
     */
    event RewardsClaimed(
        address indexed user,
        address indexed reward,
        address indexed to,
        address claimer,
        uint256 amount
    );

    /**
     * @dev Emitted when a transfer strategy is installed for the reward distribution
     * @param reward The address of the token reward
     * @param transferStrategy The address of TransferStrategy contract
     */
    event TransferStrategyInstalled(
        address indexed reward,
        address indexed transferStrategy
    );

    /**
     * @dev Emitted when the reward oracle is updated
     * @param reward The address of the token reward
     * @param rewardOracle The address of oracle
     */
    event RewardOracleUpdated(
        address indexed reward,
        address indexed rewardOracle
    );

    /**
     * @dev Whitelists an address to claim the rewards on behalf of another address
     * @param user The address of the user
     * @param claimer The address of the claimer
     */
    function setClaimer(address user, address claimer) external;

    /**
     * @dev Get the price aggregator oracle address
     * @param reward The address of the reward
     * @return The price oracle of the reward
     */
    function getRewardOracle(address reward) external view returns (address);

    /**
     * @dev Returns the whitelisted claimer for a certain address (0x0 if not set)
     * @param user The address of the user
     * @return The claimer address
     */
    function getClaimer(address user) external view returns (address);

    /**
     * @dev Returns the Transfer Strategy implementation contract address being used for a reward address
     * @param reward The address of the reward
     * @return The address of the TransferStrategy contract
     */
    function getTransferStrategy(
        address reward
    ) external view returns (address);

    /**
     * @dev Called by the corresponding asset on any update that affects the rewards distribution
     * @param user The address of the user
     * @param userBalance The user balance of the asset
     * @param totalSupply The total supply of the asset
     **/
    function handleAction(
        address user,
        uint256 userBalance,
        uint256 totalSupply
    ) external;

    /**
     * @dev Claims reward for a user to the desired address, on all the assets of the pool, accumulating the pending rewards
     * @param assets List of assets to check eligible distributions before claiming rewards
     * @param amount The amount of rewards to claim
     * @param to The address that will be receiving the rewards
     * @param reward The address of the reward token
     * @return The amount of rewards claimed
     **/
    function claimRewards(
        address[] calldata assets,
        uint256 amount,
        address to,
        address reward
    ) external returns (uint256);

    /**
     * @dev Claims reward for a user on behalf, on all the assets of the pool, accumulating the pending rewards. The
     * caller must be whitelisted via "allowClaimOnBehalf" function by the RewardsAdmin role manager
     * @param assets The list of assets to check eligible distributions before claiming rewards
     * @param amount The amount of rewards to claim
     * @param user The address to check and claim rewards
     * @param to The address that will be receiving the rewards
     * @param reward The address of the reward token
     * @return The amount of rewards claimed
     **/
    function claimRewardsOnBehalf(
        address[] calldata assets,
        uint256 amount,
        address user,
        address to,
        address reward
    ) external returns (uint256);

    /**
     * @dev Claims reward for msg.sender, on all the assets of the pool, accumulating the pending rewards
     * @param assets The list of assets to check eligible distributions before claiming rewards
     * @param amount The amount of rewards to claim
     * @param reward The address of the reward token
     * @return The amount of rewards claimed
     **/
    function claimRewardsToSelf(
        address[] calldata assets,
        uint256 amount,
        address reward
    ) external returns (uint256);

    /**
     * @dev Claims all rewards for a user to the desired address, on all the assets of the pool, accumulating the pending rewards
     * @param assets The list of assets to check eligible distributions before claiming rewards
     * @param to The address that will be receiving the rewards
     * @return rewardsList List of addresses of the reward tokens
     * @return claimedAmounts List that contains the claimed amount per reward, following same order as "rewardList"
     **/
    function claimAllRewards(
        address[] calldata assets,
        address to
    )
        external
        returns (address[] memory rewardsList, uint256[] memory claimedAmounts);

    /**
     * @dev Claims all rewards for a user on behalf, on all the assets of the pool, accumulating the pending rewards. The caller must
     * be whitelisted via "allowClaimOnBehalf" function by the RewardsAdmin role manager
     * @param assets The list of assets to check eligible distributions before claiming rewards
     * @param user The address to check and claim rewards
     * @param to The address that will be receiving the rewards
     * @return rewardsList List of addresses of the reward tokens
     * @return claimedAmounts List that contains the claimed amount per reward, following same order as "rewardsList"
     **/
    function claimAllRewardsOnBehalf(
        address[] calldata assets,
        address user,
        address to
    )
        external
        returns (address[] memory rewardsList, uint256[] memory claimedAmounts);

    /**
     * @dev Claims all reward for msg.sender, on all the assets of the pool, accumulating the pending rewards
     * @param assets The list of assets to check eligible distributions before claiming rewards
     * @return rewardsList List of addresses of the reward tokens
     * @return claimedAmounts List that contains the claimed amount per reward, following same order as "rewardsList"
     **/
    function claimAllRewardsToSelf(
        address[] calldata assets
    )
        external
        returns (address[] memory rewardsList, uint256[] memory claimedAmounts);
}
