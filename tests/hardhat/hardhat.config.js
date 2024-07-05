require("@nomicfoundation/hardhat-toolbox");

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: "0.8.21",
  networks: {
    anvil: {
      url: "http://127.0.0.1:8556",
      accounts: ["0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"]
    },
  },
  defaultNetwork: "anvil"
};
