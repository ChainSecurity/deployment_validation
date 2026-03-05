# Configuration File

The configuration file is a JSON file that stores information used to generate dvf files; this includes parameters like RPC URLs, API keys, and trusted signers.
When running the `dvf` command, the default configuration file is expected at `$HOME/.dv_config.json`. Otherwise, its path can be specified using the `-c` option.

| Field | Description |
| --- | --- |
| `rpc_urls` | Mapping from chain ID to RPC URL |
| `dvf_storage` | Folder where DVFs are stored |
| `trusted_signers` | List of addresses of trusted signers |
| `etherscan_global` | Etherscan configuration for all chains, optional |
| - `api_url` | Etherscan API URL |
| - `api_key` | Etherscan API Key |
| `etherscan_chain_configs` | Mapping from chain ID to chain-specific Etherscan configuration, optional |
| - Chain ID |
| - - `api_url` | Chain-specific Etherscan API URL |
| - - `api_key` | Chain-specific Etherscan API Key |
| `blockscout_global` | Global Blockscout Pro API configuration, optional. One API key works for all chains. |
| - `api_url` | Blockscout Pro API base URL (defaults to `https://api.blockscout.com`) |
| - `api_key` | Blockscout Pro API Key |
| `max_blocks_per_event_query` | Number of blocks that can be queried at once in `getLogs`, optional, defaults to 9999 |
| `web3_timeout` | Timeout in seconds for web3 RPC queries, optional, defaults to 5000 |
| `signer` | Configuration on how to sign, optional |
| - `wallet_address` | Address which is used to sign |
| - `wallet_type` | Can have different structure |
| - - `secret_key` | If secret key is used, hex string |
| - - `ledger_type` | If ledger is used, "LedgerLive" or "Legacy" |
| - - `ledger_index` | If ledger is used, Ledger Index to use |
| `projects` | List of project configurations for the `inspect-tx` command, optional |
| - `project_path` | Path to the root folder of the source code project |
| - `output_path` | Path to the output DVF file |
| - `environment` | Project's development environment, defaults to "Foundry" |
| - `artifacts_path` | Folder containing the project artifacts, defaults to "artifacts" |
| - `build_cache_path` | Folder containing build-info files, optional |
| - `libraries` | Library specifiers in the form Path:Name:Address, optional |
| - `address` | Address of the contract |
| - `chain_id` | Chain ID where the contract is deployed, optional |
| - `contract_name` | Name of the contract |
| - `deployment_tx` | Deployment transaction hash, optional |
| - `factory` | Treat this contract as a factory, which changes bytecode verification, defaults to false |
| - `implementation_config` | Optional implementation project configuration for proxy contracts |
| - - `project_path` | Path to the root folder of the implementation project |
| - - `environment` | Implementation project's development environment, defaults to "Foundry" |
| - - `artifacts_path` | Folder containing the implementation project artifacts, defaults to "artifacts" |
| - - `build_cache_path` | Folder containing the implementation contract's build-info files, optional |
| - - `contract_name` | Name of the implementation contract |
