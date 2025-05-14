# Configuration File

The configuration file is a JSON file that stores information used to generate dvf files; this includes parameters like RPC URLs, API keys, and trusted signers.
When running the `dvf` command, the default configuration file is expected at `$HOME/.dvf_config.json`. Otherwise, its path can be specified using the `-c` option.

| Field | Description |
| --- | --- |
| `rpc_urls` | Mapping from chain ID to RPC URL |
| `dvf_storage` | Folder where DVFs are stored |
| `trusted_signers`: | List of addresses of trusted signers |
| `etherscan_global` | Etherscan configuration for all chains, optional | 
| - `api_url` | Etherscan API URL |
| - `api_key` | Etherscan API Key |
| `etherscan_chain_configs` | Mapping from chain ID to chain-specific Etherscan configuration, optional |
| - Chain ID |
| - - `api_url` | Chain-specific Etherscan API URL |
| - - `api_key` | Chain-specific Etherscan API Key |
| `blockscout_global` | Global Blockscout configuration, optional | 
| - `api_url` | Blockscout API URL |
| - `api_key` | Blockscout API Key |
| `blockscout_chain_configs` | Mapping from chain ID to chain-specific Blockscout configuration, optional |
| - Chain ID |
| - - `api_url` | Chain-specific Blockscout API URL |
| - - `api_key` | Chain-specific Blockscout API Key |
| `max_blocks_per_event_query` | Number of blocks that can be queried at once in `getLogs`, optional, defaults to 9999 |
| `web3_timeout` | Timeout in seconds for web3 RPC queries, optional, defaults to 700 |
| `signer` | Configuration on how to sign, optional |
| - `wallet_address` | Address which is used to sign |
| - `wallet_type` | Can have different structure |
| - - `secret_key` | If secret key is used, hex string |
| - - `ledger_type` | If ledger is used, "LedgerLive" or "Legacy" |
| - - `ledger_index` | If ledger is used, Ledger Index to use |



