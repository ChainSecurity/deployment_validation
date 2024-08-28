# Configuration File

The configuration file is a JSON file that stores information used to generate dvf files; this includes parameters like RPC URLs, API keys, and trusted signers.
When running the `dvf` command, the default configuration file is expected at `$HOME/.dvf_config.json`. Otherwise, its path can be specified using the `-c` option.

| Field | Description |
| --- | --- |
| `rpc_urls` | Mapping from chain ID to RPC URL |
| `dvf_storage` | Folder where DVFs are stored |
| `trusted_signers`: | List of addresses of trusted signers |
| `etherscan_api_key` | Mapping from chain ID to Etherscan API Key, free plan sufficient, optional | 
| `blockscout_api_key` | Mapping from chain ID to Blockscout API Key, free plan sufficient, optional |
| `etherscan_test_api_url` | Only for testing, optional | 
| `blockscout_test_api_url` | Only for testing, optional | 
| `max_blocks_per_event_query` | Number of blocks that can be queried at once in `getLogs`, optional |
| `web3_timeout` | Timeout is seconds for web3 RPC queries, optional |
| `signer` | Configuration on how to sign, optional |
| - `wallet_address` | Address which is used to sign |
| - `wallet_type` | Can have different structure |
| - - `secret_key` | If secret key is used, hex string |
| - - `ledger_type` | If ledger is used, "LedgerLive" or "Legacy" |
| - - `ledger_index` | If ledger is used, Ledger Index to use |



