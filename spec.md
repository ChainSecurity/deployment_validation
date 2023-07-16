# DVF Specification

This specification first defines the file format, later how validation is performed and what validation results are. One DVF is generated per address.

## DVF File Format

DVF is saved as a JSON file.

| Option | Description |
| --- | --- |
| `version` | Show file differences that haven't been staged |
| `id` | DVF ID, a hash of the DVF without `references` and `sig_data` |
| `contract_name` | Name of Contract |
| `address` | Contract Address |
| `chain_id` | Chain ID |
| `deployment_block_num` | Block Number of Contract Deployment |
| `codehash` | Contract's Code Hash |
| `insecure` | Boolean Flag, labels Contract as insecure, optional |
| `critical_storage_variables` | List of Critical Storage Variables, optional, each entry has the following parts |
| - `slot` | Storage Slot of the Variable |
| - `offset` | Offset within Storage Slot |
| - `var_name` | Human Readable name, e.g. `balances[0x1234]` |
| - `value` | Hex-encoded string, starting with "0x", contains between 1 and 32 bytes |
| `critical_events` | List of Critical Events, optional, each entry has the following parts |
| - `sig` | Human Readable signature, e.g. `Transfer(address,address,uint256)` |
| - `topic0` | Hex-encoded string, starting with "0x", of topic0 |
| - `occurrences` | Historic list of event occurrences, each entry has the following parts |
| - - `topics` | List of topics, hex-encoded strings, starting with "0x" |
| - - `data` | Event data, hex-encoded string, starting with "0x" |
| `expiry_in_epoch_seconds` | Expiry date of validity, optional, Specified as unix timestamp |
| `references` | List of References to other DVF by their `id` that this DVF depends on, optional |
| `unvalidated` | A collection of unvalidated metadata, optional |
| - `author_name` | DVF Author Name, optional |
| - `description` | A short description of the deployment, optional |
| - `hardfork` | A list of strings, each string is a hardfork name, indicates which hardforks this DVF is valid for, optional |
| - `audit_report` | URL of the audit report, optional |
| - `source_url` | URL of the code repo, should be with tag or commit, optional |
| `signature` | A digital signature, optional, contains the following parts |
| - `sig_data` | A hex-encoded string of the ECDSA signature |
| - `signer` | Address of signer |


## DVF Validation

The following inputs must be provided to the validation:

1. DVF File
2. Validation block number, representing at which block the validity should be checked, optional, if not specified it is the latest block
3. If unsigned DVFs are acceptable, and if not, the list of trusted signers

The following steps must be performed during validation:

1. Check DVF version
2. Recompute ID and compare, fail with `Invalid` if different
3. If signature is present:
   1. Validate signature is correct and from specified signer
   2. Validate that signer is trusted
4. If expiry date has been set compare to timestamp of validation block, if expired fail with `NoDVFFound`
5. If the signature is not present:
   1. Check that unsigned DVFs are acceptable, fail with `Invalid` otherwise
6. Check the code hash, fail if different
7. For each critical storage variable:
   1. Load the value of the slot at the given offset at the validation block
   2. Compare to the saved value, fail with `Invalid` if different
8. For each critical event: 
   1. Search all event occurrences between the deployment block and the validation block
   2. Compare the list to the known occurrences, fail if different
9. If references are set
   1. Search referenced DVF by `id` locally and by pulling all trusted DVFs from the registry
   2. Validate depth-first, thereby avoid following cycles
   3. If the validation of any referenced DVF fails or if any referenced DVF cannot be found, fail with `Invalid`
10. If the `insecure` flag has been set, fail with `Insecure`
11. Return `Valid` as Validation Result

## DVF Validation Results

The pontential results of a DVF validation are:

| Result | Description |
| --- | --- |
| Valid | All checks passed |
| Invalid | At least one of the following has changed: `codehash`, `critical_storage_variables`, `critical_events` |
| NoDVFFound | For the contract in question or for one of the references no (or only an expired) DVF was found |
| Insecure | This contract is insecure and should not be used |
| Error | Some processing error, e.g., events could not be obtained |

DVF Validation Results might require further aggregation, as multiple DVFs might exist for the same address. The aggregated result is as follows:

| Aggregated Result | Description |
| --- | --- |
| Insecure | If at least one result was Insecure |
| Invalid | If no Insecure and no Valid results exist, and at least one Invalid result exists |
| Valid | If at least one Valid exists and no Insecure exists |
| NoDVFFound | If no results were found or all results were NoDVFFound |
| Error | If only Errors occured during Validation |







