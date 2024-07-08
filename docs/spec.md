# DVF Specification

This specification first defines the file format, later how validation is performed and what validation results are. One DVF is generated per address.

## DVF File Format

DVF is saved as a JSON file.

| Field | Description |
| --- | --- |
| `version` | Show file differences that haven't been staged |
| `id` | DVF ID, a hash of the DVF without `references` and `sig_data` |
| `contract_name` | Name of Contract |
| `address` | Contract Address |
| `chain_id` | Chain ID |
| `deployment_block_num` | Block Number of Contract Deployment |
| `init_block_num` | Block Number when Deployment was completed and State Snapshot was taken |
| `codehash` | Contract's Code Hash |
| `insecure` | Boolean Flag, labels Contract as insecure, optional |
| `critical_storage_variables` | List of Critical Storage Variables, optional, each entry has the following parts |
| - `slot` | Storage Slot of the Variable |
| - `offset` | Offset within Storage Slot |
| - `var_name` | Human Readable name, e.g. `balances[0x1234]`, these are inferred during generation, but can be changed and are not validated |
| - `value` | Hex-encoded string, starting with "0x", contains between 1 and 32 bytes |
| - `value_hint` | Unvalidated additional information about the value, optional |
| `critical_events` | List of Critical Events, optional, each entry has the following parts |
| - `sig` | Human Readable signature, e.g. `Transfer(address,address,uint256)` |
| - `topic0` | Hex-encoded string, starting with "0x", of topic0 |
| - `occurrences` | Historic list of event occurrences, each entry has the following parts |
| - - `topics` | List of topics, hex-encoded strings, starting with "0x" |
| - - `data` | Event data, hex-encoded string, starting with "0x" |
| `expiry_in_epoch_seconds` | Expiry date of validity, optional, Specified as unix timestamp |
| `references` | List of References to other DVFs that this DVF depends on, optional |
|- `id` | `id` of referenced DVF |
|- `contract_name` | Name of referenced contract |
| `unvalidated` | A collection of unvalidated metadata, optional |
| - `author_name` | DVF Author Name, optional |
| - `description` | A short description of the deployment, optional |
| - `hardfork` | A list of strings, each string is a hardfork name, indicates which hardforks this DVF is valid for, optional |
| - `audit_report` | URL of the audit report, optional |
| - `source_url` | URL of the code repo, should be with tag or commit, optional |
| - `security_contact` | Security Contact for project, optional |
| - `implementation_name` | In case of proxy contract, the implementation name, optional |
| - `implementation_address` | In case of proxy contract, the implementation address, optional |
| `signature` | A digital signature, optional, contains the following parts |
| - `sig_data` | A hex-encoded string of the ECDSA signature |
| - `signer` | Address of signer |


## DVF Validation

The following inputs must be provided to the validation:

1. DVF File
2. Validation block number, through `--validationblock`, representing at which block the validity should be checked, optional, if not specified it is the latest block. Please note that this always describes the state at the **beginning** of that block.
3. Whether to allow untrusted or unsigned DVFs, through `--allowuntrusted`, if not only trusted signers are allowed

The following steps must be performed during validation:

1. Check DVF version
2. Recompute ID and compare, fail with `Invalid` if different
3. If `--allowuntrusted` was not used:
   1. Validate signature is present, correct and from specified signer
   2. Validate that signer is trusted
   3. If any of those fail, fail with `NoDVFFound`
4. If expiry date has been set compare to timestamp of validation block, if expired fail with `NoDVFFound`
5. Check the code hash, fail with `Invalid` if different
6. For each critical storage variable:
   1. Load the value of the slot at the given offset at the validation block
   2. Compare to the saved value, fail with `Invalid` if different
7. For each critical event: 
   1. Search all event occurrences between the deployment block and the validation block
   2. Compare the list to the known occurrences, fail if different
8. If references are set
   1. Search referenced DVF by `id` locally
   2. Validate depth-first, thereby avoid following cycles
   3. If multiple DVFs with this `id` are found (should not really happen), aggregate the results per-target, see below for more
   4. Check that the `contract_name` in the DVF matches the `contract_name` of the reference 
   5. Aggregate the results of DVFs from the different ids
9. If the `insecure` flag has been set, fail with `Insecure`
10. Return `Valid` as Validation Result

## DVF Validation Results

The potential results of a DVF validation are:

| Result | Description |
| --- | --- |
| Valid | All checks passed |
| Invalid | At least one of the following has changed: `codehash`, `critical_storage_variables`, `critical_events` |
| NoDVFFound | For the contract in question or for one of the references no (or only an expired) DVF was found |
| Insecure | This contract is insecure and should not be used |
| Error | Some processing error, e.g., events could not be obtained due to network error |

DVF Validation Results might require further aggregation. There are two types of aggregation.

#### Per-Target Aggregation  

This is aggregation is used if multiple DVFs exist for the same address or ID. As an example for a particular address, there might be multiple DVFs, e.g., one pre-upgrade and one post-upgrade.

| Aggregated Result | Description |
| --- | --- |
| Insecure | If at least one result was Insecure |
| Invalid | If no Insecure and no Valid results exist, and at least one Invalid result exists |
| Valid | If at least one Valid exists and no Insecure exists |
| NoDVFFound | If no results were found or all results were NoDVFFound |
| Error | If only Errors occured during Validation |



#### Across-Target Aggregation

This is aggregation is used if a DVF has multiple references and individual results have been obtained for each of these references.


| Aggregated Result | Description |
| --- | --- |
| Insecure | If at least one result was Insecure |
| Invalid | If no Insecure, and at least one Invalid result exists |
| NoDVFFound | If none of the above and at least one result was NoDVFFound |
| Error | If none of the above and at least one result was Error |
| Valid | Else |







