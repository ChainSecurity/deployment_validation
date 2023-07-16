## Creating a DVF for a simple contract

The workflow is as follows, initially the user calls:
```
dvf init
```

This generates an empty file looking like:
```json
{
  "version": "0.9.0",
  "contract_name": "",
  "address": "",
  "chain_id": 1
}
```

Here, the user enters Contract Name, Address and Chain ID. Then the user calls:

```
dvf dump --project <PATH> --initblock <BLOCKNUM>
```

Firstly, this performs a bytecode check based on the on-chain code and the locally compiled code from the project path. If the code contains immutables, these immutables are listed and decoded. This steps fails in case the locally compiled bytecode does not match the on-chain bytecode.

Then this command dumps all the relevant information into the DVF. The dumped information includes:

- The code hash
- All storage variables and their value at the specified block number. These storage variables are decoded for easier understanding and the entries look like this:
    ```json
    {
      "slot": "0x255734dd274e3cb2f163891b4adcca22bfe16f8e3d43dbcfc38ef172ec0a632c",
      "offset": 0,
      "var_name": "strategyIsWhitelistedForDeposit[0x93c4b944d05dfe6df7645a86cd2206016c51564d]",
      "value": "0x01"
    }
    ```
    On the command line additional information is provided about the storage variables.
- All events which occurred up the specified block number. An example entry looks like this:
    ```json
    {
      "sig": "AdminChanged(address,address)",
      "topic0": "0x7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f",
      "occurrences": [
        {
          "topics": [
            "0x7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f"
          ],
          "data": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000008b9566ada63b64d1e1dcf1418b43fd1433b72444"
        }
      ]
    }
    ```
    On the command line extra information is available, for example:
    ```
    +---------------------------------------------------------------------------------------------------------------------------------+
    | AdminChanged(address,address)                                                                                                   |
    +---------------------------------------------------------------------------------------------------------------------------------+
    | - (previousAdmin = 0x0000000000000000000000000000000000000000, newAdmin = 0x8b9566ada63b64d1e1dcf1418b43fd1433b72444)           |
    ```

Then the DVF author decides which storage variables and which events are critical based on the contract's logic and simply deletes the others from the DVF.

Finally, if desired the DVF author can decide to digitally sign the DVF, using:
```
dvf sign <DVF_FILE_PATH>
```
