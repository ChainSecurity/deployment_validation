## Creating a DVF for a proxy contract

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

Here, the user enters the **Proxy** Contract Name, **Proxy** Address and Chain ID. Then the user calls:

```
dvf dump --project <PATH> --initblock <BLOCKNUM> --implementation <IMPLEMENTATION_CONTRACT_NAME>
```

Firstly, this performs a bytecode check for the proxy based on the on-chain code and the locally compiled code from the project path. If the code contains immutables, these immutables are listed and decoded. This steps fails in case the locally compiled bytecode does not match the on-chain bytecode.

Then this command dumps all the relevant information into the DVF. The dumped information includes:

- The code hash
- All storage variables and their value at the specified block number. Here, all storage variables are the union of the variables of the proxy and the variables of the implementation. These storage variables are decoded for easier understanding and the entries look like this:
    ```json
    {
      "slot": "0x255734dd274e3cb2f163891b4adcca22bfe16f8e3d43dbcfc38ef172ec0a632c",
      "offset": 0,
      "var_name": "strategyIsWhitelistedForDeposit[0x93c4b944d05dfe6df7645a86cd2206016c51564d]",
      "value": "0x01"
    }
    ```
    On the command line additional information is provided about the storage variables.
- All events which occurred up the specified block number. Here, the event types of the proxy and the implementation are combined to achieve this. An example entry looks like this:
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

Now the DVF author generates a DVF for the implementation contract. This workflow is as described in the [simple case](./simple.md) and is generally very fast as the storage of the implementation contract is mostly irrelevant. Using the DVF for the implementation contract the author does:

```
dvf sign <IMPLEMENTATION_DVF_FILE_PATH>
```

This will also compute the ID of the Implementation DVF. This ID can now be referenced in the proxy DVF (because it depends on the correctness of the implementation):

```
dvf add-reference --newref <IMPLEMENTATION_DVF_ID> <PROXY_DVF_FILE_PATH>
```

Finally, the author has generated two DVFs, where the Proxy DVF references the Implementation DVF and can complete this by signing the Proxy DVF:

```
dvf sign <PROXY_DVF_FILE_PATH>
```
