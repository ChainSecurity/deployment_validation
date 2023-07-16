## Updating an existing DVF

In some cases and existing DVF should be updated. One example would be a [proxy DVF](./proxy.md) where the implementation is supposed to be upgraded to a new implementation. For such cases there is:

```
dvf update <DVF_PATH>
```

Here, the following operations will take place:

1. Modified critical storage variables are pointed out to the author
2. Additional critical events are highlighted
3. A new adapted DVF is proposed by the tool

This new DVF should be checked by the author. 

- Are all storage changes as expected?
- Are all additional events as expected?
- Should new storage variables be added as they are now critical?
- Should new events be added as they are now critical?
- Can elements be removed from the DVF as they are no longer critical?


