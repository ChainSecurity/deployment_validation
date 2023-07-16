## Ensuring Distributed Ownership

In some deployments it is important to ensure that ownership is distributed. For this example let us assume that there is an `Investment` contract, which has an `owner` variable. The `owner` has special powers and the investors want to make sure that the ownership is distributed.
Hence, the `owner` is set to a Safe contract with multi-signature wallet. 

To monitor the distributed ownership, the investors can act as follows:

1. The investors can create a DVF for the Safe, making sure that the threshold for decisions is 3, e.g. a 3-out-of-5 multi-signature wallet.
2. The investors can generate a [Investment DVF](./simple.md) that ensures that the `owner` variable is set to the Safe's address.
3. They can reference the Safe DVF in the Investment DVF to ensure that the Investment's deployment is only valid if the ownership remains distributed.
