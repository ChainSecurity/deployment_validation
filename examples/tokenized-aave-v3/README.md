## Generate DVFs

```
cargo run --bin dvf init --address 0xeAb4AdB3BE28FfF9a50bB4bfaFACe919aE318ABf --project ./examples/tokenized-aave-v3/ --contractname AaveV3LenderFactory --chainid 43114 AaveV3LenderFactory.dvf
cargo run --bin dvf init --address 0x6E6d8E6778D0a2D6Da38940cB5d4Cc06AB56c84B --project ./examples/tokenized-aave-v3/ --contractname AaveV3Lender --implementation TokenizedStrategy --chainid 43114 AaveV3Lender.dvf
```
