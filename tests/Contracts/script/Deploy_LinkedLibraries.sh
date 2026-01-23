#!/bin/bash
# deploy.sh

set -e

ANVIL_DEF_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
RPC_URL=$1

LIB_ADDR1=$(forge create src/linked_libraries/SimpleMath.sol:SimpleMath \
  --private-key $ANVIL_DEF_PRIVATE_KEY \
  --rpc-url $RPC_URL \
  --chain-id 31337 \
  --broadcast \
  --json | jq -r .deployedTo)

echo "Deployed SimpleMath to: $LIB_ADDR1"

LIB_ADDR2=$(forge create src/linked_libraries/SimpleNumber.sol:SimpleNumber \
  --private-key $ANVIL_DEF_PRIVATE_KEY \
  --rpc-url $RPC_URL \
  --chain-id 31337 \
  --broadcast \
  --json | jq -r .deployedTo)

echo "Deployed SimpleNumber to: $LIB_ADDR2"

# Step 3: Run the Solidity script to deploy Calculator
CALCULATOR_ADDR=$(forge create src/linked_libraries/Calculator.sol:Calculator \
  --private-key $ANVIL_DEF_PRIVATE_KEY \
  --rpc-url $RPC_URL \
  --chain-id 31337 \
  --libraries src/linked_libraries/SimpleMath.sol:SimpleMath:$LIB_ADDR1 \
  --libraries src/linked_libraries/SimpleNumber.sol:SimpleNumber:$LIB_ADDR2 \
  --broadcast \
  --json | jq -r .deployedTo)

echo "Deployed Calculator to: $CALCULATOR_ADDR"