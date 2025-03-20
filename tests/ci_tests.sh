#!/bin/bash
set -ex

# Can use env with "set -a && source .env && set +a" for testing
#export RUSTFLAGS='-D warnings'   # This flag makes pipeline fail on warnings
pkill geth || true
pkill anvil || true
pkill cached_proxy || true
rm -rf /tmp/uni-factory /tmp/usdc_implementation2
cargo build
cargo clippy
mkdir -p /tmp/dvfs
if [ "$REBUILD_CACHE" = "1" ]; then
    echo "Rebuilding Cache"
    cargo run --bin cached_proxy -- -d tests/cachedrpc -u $RPC_MAINNET &
    cargo run --bin cached_proxy -- -d tests/cachedrpc -p 5001 -u "https://eth.blockscout.com" &
    cargo run --bin cached_proxy -- -d tests/cachedrpc -p 5002 -u "https://api.etherscan.io/api" &
else
    echo "Using Cache"
    cargo run --bin cached_proxy -- -d tests/cachedrpc -p 5001 &
    cargo run --bin cached_proxy -- -d tests/cachedrpc -p 5002 &
    cargo run --bin cached_proxy -- -d tests/cachedrpc &
fi
cd tests/Contracts && forge build && cd -
cd tests/with_metadata && forge build && cd -
cd tests/hardhat && yarn install -y && npx hardhat compile && cd -
cd tests/hardhat_2_0 && yarn install -y && npx hardhat compile && cd -
RUST_BACKTRACE=1 cargo test 
envsubst < tests/config.json > /tmp/eval_config.json
cargo run --bin fetch-from-etherscan -- -c  /tmp/eval_config.json --address 0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f --project /tmp/uni-factory
cargo run --bin dv --  --config  /tmp/eval_config.json init --address 0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f --project /tmp/uni-factory --chainid 1 --factory --contractname UniswapV2Factory UniswapV2Factory_0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f.dvf.json
# TODO: Parse output
cargo run --bin dv -- -c  /tmp/eval_config.json generate-build-cache --project /tmp/uni-factory
cargo run --bin dv -- --verbose --verbose --config  /tmp/eval_config.json init --address 0x5e8422345238f34275888049021821e8e08caa1f --contractname frxETH --project examples/frxETH-public --initblock 15728402 examples/dvfs/frx_out.dvf.json
cargo run --bin dv -- --config  /tmp/eval_config.json sign examples/dvfs/frxETH_filtered.dvf.json
cargo run --bin dv -- --config  /tmp/eval_config.json validate --validationblock  15729502 examples/dvfs/frxETH_filtered.dvf.json
cargo run --bin dv -- --config  /tmp/eval_config.json validate --validationblock  15740402  examples/dvfs/CErc20Delegator_0x5d3a536E4D6DbD6114cc1Ead35777bAB948E3643.dvf.json || touch should_fail
rm should_fail # Check that it failed
cargo run --bin dv -- --config  /tmp/eval_config.json update --validationblock  15740402  examples/dvfs/CErc20Delegator_0x5d3a536E4D6DbD6114cc1Ead35777bAB948E3643.dvf.json
cargo run --bin dv -- --config  /tmp/eval_config.json sign examples/dvfs/CErc20Delegator_0x5d3a536E4D6DbD6114cc1Ead35777bAB948E3643_updated.dvf.json
cargo run --bin dv -- --config  /tmp/eval_config.json validate --validationblock  15740402  examples/dvfs/CErc20Delegator_0x5d3a536E4D6DbD6114cc1Ead35777bAB948E3643_updated.dvf.json
# Make sure libraries work
cargo run --bin fetch-from-etherscan -- --config  /tmp/eval_config.json --address 0x43506849D7C04F9138D1A2050bbF3A0c054402dd --project /tmp/usdc_implementation2
cargo run --bin dv -- -c  /tmp/eval_config.json init --address 0x43506849D7C04F9138D1A2050bbF3A0c054402dd --project /tmp/usdc_implementation2 --chainid 1 --contractname FiatTokenV2_2 FiatTokenV2_2_0x43506849D7C04F9138D1A2050bbF3A0c054402dd.dvf.json
#    - echo "DAI Tests"
#    - cargo run --bin fetch-from-etherscan -- --config tests/test_config.json --project /tmp/dai --address 0x6b175474e89094c44da98b954eedeac495271d0f
#    - cargo run --bin dv -- --config tests/test_config.json init --address 0x6b175474e89094c44da98b954eedeac495271d0f --project /tmp/dai --chainid 1 --contractname Dai Dai_0x6b175474e89094c44da98b954eedeac495271d0f.dvf.json
#    - \[ `cat Dai_0x6b175474e89094c44da98b954eedeac495271d0f.dvf.json | jq '.codehash'` == "\"0x4e36f96ee1667a663dfaac57c4d185a0e369a3a217e0079d49620f34f85d1ac7\"" \]
#    - cat Dai_0x6b175474e89094c44da98b954eedeac495271d0f.dvf.json | jq -c '.critical_events = []' > filtere.dvf.jsoni.dvf
#    - cargo run --bin dv -- --config tests/test_config.json sign filtered_dai.dvf.json
#    - cargo run --bin dv -- --config tests/test_config.json validate filtered_dai.dvf.json || touch should_fail # Should fail
#    - rm should_fail
#    - cargo run --bin dv -- --config tests/test_config.json update filtered_dai.dvf.json
#    - cargo run --bin dv -- --config tests/test_config.json id filtered_dai_updated.dvf.json
#    - cargo run --bin dv -- --config tests/test_config.json validate filtered_dai_updated.dvf.json || touch should_fail # Should fail
#    - rm should_fail
#    - cargo run --bin dv -- --config tests/test_config.json validate --allowuntrusted filtered_dai_updated.dvf.json 
#    - cargo run --bin dv -- --config tests/test_config.json sign filtered_dai_updated.dvf.json
#    - cargo run --bin dv -- --config tests/test_config.json validate filtered_dai_updated.dvf.json 
pkill cached_proxy
pkill geth || true
pkill anvil || true
