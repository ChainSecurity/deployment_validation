#!/bin/bash
set -ex

cargo fmt -- --check 
forge fmt --check tests/Contracts/src
forge fmt --check tests/Contracts/script

