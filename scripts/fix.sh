#!/usr/bin/env bash
set -eux

zepter lint propagate-feature --feature std,runtime-benchmarks,try-runtime --workspace --fix
zepter format features --fix
cargo fmt

echo "Fixed. Run ./scripts/check.sh to verify."
