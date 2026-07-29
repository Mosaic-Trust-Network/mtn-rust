#!/usr/bin/env bash
set -eux

run_format()      { zepter format features; }
run_propagate()   { zepter lint propagate-feature --feature std,runtime-benchmarks,try-runtime --workspace; }
run_fmt()         { cargo fmt --check; }
run_deny()        { cargo deny check --hide-inclusion-graph; }
run_clippy()      { cargo clippy --workspace --all-targets --no-deps -- -D warnings; }
run_test()        { cargo test --workspace ${TEST_FILTER:+-- "$TEST_FILTER"}; }
run_serde-test()  { cargo test --workspace --features serde ${TEST_FILTER:+-- "$TEST_FILTER"}; }
run_nostd() { cargo check -p pallet-mosaic-did --no-default-features --target wasm32-unknown-unknown; }

if [ $# -eq 0 ]; then
    STEPS=(format propagate fmt deny clippy test serde-test nostd)
else
    STEPS=("$@")
fi

for step in "${STEPS[@]}"; do
    if [[ "$step" == test:* ]]; then
        TEST_FILTER="${step#test:}"
        step="test"
    elif [[ "$step" == serde-test:* ]]; then
        TEST_FILTER="${step#serde-test:}"
        step="serde-test"
    else
        unset TEST_FILTER
    fi
    "run_${step}"
done
