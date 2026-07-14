#!/usr/bin/env bash
set -eux

run_format()      { zepter format features; }
run_propagate()   { zepter lint propagate-feature --feature std,runtime-benchmarks,try-runtime --workspace; }
run_fmt()         { cargo fmt --check; }
run_deny()        { cargo deny check --hide-inclusion-graph; }
run_clippy()      { cargo clippy --workspace --all-targets --no-deps -- -D warnings; }
run_test()        { cargo test --workspace; }
run_nostd()       { cargo check -p pallet-mosaic-did --no-default-features; }

if [ $# -eq 0 ]; then
    STEPS=(format propagate fmt deny clippy test nostd)
else
    STEPS=("$@")
fi

for step in "${STEPS[@]}"; do
    "run_${step}"
done
