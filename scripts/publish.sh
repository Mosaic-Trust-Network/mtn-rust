#!/usr/bin/env bash

# Run `scripts/publish.sh --dry-run` from the root of the repository to
# check if everything is ready for publishing. Then remove --dry-run to
# actually publish all crates on https://crates.io/

cargo publish --workspace "$@"
