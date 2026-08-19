#!/usr/bin/env bash

# Run `scripts/publish.sh --dry-run` from the root of the repository to
# check if everything is ready for publishing. Then remove --dry-run to
# actually publish all crates on https://crates.io/

declare -a crates=(
	"json-digest"
	"mosaic-keyvault"
	"mosaic-vault"
	"mosaic-did-types"
	"mosaic-sdk"
)

for crate in "${crates[@]}"; do
    cargo publish -p "$crate" "$@"
done
