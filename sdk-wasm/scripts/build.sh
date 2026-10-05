#!/usr/bin/env bash
set -euo pipefail
sdk_root="$(dirname "$(dirname "$(realpath "$0")")")"
repo_root="$(dirname "$sdk_root")"
target_root="${CARGO_TARGET_DIR:-$repo_root/target}"
locked_version=$(python3 - "$repo_root/Cargo.lock" <<'PYCODE'
import sys,tomllib
lock=tomllib.load(open(sys.argv[1], 'rb'))
print(next(p['version'] for p in lock['package'] if p['name']=='wasm-bindgen'))
PYCODE
)
if [[ "$(wasm-bindgen --version)" != "wasm-bindgen $locked_version" ]]; then
  echo "wasm-bindgen CLI must match locked crate $locked_version" >&2
  exit 1
fi
cargo build --locked --manifest-path "$repo_root/Cargo.toml" --release -p mosaic-sdk-wasm --target wasm32-unknown-unknown
for target in nodejs web; do
  destination=node
  [[ "$target" == web ]] && destination=web
  wasm-bindgen "$target_root/wasm32-unknown-unknown/release/mosaic_sdk_wasm.wasm" --target "$target" --out-dir "$sdk_root/generated/$destination" --out-name mosaic_sdk_wasm
 done
# Node generated CommonJS lives inside an ESM package: make its extension explicit.
mv "$sdk_root/generated/node/mosaic_sdk_wasm.js" "$sdk_root/generated/node/mosaic_sdk_wasm.cjs"
mv "$sdk_root/generated/node/mosaic_sdk_wasm.d.ts" "$sdk_root/generated/node/mosaic_sdk_wasm.d.cts"
"$sdk_root/node_modules/.bin/tsc" --project "$sdk_root/tsconfig.json"

python3 "$sdk_root/scripts/provenance.py"
