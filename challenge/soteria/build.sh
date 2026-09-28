#!/usr/bin/env bash

# Rebuild the client and server modules and copy them next to this script so
# go:embed can see them, then minify js/ into static/. Both modules come from
# one cargo invocation, so they share an opcode numbering
# (SOTERIA_OPCODE_SEED, if set).

set -euo pipefail

cd "$(dirname "$0")"

root="$(git rev-parse --show-toplevel)"
out="${root}/target/wasm32-unknown-unknown/release"

(cd "${root}" && cargo build --release -p soteria-client -p soteria-server --target wasm32-unknown-unknown)

cp "${out}/soteria_client.wasm" "${out}/soteria_server.wasm" static/

# es2020 for BigInt (the fingerprint is a u64) and ??. Every browser with
# WASM SIMD, which the client module needs, is newer than that.
for file in js/*.js; do
	esbuild "${file}" --minify --target=es2020 --outfile="static/${file#js/}" --log-level=warning
done
