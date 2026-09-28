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

# The mobile request classifier (github.com/TecharoHQ/mobile-request-classifier).
# Its URL is overwritten on every upload, so pin the hash: a different module
# could change who gets the phone discount. Bump both together.
classifier_url="https://pkgs.techaro.lol/wasm/mobile_request_classifier.wasm"
classifier_sha256="30ca236715c6dda90efcd4d01a20e00d57ed364c422b0a8ff4fa0bfd685ac75b"
classifier="static/mobile_request_classifier.wasm"

sha256() {
	if command -v sha256sum >/dev/null; then
		sha256sum "$1" | cut -d' ' -f1
	else
		shasum -a 256 "$1" | cut -d' ' -f1
	fi
}

if [ ! -f "${classifier}" ] || [ "$(sha256 "${classifier}")" != "${classifier_sha256}" ]; then
	curl -sSfL -o "${classifier}.tmp" "${classifier_url}"
	got="$(sha256 "${classifier}.tmp")"
	if [ "${got}" != "${classifier_sha256}" ]; then
		rm -f "${classifier}.tmp"
		echo "build.sh: ${classifier_url} has sha256 ${got}, want ${classifier_sha256}" >&2
		exit 1
	fi
	mv "${classifier}.tmp" "${classifier}"
fi
