#!/usr/bin/env bash
set -euo pipefail

# asn extension setup: Rust crates plus the wasm32 target and
# wasm-bindgen-test-runner used by AsnCodec JS round-trip tests.
# Idempotent via a stamp under .make/.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$ROOT/.." && pwd)"
# shellcheck source=scripts/lib/stamp.sh
. "$REPO_ROOT/scripts/lib/stamp.sh"

WASM_TARGET="wasm32-unknown-unknown"
# Keep in lockstep with workspace wasm-bindgen.
WASM_BINDGEN_CLI_VERSION="0.2.126"

STAMP="$STAMP_DIR/setup-asn.hash"
MANIFESTS=(
	"$ROOT/scripts/setup.sh"
	"$ROOT/package.json"
	"$ROOT/package-lock.json"
	"$REPO_ROOT/Cargo.toml"
	"$REPO_ROOT/Cargo.lock"
	"$REPO_ROOT/rust-toolchain.toml"
)

setup_required() {
	if [ ! -d "$ROOT/node_modules" ]; then
		return 0
	fi
	if ! rustup target list --installed | grep -qx "$WASM_TARGET"; then
		return 0
	fi
	if ! command -v wasm-bindgen-test-runner >/dev/null 2>&1; then
		return 0
	fi
	stamp_stale "$STAMP" "${MANIFESTS[@]}"
}

install_npm_workspace() {
	echo "Installing asn npm workspace (npm ${NPM_INSTALL_CMD})..."
	# shellcheck disable=SC2086
	(cd "$ROOT" && npm "$NPM_INSTALL_CMD" ${NPM_INSTALL_FLAGS:-})
}

install_wasm_test_tooling() {
	echo "Installing asn wasm test tooling..."
	rustup target add "$WASM_TARGET"

	if ! command -v wasm-bindgen-test-runner >/dev/null 2>&1; then
		echo "Installing wasm-bindgen-cli ${WASM_BINDGEN_CLI_VERSION}..."
		cargo install wasm-bindgen-cli --version "$WASM_BINDGEN_CLI_VERSION" --locked
	fi
}

main() {
	acquire_lock
	trap release_lock EXIT

	if setup_required; then
		install_wasm_test_tooling
		install_npm_workspace
		write_stamp "$STAMP" "${MANIFESTS[@]}"
		echo "asn setup complete."
	else
		echo "asn setup already up to date."
	fi
}

main
