#!/usr/bin/env bash
set -euo pipefail

# The asn setup, which installs the npm workspace, and the wasm-bindgen CLI at
# the version that Cargo.lock resolves: docs/development.md (Projects).

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$ROOT/.." && pwd)"
# shellcheck source=scripts/lib/stamp.sh
. "$REPO_ROOT/scripts/lib/stamp.sh"

STAMP="$STAMP_DIR/setup-asn.hash"
MANIFESTS=(
	"$ROOT/scripts/setup.sh"
	"$ROOT/package.json"
	"$ROOT/package-lock.json"
	"$REPO_ROOT/Cargo.toml"
	"$REPO_ROOT/Cargo.lock"
)

# The version of the wasm-bindgen library that Cargo.lock resolves. The CLI
# MUST be the same version, because it reads the schema the library writes.
required_wasm_bindgen() {
	local versions
	versions="$(cargo metadata --format-version 1 --manifest-path "$REPO_ROOT/Cargo.toml" \
		| jq -r '[.packages[] | select(.name == "wasm-bindgen") | .version] | unique | .[]')"
	if [ -z "$versions" ] || [ "$versions" != "${versions%%$'\n'*}" ]; then
		echo "ERROR: Cargo.lock resolves no single wasm-bindgen version (got: ${versions:-none})." >&2
		exit 1
	fi

	printf '%s' "$versions"
}

# The version of the installed wasm-bindgen CLI, or nothing.
installed_wasm_bindgen() {
	if command -v wasm-bindgen >/dev/null 2>&1; then
		wasm-bindgen --version | awk '{ print $2 }'
	fi
}

setup_required() {
	if [ ! -d "$ROOT/node_modules" ]; then
		return 0
	fi
	if [ "$(installed_wasm_bindgen)" != "$WASM_BINDGEN_VERSION" ]; then
		return 0
	fi
	stamp_stale "$STAMP" "${MANIFESTS[@]}"
}

install_npm_workspace() {
	echo "Installing asn npm workspace (npm ${NPM_INSTALL_CMD})..."
	# shellcheck disable=SC2086
	(cd "$ROOT" && npm "$NPM_INSTALL_CMD" ${NPM_INSTALL_FLAGS:-})
}

install_wasm_bindgen() {
	if [ "$(installed_wasm_bindgen)" = "$WASM_BINDGEN_VERSION" ]; then
		return 0
	fi

	echo "Installing wasm-bindgen-cli ${WASM_BINDGEN_VERSION}, the version Cargo.lock resolves..."
	cargo install wasm-bindgen-cli --version "$WASM_BINDGEN_VERSION" --locked
}

main() {
	acquire_lock
	trap release_lock EXIT

	WASM_BINDGEN_VERSION="$(required_wasm_bindgen)"
	if setup_required; then
		install_wasm_bindgen
		install_npm_workspace
		write_stamp "$STAMP" "${MANIFESTS[@]}"
		echo "asn setup complete."
	else
		echo "asn setup already up to date."
	fi
}

main
