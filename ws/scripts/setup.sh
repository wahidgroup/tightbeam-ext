#!/usr/bin/env bash
set -euo pipefail

# The ws setup, which installs the npm workspace, the Playwright chromium, and
# wasm-pack: docs/development.md (Projects).

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$ROOT/.." && pwd)"
# shellcheck source=scripts/lib/stamp.sh
. "$REPO_ROOT/scripts/lib/stamp.sh"

STAMP="$STAMP_DIR/setup-ws.hash"
MANIFESTS=(
	"$ROOT/package.json"
	"$ROOT/package-lock.json"
	"$ROOT/scripts/setup.sh"
)

setup_required() {
	if [ ! -d "$ROOT/node_modules" ]; then
		return 0
	fi
	if ! command -v wasm-pack >/dev/null 2>&1; then
		return 0
	fi
	stamp_stale "$STAMP" "${MANIFESTS[@]}"
}

install_wasm_tooling() {
	if ! command -v wasm-pack >/dev/null 2>&1; then
		echo "Installing wasm-pack..."
		cargo install wasm-pack --locked
	fi
}

install_npm_workspace() {
	echo "Installing ws npm workspace (npm ${NPM_INSTALL_CMD})..."
	# shellcheck disable=SC2086
	(cd "$ROOT" && npm "$NPM_INSTALL_CMD" ${NPM_INSTALL_FLAGS:-})

	echo "Installing Playwright chromium..."
	if [ "$NPM_INSTALL_CMD" = "ci" ]; then
		(cd "$ROOT/tests" && npx playwright install --with-deps chromium)
	else
		(cd "$ROOT/tests" && npx playwright install chromium)
	fi
}

main() {
	acquire_lock
	trap release_lock EXIT

	if setup_required; then
		install_wasm_tooling
		install_npm_workspace
		write_stamp "$STAMP" "${MANIFESTS[@]}"
		echo "ws setup complete."
	else
		echo "ws setup already up to date."
	fi
}

main
