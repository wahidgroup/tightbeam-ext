#!/usr/bin/env bash
set -euo pipefail

# pubsub extension setup: the npm workspace (subscription manager client
# and its e2e tests). Idempotent via a stamp under .make/.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$ROOT/.." && pwd)"
# shellcheck source=scripts/lib/stamp.sh
. "$REPO_ROOT/scripts/lib/stamp.sh"

STAMP="$STAMP_DIR/setup-pubsub.hash"
MANIFESTS=(
	"$ROOT/package.json"
	"$ROOT/package-lock.json"
	"$ROOT/scripts/setup.sh"
)

setup_required() {
	if [ ! -d "$ROOT/node_modules" ]; then
		return 0
	fi
	stamp_stale "$STAMP" "${MANIFESTS[@]}"
}

install_npm_workspace() {
	echo "Installing pubsub npm workspace (npm ${NPM_INSTALL_CMD})..."
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
		install_npm_workspace
		write_stamp "$STAMP" "${MANIFESTS[@]}"
		echo "pubsub setup complete."
	else
		echo "pubsub setup already up to date."
	fi
}

main
