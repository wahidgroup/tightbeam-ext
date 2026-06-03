#!/usr/bin/env bash
set -euo pipefail

# Run the self-contained e2e example against a dockerized echo server, then tear
# it down. Hard-fails when e2e deps are missing or docker is unavailable.
#
# Flags: --ui (interactive), --trace (force traces), --verbose (list reporter).

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The e2e package is an npm workspace member, so its dependencies are hoisted
# to the workspace root rather than living under e2e/node_modules.
if [ ! -d "$ROOT/node_modules/@playwright/test" ]; then
	echo "ERROR: workspace dependencies not installed; run 'make setup'" >&2
	exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
	echo "ERROR: docker not available; the e2e echo server runs in a container" >&2
	exit 1
fi

cleanup() {
	"$ROOT/scripts/stack.sh" down e2e || true
}
trap cleanup EXIT

"$ROOT/scripts/stack.sh" up e2e

ENV_FILE="$("$ROOT/scripts/stack.sh" env e2e)"
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

export E2E_ECHO_WS_ENDPOINT="$ECHO_WS_ENDPOINT"

cd "$ROOT/e2e"

ARGS=()
for arg in "$@"; do
	case "$arg" in
		--ui)      ARGS+=(--ui) ;;
		--trace)   ARGS+=(--trace on) ;;
		--verbose) ARGS+=(--reporter=list) ;;
	esac
done

npx playwright test ${ARGS[@]+"${ARGS[@]}"}
