#!/usr/bin/env bash
set -euo pipefail

# Run the self-contained e2e example against a dockerized echo server, then tear
# it down. Hard-fails when e2e deps are missing or docker is unavailable.
#
# Options (environment, set by the Makefile):
#   E2E_UI=1     interactive Playwright UI mode
#   E2E_TRACE=1  force Playwright traces
#   E2E_DEBUG=1  verbose list reporter

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The e2e package (ws/tests) is an npm workspace member, so its dependencies
# are hoisted to the npm root (ws/) rather than living under tests/node_modules.
if [ ! -d "$ROOT/ws/node_modules/@playwright/test" ]; then
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
export E2E_ECHO_WS_SECURE_ENDPOINT="$ECHO_WS_SECURE_ENDPOINT"
export E2E_ECHO_WS_MUTUAL_ENDPOINT="$ECHO_WS_MUTUAL_ENDPOINT"
export E2E_ECHO_WS_SINK_ENDPOINT="$ECHO_WS_SINK_ENDPOINT"
export E2E_CERT_DIR="$CERT_DIR"

cd "$ROOT/ws/tests"

ARGS=()
if [ -n "${E2E_UI:-}" ]; then
	ARGS+=(--ui)
fi
if [ -n "${E2E_TRACE:-}" ]; then
	ARGS+=(--trace on)
fi
if [ -n "${E2E_DEBUG:-}" ]; then
	ARGS+=(--reporter=list)
fi

npx playwright test ${ARGS[@]+"${ARGS[@]}"}

echo "==> Node lane (vitest against the same echo servers)"
npm run test:node
