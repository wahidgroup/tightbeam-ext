#!/usr/bin/env bash
set -euo pipefail

# ws e2e lanes against the running stack: the Playwright browser suite,
# then the node lane against the same echo servers. Expects the E2E_*
# endpoints exported by scripts/test-e2e.sh (which owns the stack).
#
# Options (environment, set by the Makefile):
#   E2E_UI=1     interactive Playwright UI mode
#   E2E_TRACE=1  force Playwright traces
#   E2E_DEBUG=1  verbose list reporter

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The e2e package (tests/) is an npm workspace member, so its dependencies
# are hoisted to the npm root (ws/) rather than living under tests/node_modules.
if [ ! -d "$ROOT/node_modules/@playwright/test" ]; then
	echo "ERROR: workspace dependencies not installed; run 'make setup ws'" >&2
	exit 1
fi

# Map this extension's E2E_* names from the exported stack variables.
export E2E_ECHO_WS_MUX_ENDPOINT="$ECHO_WS_MUX_ENDPOINT"
export E2E_ECHO_WS_MUX_CLEAR_ENDPOINT="$ECHO_WS_MUX_CLEAR_ENDPOINT"
export E2E_ECHO_WS_MUX_MUTUAL_ENDPOINT="$ECHO_WS_MUX_MUTUAL_ENDPOINT"
export E2E_ECHO_WS_MUX_DUPLEX_ENDPOINT="$ECHO_WS_MUX_DUPLEX_ENDPOINT"
export E2E_CERT_DIR="$CERT_DIR"

cd "$ROOT/tests"

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

echo "==> ws browser lane (Playwright)"
npx playwright test ${ARGS[@]+"${ARGS[@]}"}

echo "==> ws node lane (vitest against the same echo servers)"
npm run test:node
