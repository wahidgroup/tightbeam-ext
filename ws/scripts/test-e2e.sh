#!/usr/bin/env bash
set -euo pipefail

# ws e2e lanes against the running stack: the Playwright browser suite,
# then the node lane against the same echo servers. Expects the stack
# variables that scripts/test-e2e.sh (which owns the stack) exports from the
# env file, which the suites read under their own names.
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
