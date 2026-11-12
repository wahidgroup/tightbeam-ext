#!/usr/bin/env bash
set -euo pipefail

# The ws e2e lanes against the running stack, with the stack variables that
# scripts/test-e2e.sh exports: the Playwright browser suite, then the node lane.
#
# The Makefile sets these options in the environment:
# - E2E_UI=1 runs the interactive Playwright UI mode.
# - E2E_TRACE=1 forces Playwright traces.
# - E2E_DEBUG=1 selects the verbose list reporter.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The e2e package (tests/) is an npm workspace member, so its dependencies
# sit at the npm root (ws/).
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
