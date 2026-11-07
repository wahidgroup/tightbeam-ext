#!/usr/bin/env bash
set -euo pipefail

# pubsub e2e lanes against the running stack: the Playwright live-board
# suite, then the node suite, both driving the pub/sub demo server.
# Expects the stack variables that scripts/test-e2e.sh exports from the env
# file, which the suites read under their own names.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ ! -d "$ROOT/node_modules" ]; then
	echo "ERROR: workspace dependencies not installed; run 'make setup pubsub'" >&2
	exit 1
fi

cd "$ROOT/tests"

echo "==> pubsub browser lane (Playwright live board)"
npx playwright test

echo "==> pubsub node lane (vitest against the pubsub demo server)"
npm run test:node
