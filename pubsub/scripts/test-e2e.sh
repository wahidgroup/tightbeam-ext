#!/usr/bin/env bash
set -euo pipefail

# pubsub e2e lanes against the running stack: the Playwright live-board
# suite, then the node suite, both driving the pub/sub demo server.
# Expects the E2E_* endpoints exported by scripts/test-e2e.sh.
#
# The browser lane runs first: the node lane's final test quiesces the
# demo server's registry for good.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ ! -d "$ROOT/node_modules" ]; then
	echo "ERROR: workspace dependencies not installed; run 'make setup pubsub'" >&2
	exit 1
fi

# Map this extension's E2E_* names from the exported stack variables.
export E2E_PUBSUB_WS_ENDPOINT="$PUBSUB_WS_ENDPOINT"
export E2E_PUBSUB_PROCESSED_WS_ENDPOINT="$PUBSUB_PROCESSED_WS_ENDPOINT"
export E2E_PUBSUB_QUEUE_CAPACITY="$PUBSUB_QUEUE_CAPACITY"

cd "$ROOT/tests"

echo "==> pubsub browser lane (Playwright live board)"
npx playwright test

echo "==> pubsub node lane (vitest against the pubsub demo server)"
npm run test:node
