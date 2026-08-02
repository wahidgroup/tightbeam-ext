#!/usr/bin/env bash
set -euo pipefail

# E2E orchestration: bring the shared dockerized stack up, export the
# endpoint environment, run each selected project's own e2e lanes
# (<project>/scripts/test-e2e.sh), then tear the stack down.
#
# Usage: test-e2e.sh [project...]   (default: every project)
#
# Options (environment, set by the Makefile):
#   E2E_UI=1     interactive Playwright UI mode (ws)
#   E2E_TRACE=1  force Playwright traces (ws)
#   E2E_DEBUG=1  verbose list reporter (ws)

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

REPO_ROOT="$ROOT"
# shellcheck source=scripts/lib/projects.sh
. "$ROOT/scripts/lib/projects.sh"

selection="$(select_projects "$@")"
mapfile -t PROJECTS <<< "$selection"

if ! command -v docker >/dev/null 2>&1; then
	echo "ERROR: docker not available; the e2e servers run in containers" >&2
	exit 1
fi

cleanup() {
	"$ROOT/scripts/stack.sh" down e2e || true
}
trap cleanup EXIT

"$ROOT/scripts/stack.sh" up e2e

# Export the raw stack variables.
ENV_FILE="$("$ROOT/scripts/stack.sh" env e2e)"
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

for project in "${PROJECTS[@]}"; do
	"$ROOT/$project/scripts/test-e2e.sh"
done
