#!/usr/bin/env bash
set -euo pipefail

# Run the e2e lane of each selected project that ships a stack fragment, against one stack.
#
# Usage: test-e2e.sh [project...]   (default: every project)
#
# The Makefile sets these options in the environment:
# - E2E_UI=1 runs the ws lane in Playwright UI mode.
# - E2E_TRACE=1 forces Playwright traces in the ws lane.
# - E2E_DEBUG=1 runs the ws lane with the verbose list reporter.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

REPO_ROOT="$ROOT"
# shellcheck source=scripts/lib/projects.sh
. "$ROOT/scripts/lib/projects.sh"

selection="$(select_projects "$@")"
mapfile -t PROJECTS <<< "$selection"

# A project with a stack fragment (scripts/stack-env.sh) runs its lane (scripts/test-e2e.sh).
LANES=()
for project in "${PROJECTS[@]}"; do
	if [ -f "$ROOT/$project/scripts/stack-env.sh" ]; then
		LANES+=("$project")
	fi
done

if [ "${#LANES[@]}" -eq 0 ]; then
	echo "==> No e2e lane in: ${PROJECTS[*]}"
	exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
	echo "ERROR: docker is not available, and the e2e servers run in containers" >&2
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

for project in "${LANES[@]}"; do
	"$ROOT/$project/scripts/test-e2e.sh"
done
