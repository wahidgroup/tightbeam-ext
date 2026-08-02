#!/usr/bin/env bash
set -euo pipefail

# Audit the Rust workspace (cargo audit) and each selected project's npm
# workspace (npm audit).
#
# Usage: audit.sh [project...]   (default: every project)
# Mode: AUDIT_MODE=fix runs `npm audit fix`; cargo audit is check-only.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODE="${AUDIT_MODE:-check}"

REPO_ROOT="$ROOT"
# shellcheck source=scripts/lib/projects.sh
. "$ROOT/scripts/lib/projects.sh"

selection="$(select_projects "$@")"
mapfile -t PROJECTS <<< "$selection"

cd "$ROOT"

echo "Running security audit (mode: ${MODE})..."

echo "Auditing Rust workspace (cargo audit)..."
cargo audit

for project in "${PROJECTS[@]}"; do
	echo "Auditing npm workspace ($project)..."
	cd "$ROOT/$project"
	if [ "$MODE" = "fix" ]; then
		npm audit fix
	else
		npm audit --audit-level=high
	fi
done
