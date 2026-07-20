#!/usr/bin/env bash
set -euo pipefail

# Audit the Rust workspace (cargo audit) and the npm workspace (npm audit).
# Mode: AUDIT_MODE=fix runs `npm audit fix`; cargo audit is check-only.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODE="${AUDIT_MODE:-check}"

cd "$ROOT"

echo "Running security audit (mode: ${MODE})..."

echo "Auditing Rust workspace (cargo audit)..."
cargo audit

echo "Auditing npm workspace..."
cd "$ROOT/ws"
if [ "$MODE" = "fix" ]; then
	npm audit fix
else
	npm audit --audit-level=high
fi
