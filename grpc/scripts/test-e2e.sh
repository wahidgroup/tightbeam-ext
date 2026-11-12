#!/usr/bin/env bash
set -euo pipefail

# The grpc e2e lane, against the stack that the root scripts/test-e2e.sh runs.
# That script exports GRPC_ENVOY_HOST_PORT, GRPC_ENVOY_ADMIN_HOST_PORT,
# GRPC_COUPLED_HOST_PORT, and CERT_DIR.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT"

echo "==> grpc hop lane (Envoy)"
cargo test -p tightbeam-grpc --features e2e --test hop

echo "==> grpc stock lane (grpcurl through the coupled edge)"
cargo test -p tightbeam-grpc --features e2e --test stock
