#!/usr/bin/env bash
set -euo pipefail

# grpc e2e lane against the running stack: the hop suite dials the pinned Envoy
# by host name, and every tunnel reaches the grpc work gateway through it. The
# stock suite runs grpcurl against the coupled edge. Expects
# GRPC_ENVOY_HOST_PORT, GRPC_COUPLED_HOST_PORT, and CERT_DIR, which
# scripts/test-e2e.sh (which owns the stack) exports from the env file.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT"

echo "==> grpc hop lane (Envoy)"
cargo test -p tightbeam-grpc --features e2e --test hop

echo "==> grpc stock lane (grpcurl through the coupled edge)"
cargo test -p tightbeam-grpc --features e2e --test stock
