#!/usr/bin/env bash
set -euo pipefail

# wire has no transport e2e lane. Each socket kind runs the rules against a
# real peer in its own suites: ws, ws-wasm, and grpc.

echo "==> wire has no e2e lane; skipping"
