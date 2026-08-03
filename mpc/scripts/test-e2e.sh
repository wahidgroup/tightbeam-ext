#!/usr/bin/env bash
set -euo pipefail

# mpc e2e lane: the adapter's multi-party integration tests run entirely
# in-process over localhost TCP inside `cargo test`, so there is no
# dockerized lane to drive here.

echo "mpc has no dockerized e2e lane; covered by 'make test mpc'."
