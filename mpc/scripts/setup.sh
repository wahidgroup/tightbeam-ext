#!/usr/bin/env bash
set -euo pipefail

# mpc extension setup: the adapter is a pure Rust crate with no npm
# workspace, so the shared toolchain installed by the root setup.sh is
# all it needs.

echo "mpc setup: nothing beyond the shared Rust toolchain."
