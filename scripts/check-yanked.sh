#!/usr/bin/env bash
set -euo pipefail

# Fail if the named extension's current crate version has been yanked.
# Usage: check-yanked.sh [ext]  (default: ws)

EXT="${1:-ws}"
CRATE_TOML="${EXT}/tightbeam-${EXT}/Cargo.toml"
YANKED_PREFIX="yanked/${EXT}/v"

VERSION=$(awk -F'"' '/^\[package\]/{f=1;next} f&&/^\[/{f=0} f&&/^version/{print $2;exit}' "$CRATE_TOML" 2>/dev/null || echo "")

if [ -n "$VERSION" ] && \
   git ls-remote --tags origin "${YANKED_PREFIX}${VERSION}" 2>/dev/null | grep -q .; then
	printf '  \033[0;31m[error]\033[0m %s version %s has been yanked. Cannot proceed.\n' "$EXT" "$VERSION" >&2
	exit 1
fi
