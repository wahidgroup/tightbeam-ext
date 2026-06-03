#!/usr/bin/env bash
set -euo pipefail

# Fail if the current crate version has been yanked.

CRATE_TOML="Cargo.toml"
YANKED_PREFIX="yanked/v"

VERSION=$(awk -F'"' '/^\[workspace\.package\]/{f=1;next} f&&/^\[/{f=0} f&&/^version/{print $2;exit}' "$CRATE_TOML" 2>/dev/null || echo "")

if [ -n "$VERSION" ] && \
   git ls-remote --tags origin "${YANKED_PREFIX}${VERSION}" 2>/dev/null | grep -q .; then
	printf '  \033[0;31m[error]\033[0m Version %s has been yanked. Cannot proceed.\n' "$VERSION" >&2
	exit 1
fi
