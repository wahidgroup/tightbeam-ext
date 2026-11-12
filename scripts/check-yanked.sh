#!/usr/bin/env bash
set -euo pipefail

# Fail if the current version of the named extension has been yanked, or if
# origin cannot answer.
# Usage: check-yanked.sh <ext>

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/lib/extension.sh
. "$REPO_ROOT/scripts/lib/extension.sh"

fail() {
	printf '  \033[0;31m[error]\033[0m %s\n' "$1" >&2
	exit 1
}

EXT="${1:-}"
extension_require "$EXT"

VERSION="$(extension_version "$EXT")"
TAG="$(yanked_tag "$EXT" "$VERSION")"

status=0
git -C "$REPO_ROOT" ls-remote --exit-code --tags origin "refs/tags/${TAG}" >/dev/null 2>&1 || status=$?
case "$status" in
	0) fail "${EXT} version ${VERSION} has been yanked (${TAG}). Cannot proceed." ;;
	2) ;;
	*) fail "Could not query origin for ${TAG} (network or auth error)" ;;
esac
