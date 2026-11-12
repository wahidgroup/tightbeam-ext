#!/usr/bin/env bash
set -euo pipefail

# Verify a release tag against the versions on the tagged ref, and export the
# release facts: docs/development.md (Releases).
#
# Usage: verify-release-tag.sh [ref-name], where the release tag ref-name is $GITHUB_REF_NAME by default.
#
# The exports go to $GITHUB_ENV, or to stdout when it is unset:
# - EXT is the extension directory, such as ws.
# - VERSION is the release version, such as 0.3.0.
# - CRATE is the canonical crate, tightbeam-<ext>.
# - CRATES lists the crates that the release publishes to crates.io, separated by spaces.
# - TITLE is the release title, <crate> v<version>.
# - NPM_CLIENT is the npm name of the client of the extension, and empty when it has none.
# - SBOM is the SBOM asset of the release, and empty when the client ships none.

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/lib/extension.sh
. "$REPO_ROOT/scripts/lib/extension.sh"

REF_NAME="${1:-${GITHUB_REF_NAME:-}}"

fail() {
	printf '  \033[0;31m[error]\033[0m %s\n' "$1" >&2
	exit 1
}

emit_env() {
	if [ -n "${GITHUB_ENV:-}" ]; then
		cat >> "$GITHUB_ENV"
	else
		cat
	fi
}

if [ -z "$REF_NAME" ]; then
	fail "No ref name (pass one or set GITHUB_REF_NAME)"
fi

parsed="$(release_tag_parse "$REF_NAME")"
read -r EXT VERSION <<< "$parsed"
extension_require "$EXT"
CRATE="$(extension_crate "$EXT")"
BUMP="Bump on master via make release ${EXT} version=v${VERSION} before tagging."

mismatches="$(extension_version_mismatches "$EXT" "$VERSION")"
if [ -n "$mismatches" ]; then
	while read -r manifest current; do
		printf '  %s version (%s) does not match tag (%s)\n' "$manifest" "$current" "$VERSION" >&2
	done <<< "$mismatches"
	fail "$BUMP"
fi

publishable="$(extension_publishable_crates "$EXT")"
if [ -z "$publishable" ]; then
	fail "No publishable crates found under ${EXT}/"
fi
if ! grep -qx "$CRATE" <<< "$publishable"; then
	fail "Canonical crate ${CRATE} is not publishable under ${EXT}/"
fi
CRATES="$(tr '\n' ' ' <<< "$publishable")"
CRATES="${CRATES% }"

NPM_CLIENT="$(extension_npm_client "$EXT")"
SBOM=""
if [ -n "$NPM_CLIENT" ]; then
	npm_version="$(extension_npm_version "$EXT")"
	if [ "$npm_version" != "$VERSION" ]; then
		printf '  %s version (%s) does not match tag (%s)\n' "$(extension_npm_manifest "$EXT")" "$npm_version" "$VERSION" >&2
		fail "$BUMP"
	fi
	SBOM="$(extension_npm_sbom "$EXT")"
fi

{
	echo "EXT=$EXT"
	echo "VERSION=$VERSION"
	echo "CRATE=$CRATE"
	echo "CRATES=$CRATES"
	echo "TITLE=${CRATE} v${VERSION}"
	echo "NPM_CLIENT=$NPM_CLIENT"
	echo "SBOM=$SBOM"
} | emit_env
