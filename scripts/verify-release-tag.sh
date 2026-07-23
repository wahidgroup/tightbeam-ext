#!/usr/bin/env bash
set -euo pipefail

# Verify a release tag against the versions committed on the tagged ref
# and export the release facts the workflow steps consume.
#
# Usage: verify-release-tag.sh [ref-name]
#   ref-name  Tag name shaped releases/<ext>/v<version>.
#             Defaults to $GITHUB_REF_NAME (set by GitHub Actions).
#
# Exports (appended to $GITHUB_ENV, stdout when unset for local runs):
#   EXT       Extension directory (e.g. ws)
#   VERSION   Release version (e.g. 0.3.0)
#   CRATE     Crate name (tightbeam-<ext>)
#   TITLE     Release title (<crate> v<version>)
#   HAS_NPM   true when the extension ships an npm client

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

case "$REF_NAME" in
	releases/*/v*) ;;
	*) fail "Ref '${REF_NAME}' does not match releases/<ext>/v<version>" ;;
esac

REF="${REF_NAME#releases/}"
EXT="${REF%%/v*}"
VERSION="${REF#*/v}"
CRATE="tightbeam-${EXT}"
CRATE_TOML="${EXT}/${CRATE}/Cargo.toml"

if [ ! -f "$CRATE_TOML" ]; then
	fail "Unknown extension '${EXT}' (expected ${CRATE_TOML})"
fi

CURRENT=$(awk -F'"' '/^\[package\]/{f=1;next} f&&/^\[/{f=0} f&&/^version/{print $2;exit}' "$CRATE_TOML")
if [ "$CURRENT" != "$VERSION" ]; then
	printf '  %s version (%s) does not match tag (%s)\n' "$CRATE_TOML" "$CURRENT" "$VERSION" >&2
	fail "Bump on master via make release version=v${VERSION} ext=${EXT} before tagging."
fi

HAS_NPM=false
if [ -f "${EXT}/client/package.json" ]; then
	HAS_NPM=true
	NPM_CURRENT=$(node -p "require('./${EXT}/client/package.json').version")
	if [ "$NPM_CURRENT" != "$VERSION" ]; then
		printf '  %s/client/package.json version (%s) does not match tag (%s)\n' "$EXT" "$NPM_CURRENT" "$VERSION" >&2
		fail "Bump on master via make release version=v${VERSION} ext=${EXT} before tagging."
	fi
fi

{
	echo "EXT=$EXT"
	echo "VERSION=$VERSION"
	echo "CRATE=$CRATE"
	echo "TITLE=${CRATE} v${VERSION}"
	echo "HAS_NPM=$HAS_NPM"
} | emit_env
