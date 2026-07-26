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
#   CRATE     Canonical crate name (tightbeam-<ext>)
#   CRATES    Space-separated publishable crate names under EXT/
#   TITLE     Release title (<crate> v<version>)
#   HAS_NPM   true when the extension ships an npm client
#   HAS_SBOM  true when the npm client ships an SBOM asset

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

# Read [package].name from a Cargo.toml.
cargo_package_name() {
	awk -F'"' '
		/^\[package\]/ { in_section = 1; next }
		in_section && /^\[/ { in_section = 0 }
		in_section && /^name[[:space:]]*=/ { print $2; exit }
	' "$1"
}

# Read [package].version from a Cargo.toml.
cargo_package_version() {
	awk -F'"' '
		/^\[package\]/ { in_section = 1; next }
		in_section && /^\[/ { in_section = 0 }
		in_section && /^version[[:space:]]*=/ { print $2; exit }
	' "$1"
}

# True when [package] does not set publish = false.
cargo_is_publishable() {
	! awk '
		/^\[package\]/ { in_section = 1; next }
		in_section && /^\[/ { in_section = 0 }
		in_section && /^publish[[:space:]]*=[[:space:]]*false([[:space:]]|$|#)/ {
			found = 1
			exit
		}
		END { exit found ? 0 : 1 }
	' "$1"
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

CRATES=""
found_canonical=false
for manifest in "$EXT"/*/Cargo.toml; do
	[ -f "$manifest" ] || continue
	if ! cargo_is_publishable "$manifest"; then
		continue
	fi
	name="$(cargo_package_name "$manifest")"
	[ -n "$name" ] || fail "Could not read [package].name from ${manifest}"
	current="$(cargo_package_version "$manifest")"
	if [ "$current" != "$VERSION" ]; then
		printf '  %s version (%s) does not match tag (%s)\n' "$manifest" "$current" "$VERSION" >&2
		fail "Bump on master via make release version=v${VERSION} ext=${EXT} before tagging."
	fi
	if [ -n "$CRATES" ]; then
		CRATES="${CRATES} ${name}"
	else
		CRATES="$name"
	fi
	if [ "$name" = "$CRATE" ]; then
		found_canonical=true
	fi
done

if [ -z "$CRATES" ]; then
	fail "No publishable crates found under ${EXT}/"
fi
if [ "$found_canonical" != true ]; then
	fail "Canonical crate ${CRATE} is missing or not publishable under ${EXT}/"
fi

HAS_NPM=false
HAS_SBOM=false
if [ -f "${EXT}/client/package.json" ]; then
	HAS_NPM=true
	NPM_CURRENT=$(node -p "require('./${EXT}/client/package.json').version")
	if [ "$NPM_CURRENT" != "$VERSION" ]; then
		printf '  %s/client/package.json version (%s) does not match tag (%s)\n' "$EXT" "$NPM_CURRENT" "$VERSION" >&2
		fail "Bump on master via make release version=v${VERSION} ext=${EXT} before tagging."
	fi
	# Client packages that ship an SBOM list sbom.json in "files".
	if node -e "const p=require('./${EXT}/client/package.json'); process.exit((p.files||[]).includes('sbom.json')?0:1)"; then
		HAS_SBOM=true
	fi
fi

{
	echo "EXT=$EXT"
	echo "VERSION=$VERSION"
	echo "CRATE=$CRATE"
	echo "CRATES=$CRATES"
	echo "TITLE=${CRATE} v${VERSION}"
	echo "HAS_NPM=$HAS_NPM"
	echo "HAS_SBOM=$HAS_SBOM"
} | emit_env
