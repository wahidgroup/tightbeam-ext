#!/usr/bin/env bash
set -euo pipefail

# Publish what a registry lacks of a release tag, so a run after a partial
# publish finishes the release: docs/development.md (Releases).
#
# Usage: publish-release.sh [--dry-run] crates
#        publish-release.sh [--dry-run] client <tarball>
#
# It reads EXT, VERSION, CRATES, and NPM_CLIENT as scripts/verify-release-tag.sh
# exports them. --dry-run asks the registries, then prints each publish in
# place of running it.

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
USAGE="Usage: publish-release.sh [--dry-run] crates | client <tarball>"

fail() {
	printf '  \033[0;31m[error]\033[0m %s\n' "$1" >&2
	exit 1
}

DRY_RUN=""
if [ "${1:-}" = "--dry-run" ]; then
	DRY_RUN=1
	shift
fi

# Each attempt refuses a yanked version before it reads or writes a registry.
"$REPO_ROOT/scripts/check-yanked.sh" "${EXT:?}"

# Run the publish $@, or print it under --dry-run.
publish() {
	if [ -n "$DRY_RUN" ]; then
		printf 'dry run: %s\n' "$*"
		return
	fi

	"$@"
}

# The path of crate $1 in the sparse index of crates.io.
crate_index_path() {
	local name="${1,,}"
	case "${#name}" in
		1) printf '1/%s' "$name" ;;
		2) printf '2/%s' "$name" ;;
		3) printf '3/%s/%s' "${name:0:1}" "$name" ;;
		*) printf '%s/%s/%s' "${name:0:2}" "${name:2:2}" "$name" ;;
	esac
}

# Whether the index of crates.io holds version $2 of crate $1. Fails when the
# index cannot answer.
crate_published() {
	local response status
	response="$(curl --silent --show-error --retry 3 --write-out '\n%{http_code}' \
		"https://index.crates.io/$(crate_index_path "$1")")" || fail "The index of crates.io did not answer for ${1}"
	status="${response##*$'\n'}"
	case "$status" in
		200) jq -se --arg version "$2" 'any(.[]; .vers == $version)' <<< "${response%$'\n'*}" >/dev/null ;;
		404) return 1 ;;
		*) fail "The index of crates.io answered HTTP ${status} for ${1}" ;;
	esac
}

# Whether the registry of npm package $1 holds its version $2. Fails when the
# registry cannot answer.
npm_published() {
	local answer status=0
	answer="$(npm view "$1@$2" version --json 2>/dev/null)" || status=$?
	if [ "$status" -ne 0 ]; then
		if jq -e '.error.code == "E404"' <<< "$answer" >/dev/null 2>&1; then
			return 1
		fi

		printf '%s\n' "$answer" >&2
		fail "The registry of ${1} did not answer for ${2}"
	fi

	jq -e --arg version "$2" '[.] | flatten | any(. == $version)' <<< "${answer:-null}" >/dev/null
}

# Publish each crate of CRATES at VERSION that crates.io lacks, in one
# multi-package publish.
publish_crates() {
	local crates crate
	local packages=()
	read -ra crates <<< "${CRATES:?}"
	for crate in "${crates[@]}"; do
		if crate_published "$crate" "${VERSION:?}"; then
			echo "crates.io holds ${crate} ${VERSION}"
			continue
		fi

		packages+=(-p "$crate")
	done

	if [ "${#packages[@]}" -eq 0 ]; then
		echo "crates.io holds every crate of the release"
		return
	fi

	cd "$REPO_ROOT"
	publish cargo publish --no-verify "${packages[@]}"
}

# Publish the client tarball $1 when its registry lacks it. The tarball holds
# NPM_CLIENT at VERSION.
publish_client() {
	local tarball="$1" packed
	if [ ! -f "$tarball" ]; then
		fail "No client tarball at ${tarball}"
	fi

	packed="$(tar -xOzf "$tarball" package/package.json | jq -r '"\(.name)@\(.version)"')"
	if [ "$packed" != "${NPM_CLIENT:?}@${VERSION:?}" ]; then
		fail "The tarball holds ${packed}, not the release ${NPM_CLIENT}@${VERSION}"
	fi

	if npm_published "$NPM_CLIENT" "$VERSION"; then
		echo "The registry holds ${NPM_CLIENT} ${VERSION}"
		return
	fi

	publish npm publish "$tarball" --ignore-scripts
}

case "${1:-}:$#" in
	crates:1) publish_crates ;;
	client:2) publish_client "$2" ;;
	*) fail "$USAGE" ;;
esac
