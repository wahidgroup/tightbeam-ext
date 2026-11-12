#!/usr/bin/env bash
# The release facts of an extension for the scripts that source this file with REPO_ROOT set.
# The rules of a release: docs/development.md (Releases).

# shellcheck source=scripts/lib/projects.sh
. "$REPO_ROOT/scripts/lib/projects.sh"

# The canonical crate of extension $1.
extension_crate() {
	printf 'tightbeam-%s' "$1"
}

# The workspace packages under the directory of extension $1, as JSON lines.
extension_packages() {
	cargo metadata --no-deps --format-version 1 --offline --manifest-path "$REPO_ROOT/Cargo.toml" \
		| jq -c --arg root "$REPO_ROOT/$1/" '.packages[] | select(.manifest_path | startswith($root))'
}

# Fail unless $1 names one extension: a known project that holds its
# canonical crate.
extension_require() {
	local ext="${1:-}"
	if [ -z "$ext" ] || [ "$ext" != "${ext%% *}" ]; then
		echo "ERROR: name one extension (expected one of: $(discover_projects | tr '\n' ' '))" >&2
		return 1
	fi

	select_projects "$ext" >/dev/null || return 1

	local crates
	crates="$(extension_crates "$ext")"
	if ! grep -qx "$(extension_crate "$ext")" <<< "$crates"; then
		echo "ERROR: project '$ext' holds no crate $(extension_crate "$ext")" >&2
		return 1
	fi
}

# The [package].name of each crate of extension $1, one per line.
extension_crates() {
	extension_packages "$1" | jq -r '.name'
}

# The crates of extension $1 that the release publishes to crates.io, one
# per line. Cargo reads `publish = false` as an empty registry list.
extension_publishable_crates() {
	extension_packages "$1" | jq -r 'select(.publish == null or (.publish | index("crates-io"))) | .name'
}

# The version of extension $1: the version of its canonical crate.
extension_version() {
	extension_packages "$1" | jq -r --arg crate "$(extension_crate "$1")" 'select(.name == $crate) | .version'
}

# Each crate of extension $1 whose version is not $2, as "<manifest> <version>"
# lines with the manifest relative to REPO_ROOT.
extension_version_mismatches() {
	extension_packages "$1" \
		| jq -r --arg version "$2" --arg root "$REPO_ROOT/" \
			'select(.version != $version) | "\(.manifest_path | ltrimstr($root)) \(.version)"'
}

# Every other extension that a crate of extension $1 depends on through a
# path, one per line.
extension_dependencies() {
	extension_packages "$1" \
		| jq -rs --arg root "$REPO_ROOT/" --arg ext "$1" '
			[.[].dependencies[] | select(.path != null) | .path | ltrimstr($root) | split("/")[0] | select(. != $ext)]
			| unique
			| .[]
		'
}

# Fail unless a release of extension $1 at version $2 moves it forward, and
# print that version. On a terminal an absent version is asked for in the
# words of scripts/release.sh. `make release` runs this check before
# scripts/release.sh and passes it the printed version.
extension_release_gate() {
	local ext="${1:-}"
	local entered="${2:-}"
	extension_require "$ext" || return 1
	if [ -z "$entered" ] && [ -t 0 ]; then
		printf '\n  Enter version to release (current: %s): ' "$(extension_version "$ext")" >&2
		read -r entered
	fi

	local version="${entered#v}"
	if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		echo "ERROR: name the version of the release as version=vX.Y.Z (got '${entered}')" >&2
		return 1
	fi

	# scripts/release.sh reads the same tags after the same fetch.
	if ! git -C "$REPO_ROOT" fetch origin --tags --quiet 2>/dev/null; then
		echo "WARNING: could not fetch the tags of origin, so the checks read the tags of this clone" >&2
	fi

	# The version of the latest release passes, so that a stopped release resumes.
	local tag latest
	tag="$(release_tag "$ext" "$version")"
	latest="$(git -C "$REPO_ROOT" tag --list "$(release_tag "$ext" '*')" | sort -V | tail -1)"
	if [ -n "$latest" ] && [ "$(printf '%s\n' "$latest" "$tag" | sort -V | tail -1)" != "$tag" ]; then
		echo "ERROR: v${version} is below the latest release ${latest}, and releases only go forward" >&2
		return 1
	fi

	local dependencies dependency since
	dependencies="$(extension_dependencies "$ext")" || return 1
	while IFS= read -r dependency; do
		if [ -z "$dependency" ]; then
			continue
		fi

		latest="$(git -C "$REPO_ROOT" tag --list "$(release_tag "$dependency" '*')" | sort -V | tail -1)"
		if [ -z "$latest" ]; then
			echo "ERROR: ${ext} depends on ${dependency}, which has no release tag: release ${dependency} first" >&2
			return 1
		fi

		since="$(git -C "$REPO_ROOT" rev-list --count "${latest}..HEAD" -- "${dependency}/")"
		if [ "$since" -gt 0 ]; then
			echo "ERROR: ${ext} depends on ${dependency}, which has ${since} commits since ${latest}: release ${dependency} first" >&2
			return 1
		fi
	done <<< "$dependencies"

	printf '%s\n' "$version"
}

# The npm client manifest of extension $1, relative to REPO_ROOT.
extension_npm_manifest() {
	printf '%s/client/package.json' "$1"
}

# The npm name of the client of extension $1, or nothing when it has none.
extension_npm_client() {
	local manifest
	manifest="$REPO_ROOT/$(extension_npm_manifest "$1")"
	if [ -f "$manifest" ]; then
		jq -r '.name' "$manifest"
	fi
}

# The version of the npm client of extension $1.
extension_npm_version() {
	jq -r '.version' "$REPO_ROOT/$(extension_npm_manifest "$1")"
}

# The SBOM of the npm client of extension $1, relative to REPO_ROOT, or
# nothing when its package lists no sbom.json in "files".
extension_npm_sbom() {
	local manifest
	manifest="$(extension_npm_manifest "$1")"
	if jq -e '(.files // []) | index("sbom.json")' "$REPO_ROOT/$manifest" >/dev/null; then
		printf '%s/sbom.json' "$(dirname "$manifest")"
	fi
}

# The signed tag that a release of extension $1 at version $2 pushes.
release_tag() {
	printf 'releases/%s/v%s' "$1" "$2"
}

# The marker tag that a yank of extension $1 at version $2 pushes.
yanked_tag() {
	printf 'yanked/%s/v%s' "$1" "$2"
}

# Whether $1 is the branch that scripts/release.sh commits a version bump on.
is_process_branch() {
	case "$1" in
		process/*/v*) return 0 ;;
		*) return 1 ;;
	esac
}

# The extension and the version of the release tag $1, as "<ext> <version>".
release_tag_parse() {
	local ext version
	IFS=/ read -r _ ext version <<< "$1"
	version="${version#v}"
	if [ -z "$ext" ] || [ -z "$version" ] || [ "$(release_tag "$ext" "$version")" != "$1" ]; then
		echo "ERROR: ref '$1' does not match $(release_tag '<ext>' '<version>')" >&2
		return 1
	fi

	printf '%s %s\n' "$ext" "$version"
}
