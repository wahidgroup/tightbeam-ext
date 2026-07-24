#!/usr/bin/env bash
# Project discovery for the composition scripts. A top-level directory
# owning a Makefile is an extension project. Source with REPO_ROOT set:
#
#   REPO_ROOT=... . "$REPO_ROOT/scripts/lib/projects.sh"
#   selection="$(select_projects "$@")"
#   mapfile -t PROJECTS <<< "$selection"

discover_projects() {
	local makefile
	for makefile in "$REPO_ROOT"/*/Makefile; do
		if [ -f "$makefile" ]; then
			basename "$(dirname "$makefile")"
		fi
	done
}

# Resolve the project selection: the given args (validated against the
# discovered projects), or every discovered project when none are given.
# Prints one project per line.
select_projects() {
	local known
	known="$(discover_projects)"

	if [ "$#" -eq 0 ]; then
		printf '%s\n' "$known"
		return
	fi

	local project
	for project in "$@"; do
		if ! printf '%s\n' "$known" | grep -qx "$project"; then
			echo "ERROR: unknown project '$project' (expected: $(printf '%s' "$known" | tr '\n' ' '))" >&2
			return 1
		fi
	done
	printf '%s\n' "$@"
}
