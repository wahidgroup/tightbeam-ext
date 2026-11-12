#!/usr/bin/env bash
set -euo pipefail

# Print the version of each selected extension and the commit of the tree.
#
# Usage: version.sh [project...]   (default: every project)

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/lib/extension.sh
. "$REPO_ROOT/scripts/lib/extension.sh"

selection="$(select_projects "$@")"
mapfile -t PROJECTS <<< "$selection"

commit="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
dirty=""
if [ -n "$(git -C "$REPO_ROOT" status --porcelain 2>/dev/null)" ]; then
	dirty="+dirty"
fi

for project in "${PROJECTS[@]}"; do
	extension_require "$project"
	printf '%s %s (%s%s)\n' "$(extension_crate "$project")" "$(extension_version "$project")" "$commit" "$dirty"
done
