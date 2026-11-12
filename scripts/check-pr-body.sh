#!/usr/bin/env bash
set -euo pipefail

# Check a pull request body against the PR template: CONTRIBUTING.md (Body).
#
# Usage: PR_BODY=<body> HEAD_REF=<branch> check-pr-body.sh

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/lib/extension.sh
. "$REPO_ROOT/scripts/lib/extension.sh"

TEMPLATE="$REPO_ROOT/.github/PULL_REQUEST_TEMPLATE.md"

if is_process_branch "${HEAD_REF:-}"; then
	echo "Release PR: body exempt."
	exit 0
fi

headings="$(sed -n 's/^##[[:space:]][[:space:]]*//p' "$TEMPLATE")"
if [ -z "$headings" ]; then
	echo "ERROR: ${TEMPLATE} holds no ## heading." >&2
	exit 1
fi

body="$(printf '%s' "${PR_BODY:-}" | perl -0pe 's/<!--.*?-->//gs')"

missing=()
empty=()
while IFS= read -r section; do
	content="$(printf '%s\n' "$body" | awk -v hdr="$section" '
		/^##[[:space:]]/ {
			title = $0
			sub(/^##[[:space:]]+/, "", title)
			sub(/[[:space:]]+$/, "", title)
			if (title == hdr) { found = 1; capture = 1; next }
			capture = 0
		}
		capture { print }
		END { if (!found) exit 1 }
	')" || { missing+=("## ${section}"); continue; }

	content="$(printf '%s\n' "$content" | sed -E 's/^[[:space:]]*[-*][[:space:]]*$//' | tr -d '[:space:]')"
	if [ "${#content}" -lt 3 ]; then
		empty+=("## ${section}")
	fi
done <<< "$headings"

failed=0
if [ "${#missing[@]}" -gt 0 ]; then
	echo "Missing required sections:"
	printf '  - %s\n' "${missing[@]}"
	failed=1
fi
if [ "${#empty[@]}" -gt 0 ]; then
	echo "Empty required sections (must contain at least 3 non-whitespace chars):"
	printf '  - %s\n' "${empty[@]}"
	failed=1
fi
if [ "$failed" -eq 1 ]; then
	echo ""
	echo "See CONTRIBUTING.md for the PR body specification."
	exit 1
fi
echo "PR body OK."
