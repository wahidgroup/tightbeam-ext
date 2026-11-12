#!/usr/bin/env bash
set -euo pipefail

# The root setup, which installs the pinned Rust toolchain and cargo-audit, then
# runs the setup of each selected project: docs/development.md (Projects).
#
# Usage: setup.sh [project...]   (default: every project)

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/lib/stamp.sh
. "$REPO_ROOT/scripts/lib/stamp.sh"
# shellcheck source=scripts/lib/projects.sh
. "$REPO_ROOT/scripts/lib/projects.sh"

selection="$(select_projects "$@")"
mapfile -t PROJECTS <<< "$selection"

STAMP="$STAMP_DIR/setup-root.hash"
MANIFESTS=(
	"$REPO_ROOT/Cargo.toml"
	"$REPO_ROOT/Cargo.lock"
	"$REPO_ROOT/rust-toolchain.toml"
	"$REPO_ROOT/scripts/setup.sh"
)

toolchain_required() {
	if ! command -v cargo-audit >/dev/null 2>&1; then
		return 0
	fi
	stamp_stale "$STAMP" "${MANIFESTS[@]}"
}

install_toolchain() {
	# With no argument, rustup installs the channel, the components, and the
	# targets that rust-toolchain.toml names.
	echo "Installing pinned toolchain, components, and targets (rust-toolchain.toml)..."
	rustup toolchain install

	if ! command -v cargo-audit >/dev/null 2>&1; then
		echo "Installing cargo-audit..."
		cargo install cargo-audit --locked
	fi
}

main() {
	acquire_lock
	trap release_lock EXIT

	if toolchain_required; then
		install_toolchain
		write_stamp "$STAMP" "${MANIFESTS[@]}"
		echo "Toolchain setup complete."
	else
		echo "Toolchain already up to date."
	fi

	# Project scripts take the same lock themselves.
	release_lock
	trap - EXIT

	for project in "${PROJECTS[@]}"; do
		"$REPO_ROOT/$project/scripts/setup.sh"
	done
}

main
