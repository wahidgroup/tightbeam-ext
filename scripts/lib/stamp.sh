#!/usr/bin/env bash
# Shared stamp/lock primitives for the setup scripts. Each setup script
# (root toolchain, per-project installs) sources this and composes:
#
#   REPO_ROOT=... . "$REPO_ROOT/scripts/lib/stamp.sh"
#   acquire_lock; trap release_lock EXIT
#   if stamp_stale "$STAMP" "${MANIFESTS[@]}"; then
#       ...install...
#       write_stamp "$STAMP" "${MANIFESTS[@]}"
#   fi
#
# The lock is one file for every setup script, so parallel make jobs and
# nested invocations serialize instead of racing npm/cargo installs.

STAMP_DIR="$REPO_ROOT/.make"
LOCK_FILE="$STAMP_DIR/setup.lock"
LOCK_DIR="$STAMP_DIR/setup.lock.d"
LOCK_FD=9
LOCK_KIND=""

# GitHub Actions sets CI=true; prefer lockfile-faithful installs there.
NPM_INSTALL_CMD=install
if [ "${CI:-}" = "true" ] || [ "${CI:-}" = "1" ]; then
	NPM_INSTALL_CMD=ci
fi

# sha256sum (Linux) or shasum (macOS); both print "hash  path".
if command -v sha256sum >/dev/null 2>&1; then
	SHA256_CMD=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
	SHA256_CMD=(shasum -a 256)
else
	echo "ERROR: setup needs sha256sum or shasum on PATH." >&2
	exit 1
fi

compute_hash() {
	# Hash the given manifest files plus the npm install mode/flags, so
	# switching either invalidates the stamp.
	{
		"${SHA256_CMD[@]}" "$@" 2>/dev/null
		printf 'npm-cmd:%s\n' "$NPM_INSTALL_CMD"
		printf 'npm-flags:%s\n' "${NPM_INSTALL_FLAGS:-}"
	} | "${SHA256_CMD[@]}" | awk '{ print $1 }'
}

stamp_stale() {
	# $1 = stamp file, rest = manifest files. 0 when setup must run.
	local stamp="$1"
	shift
	if [ ! -f "$stamp" ]; then
		return 0
	fi

	local current saved
	current="$(compute_hash "$@")"
	saved="$(tr -d '\n' < "$stamp")"
	[ "$current" != "$saved" ]
}

write_stamp() {
	# $1 = stamp file, rest = manifest files.
	local stamp="$1"
	shift
	mkdir -p "$STAMP_DIR"
	compute_hash "$@" > "$stamp"
}

release_lock() {
	if [ "$LOCK_KIND" = "flock" ]; then
		flock -u "$LOCK_FD" 2>/dev/null || true
		eval "exec ${LOCK_FD}>&-"
	elif [ "$LOCK_KIND" = "mkdir" ]; then
		rmdir "$LOCK_DIR" 2>/dev/null || true
	fi
	LOCK_KIND=""
}

acquire_lock() {
	mkdir -p "$STAMP_DIR"
	if command -v flock >/dev/null 2>&1; then
		eval "exec ${LOCK_FD}>\"\$LOCK_FILE\""
		if ! flock -w 600 "$LOCK_FD"; then
			echo "ERROR: timed out waiting for setup lock (${LOCK_FILE})." >&2
			exit 1
		fi
		LOCK_KIND="flock"
		return
	fi

	local waited=0
	while ! mkdir "$LOCK_DIR" 2>/dev/null; do
		if [ "$waited" -ge 600 ]; then
			echo "ERROR: timed out waiting for setup lock (${LOCK_DIR})." >&2
			exit 1
		fi
		sleep 1
		waited=$((waited + 1))
	done
	LOCK_KIND="mkdir"
}
