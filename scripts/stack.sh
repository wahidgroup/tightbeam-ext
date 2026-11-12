#!/usr/bin/env bash
set -euo pipefail

# Self-contained e2e stack orchestrator: the images, certificates, ports,
# and compose files that the project fragments declare (scripts/env.sh).
#
# - `./scripts/stack.sh up <e2e>` assembles the context, builds the images, and starts the stack, then
#   waits until it is healthy.
# - `./scripts/stack.sh down <e2e>` stops the stack and removes its volumes and its context.
# - `./scripts/stack.sh env <e2e>` prints the path to the env file of the instance.
# - `./scripts/stack.sh logs <e2e>` follows the logs of the containers.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# shellcheck source=scripts/env.sh
. "$ROOT/scripts/env.sh"

usage() {
	echo "Usage: $0 {up|down|env|logs} <e2e>" >&2
	exit "${1:-1}"
}

ACTION="${1:-}"
INSTANCE="${2:-}"

if [ -z "$ACTION" ] || [ -z "$INSTANCE" ]; then
	usage 1
fi
if ! [[ "$INSTANCE" =~ ^(e2e|dev)$ ]]; then
	echo "Invalid instance '$INSTANCE' (expected e2e or dev)" >&2
	usage 1
fi

INSTANCE_DIR="$ROOT/.dev/$INSTANCE"
CONTEXT_DIR="$INSTANCE_DIR/context"
ENV_FILE="$INSTANCE_DIR/.env"
CERT_DIR="$INSTANCE_DIR/certs"
PROJECT="${STACK_PROJECT_PREFIX}-$INSTANCE"

# Each image a fragment declares, tagged for this instance.
for image in "${STACK_IMAGES[@]}"; do
	key="${image%%:*}"
	name="$(tr '[:upper:]_' '[:lower:]-' <<< "${key%_IMAGE}")"
	printf -v "$key" '%s-%s:%s' "$STACK_PROJECT_PREFIX" "$name" "$INSTANCE"
	export "${key?}"
done
unset image key name

# One stack for every extension: each project fragment (stack-env.sh)
# contributed its compose file.
COMPOSE_FILES=()
for compose_file in "${STACK_COMPOSE_FILES[@]}"; do
	COMPOSE_FILES+=(-f "$compose_file")
done
unset compose_file

compose() {
	DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1 \
		docker compose "${COMPOSE_FILES[@]}" \
		--project-name "$PROJECT" --env-file "$ENV_FILE" "$@"
}

alloc_port() {
	# $1 = preferred, $2 = previously allocated (reused as preferred if set)
	local preferred="$1"
	local previous="${2:-}"
	if [ -n "$previous" ]; then
		preferred="$previous"
	fi
	"$ROOT/scripts/get-port.sh" "$preferred"
}

read_prior() {
	if [ -f "$ENV_FILE" ]; then
		sed -n "s/^$1=//p" "$ENV_FILE" | head -1
	fi
}

# The checkout of tightbeam-rs when Cargo resolves it from a local path, or
# nothing when it resolves from a registry.
local_tightbeam_checkout() {
	local manifest
	manifest="$(cargo metadata --format-version 1 --manifest-path "$ROOT/Cargo.toml" \
		| jq -r '.packages[] | select(.name == "tightbeam-rs" and .source == null) | .manifest_path')"
	if [ -n "$manifest" ]; then
		dirname "$(cargo locate-project --workspace --message-format plain --manifest-path "$manifest")"
	fi
}

assemble_context() {
	# Stage the repo under the context so the image build is self-contained.
	# The context has the layout of the parent of the repo, so a path
	# dependency that leaves the repo resolves inside the build as it does on
	# the host.
	rm -rf "$CONTEXT_DIR"
	mkdir -p "$CONTEXT_DIR/tightbeam-ext"

	local excludes=(
		--exclude '.git'
		--exclude 'target'
		--exclude 'node_modules'
		--exclude '.dev'
		--exclude 'dist'
		--exclude 'wasm'
		--exclude 'pkg'
	)
	rsync -a "${excludes[@]}" "$ROOT/" "$CONTEXT_DIR/tightbeam-ext/"

	# When Cargo resolves tightbeam-rs from a local checkout, stage that
	# checkout too so the in-image build resolves the same source.
	local checkout parent
	checkout="$(local_tightbeam_checkout)"
	if [ -n "$checkout" ]; then
		parent="$(dirname "$ROOT")"
		case "$checkout" in
			"$parent"/*) ;;
			*)
				echo "Local tightbeam checkout '$checkout' is outside '$parent', so the build context cannot hold it" >&2
				exit 1
				;;
		esac
		echo "==> Staging local tightbeam checkout '$checkout'"
		mkdir -p "$CONTEXT_DIR/${checkout#"$parent"/}"
		rsync -a "${excludes[@]}" "$checkout/" "$CONTEXT_DIR/${checkout#"$parent"/}/"
	fi
}

generate_certs() {
	# Each project issues its own material under CERT_DIR. Every step keeps
	# the material it finds, so restarts keep the same trust anchors.
	echo "==> Generating certificates under '$CERT_DIR'"
	local step
	for step in "${STACK_CERT_STEPS[@]}"; do
		CERT_DIR="$CERT_DIR" bash -c "$step"
	done
}

case "$ACTION" in
	env)
		echo "$ENV_FILE"
		;;

	logs)
		compose logs -f
		;;

	up)
		mkdir -p "$INSTANCE_DIR"

		for spec in "${STACK_PORT_SPECS[@]}"; do
			key="${spec%%:*}"
			pref_var="${spec#*:}"
			pref_var="${pref_var%%:*}"
			printf -v "$key" '%s' \
				"$(alloc_port "${!pref_var}" "$(read_prior "$key")")"
		done

		export CERT_DIR
		generate_certs
		render_env_file > "$ENV_FILE"

		echo "==> Assembling build context for '$PROJECT'"
		assemble_context

		for image in "${STACK_IMAGES[@]}"; do
			key="${image%%:*}"
			echo "==> Building image '${!key}'"
			DOCKER_BUILDKIT=1 docker build \
				-f "${image#*:}" \
				-t "${!key}" \
				"$CONTEXT_DIR"
		done

		echo "==> Bringing up '$PROJECT' stack"
		for spec in "${STACK_PORT_SPECS[@]}"; do
			key="${spec%%:*}"
			echo "    ${key%_HOST_PORT}: ${spec##*:}://localhost:${!key}"
		done

		if ! compose up -d --wait; then
			echo "==> Stack '$PROJECT' failed to become healthy; recent logs:" >&2
			compose logs --no-color --tail=80 || true
			exit 1
		fi
		echo "==> Stack '$PROJECT' is healthy"
		;;

	down)
		if [ -f "$ENV_FILE" ]; then
			compose down --volumes --remove-orphans || true
		else
			DOCKER_BUILDKIT=1 docker compose "${COMPOSE_FILES[@]}" \
				--project-name "$PROJECT" down --volumes --remove-orphans || true
		fi
		rm -rf "$INSTANCE_DIR"
		echo "==> Stack '$PROJECT' stopped"
		;;

	*)
		usage 1
		;;
esac
