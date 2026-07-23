#!/usr/bin/env bash
set -euo pipefail

# Self-contained e2e stack orchestrator for the tightbeam-ws echo server.
#
#   ./scripts/stack.sh up   <e2e>   Assemble context, build image, start (waits healthy)
#   ./scripts/stack.sh down <e2e>   Stop the stack and remove volumes + context
#   ./scripts/stack.sh env  <e2e>   Print the path to the instance env file
#   ./scripts/stack.sh logs <e2e>   Follow container logs

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
ECHO_IMAGE="${STACK_PROJECT_PREFIX}-echo:$INSTANCE"

compose() {
	DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1 \
		docker compose -f "$ROOT/ws/docker-compose.yml" \
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

assemble_context() {
	# Stage the repo under the context so the image build is self-contained;
	# tightbeam-rs resolves from crates.io inside the build.
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

	# When Cargo.toml patches tightbeam-rs to the sibling checkout (local
	# development), stage that checkout too so the in-image build resolves
	# the same source.
	if grep -q '^tightbeam-rs = { path = "../tightbeam/tightbeam" }' "$ROOT/Cargo.toml"; then
		echo "==> Staging local tightbeam checkout (patched Cargo.toml)"
		rsync -a "${excludes[@]}" "$ROOT/../tightbeam/" "$CONTEXT_DIR/tightbeam/"
	fi
}

generate_certs() {
	# Mint the X.509 identity fixtures the encrypted echo servers present and
	# the browser suite pins. Idempotent per instance: reuse existing certs so
	# restarts keep the same trust anchors.
	if [ -f "$CERT_DIR/server.cert.der" ] && [ -f "$CERT_DIR/client.cert.der" ]; then
		return
	fi

	echo "==> Generating identity fixtures under '$CERT_DIR'"
	CERT_DIR="$CERT_DIR" cargo run -p tightbeam-ws --features testing --example gen_certs
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
			printf -v "$key" '%s' \
				"$(alloc_port "${!pref_var}" "$(read_prior "$key")")"
		done

		export ECHO_IMAGE CERT_DIR
		generate_certs
		render_env_file > "$ENV_FILE"

		echo "==> Assembling build context for '$PROJECT'"
		assemble_context

		echo "==> Building image '$ECHO_IMAGE'"
		DOCKER_BUILDKIT=1 docker build \
			-f "$ROOT/ws/docker/echo-server/Dockerfile" \
			-t "$ECHO_IMAGE" \
			"$CONTEXT_DIR"

		echo "==> Bringing up '$PROJECT' stack"
		echo "    echo ws (mux): ws://localhost:$ECHO_WS_MUX_HOST_PORT"

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
			DOCKER_BUILDKIT=1 docker compose -f "$ROOT/ws/docker-compose.yml" \
				--project-name "$PROJECT" down --volumes --remove-orphans || true
		fi
		rm -rf "$INSTANCE_DIR"
		echo "==> Stack '$PROJECT' stopped"
		;;

	*)
		usage 1
		;;
esac
