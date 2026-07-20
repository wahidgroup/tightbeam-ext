#!/usr/bin/env bash
# Configuration for the self-contained e2e stack (see scripts/stack.sh).
#
# Every value uses `: "${VAR:=default}"` so it can be overridden from the
# environment, e.g. `PREFERRED_ECHO_WS_PORT=9200 make e2e`.

# Compose project name prefix; the instance (e2e) is appended for isolation.
: "${STACK_PROJECT_PREFIX:=tbws}"

# Preferred host ports for the echo servers; replaced by OS ports if in use.
: "${PREFERRED_ECHO_WS_PORT:=9100}"
: "${PREFERRED_ECHO_WS_SECURE_PORT:=9101}"
: "${PREFERRED_ECHO_WS_MUTUAL_PORT:=9102}"
: "${PREFERRED_ECHO_WS_SINK_PORT:=9103}"

# Single source of truth for the compose env keys. stack.sh and render_env_file
# both iterate these, so adding/reordering a key happens in exactly one place.

# Ordered: host-port env key -> PREFERRED_* override var.
STACK_PORT_SPECS=(
	"ECHO_WS_HOST_PORT:PREFERRED_ECHO_WS_PORT"
	"ECHO_WS_SECURE_HOST_PORT:PREFERRED_ECHO_WS_SECURE_PORT"
	"ECHO_WS_MUTUAL_HOST_PORT:PREFERRED_ECHO_WS_MUTUAL_PORT"
	"ECHO_WS_SINK_HOST_PORT:PREFERRED_ECHO_WS_SINK_PORT"
)

render_env_file() {
	# Emit the compose env-file body to stdout from the current environment.
	# Callers (stack.sh) must have PROJECT, ECHO_IMAGE, CERT_DIR and every
	# port key set.
	echo "COMPOSE_PROJECT_NAME=$PROJECT"
	echo "ECHO_IMAGE=$ECHO_IMAGE"
	echo "CERT_DIR=$CERT_DIR"
	local spec key
	for spec in "${STACK_PORT_SPECS[@]}"; do
		key="${spec%%:*}"
		printf '%s=%s\n' "$key" "${!key}"
	done
	echo "ECHO_WS_ENDPOINT=ws://localhost:$ECHO_WS_HOST_PORT"
	echo "ECHO_WS_SECURE_ENDPOINT=ws://localhost:$ECHO_WS_SECURE_HOST_PORT"
	echo "ECHO_WS_MUTUAL_ENDPOINT=ws://localhost:$ECHO_WS_MUTUAL_HOST_PORT"
	echo "ECHO_WS_SINK_ENDPOINT=ws://localhost:$ECHO_WS_SINK_HOST_PORT"
}
