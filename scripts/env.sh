#!/usr/bin/env bash
# Configuration for the self-contained e2e stack (see scripts/stack.sh,
# which sources this with ROOT set).
#
# The stack itself is generic: every project-specific value (ports, extra
# env, compose files) lives in the project's own scripts/stack-env.sh
# fragment, aggregated below. A project without a fragment contributes
# nothing to the stack.
#
# Every value uses `: "${VAR:=default}"` so it can be overridden from the
# environment, e.g. `PREFERRED_ECHO_WS_MUX_PORT=9200 make test ws`.

# Compose project name prefix; the instance (e2e) is appended for isolation.
: "${STACK_PROJECT_PREFIX:=tbws}"

# Filled by the project fragments:
#   STACK_PORT_SPECS    "HOST_PORT_KEY:PREFERRED_VAR:SCHEME" triples,
#                       allocated by stack.sh; each X_HOST_PORT also yields
#                       X_ENDPOINT, a SCHEME://localhost URL of the port.
#   STACK_ENV_VARS      variable names passed through to the env file.
#   STACK_COMPOSE_FILES compose files layered into the one stack (consumed
#                       by stack.sh, which sources this file).
#   STACK_CERT_STEPS    commands that stack.sh runs with CERT_DIR exported,
#                       after the shared identities exist, so a project adds
#                       its own material under CERT_DIR. Each step is
#                       idempotent.
STACK_PORT_SPECS=()
STACK_ENV_VARS=()
# shellcheck disable=SC2034
STACK_COMPOSE_FILES=()
# shellcheck disable=SC2034
STACK_CERT_STEPS=()

for stack_fragment in "$ROOT"/*/scripts/stack-env.sh; do
	if [ -f "$stack_fragment" ]; then
		# shellcheck disable=SC1090
		. "$stack_fragment"
	fi
done
unset stack_fragment

render_env_file() {
	# Emit the compose env-file body to stdout from the current environment.
	# Callers (stack.sh) must have PROJECT, ECHO_IMAGE, CERT_DIR and every
	# port key set.
	echo "COMPOSE_PROJECT_NAME=$PROJECT"
	echo "ECHO_IMAGE=$ECHO_IMAGE"
	echo "CERT_DIR=$CERT_DIR"

	local spec key scheme
	for spec in "${STACK_PORT_SPECS[@]}"; do
		key="${spec%%:*}"
		scheme="${spec##*:}"
		printf '%s=%s\n' "$key" "${!key}"
		printf '%s=%s://localhost:%s\n' "${key%_HOST_PORT}_ENDPOINT" "$scheme" "${!key}"
	done

	local var
	for var in "${STACK_ENV_VARS[@]}"; do
		printf '%s=%s\n' "$var" "${!var}"
	done
}
