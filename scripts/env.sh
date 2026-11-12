#!/usr/bin/env bash
# The configuration of the e2e stack, which scripts/stack.sh sources with ROOT set: docs/development.md (Docker stack).
#
# Each value takes its default through `: "${VAR:=default}"`, so the environment overrides it,
# as in `PREFERRED_ECHO_WS_MUX_PORT=9200 make test ws`.

# The prefix of the compose project name. stack.sh appends the instance, such as e2e.
: "${STACK_PROJECT_PREFIX:=tbws}"

# The project fragments fill these arrays.
#
# The "HOST_PORT_KEY:PREFERRED_VAR:SCHEME" triples that stack.sh allocates.
# Each X_HOST_PORT also yields X_ENDPOINT, a SCHEME://localhost URL of the port.
STACK_PORT_SPECS=()
# The names of the variables that the env file passes through.
STACK_ENV_VARS=()
# The compose files that stack.sh layers into one stack.
# shellcheck disable=SC2034
STACK_COMPOSE_FILES=()
# The "IMAGE_KEY:DOCKERFILE" pairs that stack.sh builds and tags. The env file
# carries each IMAGE_KEY.
STACK_IMAGES=()
# The commands that stack.sh runs with CERT_DIR exported. Each step adds its own
# material under CERT_DIR and keeps the material it finds.
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
	# Callers (stack.sh) must have PROJECT, CERT_DIR, every image key, and
	# every port key set.
	echo "COMPOSE_PROJECT_NAME=$PROJECT"
	echo "CERT_DIR=$CERT_DIR"

	local image key
	for image in "${STACK_IMAGES[@]}"; do
		key="${image%%:*}"
		printf '%s=%s\n' "$key" "${!key}"
	done

	local spec scheme
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
