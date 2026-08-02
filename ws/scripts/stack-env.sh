#!/usr/bin/env bash
# ws contribution to the shared e2e stack (sourced by scripts/env.sh).
# Declares the echo-server ports and this extension's compose file; the
# env file derives an X_ENDPOINT for every X_HOST_PORT key.

# Preferred host ports for the echo servers; replaced by OS ports if in use.
: "${PREFERRED_ECHO_WS_MUX_PORT:=9100}"
: "${PREFERRED_ECHO_WS_MUX_CLEAR_PORT:=9101}"
: "${PREFERRED_ECHO_WS_MUX_MUTUAL_PORT:=9102}"
: "${PREFERRED_ECHO_WS_MUX_DUPLEX_PORT:=9103}"

# Ordered: host-port env key -> PREFERRED_* override var.
STACK_PORT_SPECS+=(
	"ECHO_WS_MUX_HOST_PORT:PREFERRED_ECHO_WS_MUX_PORT"
	"ECHO_WS_MUX_CLEAR_HOST_PORT:PREFERRED_ECHO_WS_MUX_CLEAR_PORT"
	"ECHO_WS_MUX_MUTUAL_HOST_PORT:PREFERRED_ECHO_WS_MUX_MUTUAL_PORT"
	"ECHO_WS_MUX_DUPLEX_HOST_PORT:PREFERRED_ECHO_WS_MUX_DUPLEX_PORT"
)

STACK_COMPOSE_FILES+=("$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docker-compose.yml")
