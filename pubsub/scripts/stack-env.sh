#!/usr/bin/env bash
# pubsub contribution to the shared e2e stack. Declares the demo-server port,
# its queue bound, and this extension's compose file. The env file derives an
# X_ENDPOINT for every X_HOST_PORT key.

# Preferred host ports for the pubsub demo servers (plain, and the one
# publishing through the processor servlet). Replaced by OS ports if in use.
# The processor itself never gets a host port.
: "${PREFERRED_PUBSUB_WS_PORT:=9110}"
: "${PREFERRED_PUBSUB_PROCESSED_WS_PORT:=9112}"

# Per-subscriber queue bound on the pubsub demo server. Small so the e2e
# suite can force a DropOldest gap with a short publish burst.
: "${PUBSUB_QUEUE_CAPACITY:=4}"

# Ordered: host-port env key -> PREFERRED_* override var.
STACK_PORT_SPECS+=(
	"PUBSUB_WS_HOST_PORT:PREFERRED_PUBSUB_WS_PORT"
	"PUBSUB_PROCESSED_WS_HOST_PORT:PREFERRED_PUBSUB_PROCESSED_WS_PORT"
)

# Passed through to the compose environment and the env file verbatim.
STACK_ENV_VARS+=("PUBSUB_QUEUE_CAPACITY")

STACK_COMPOSE_FILES+=("$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docker-compose.yml")
