#!/usr/bin/env bash
# pubsub contribution to the shared e2e stack. Declares the demo-server port,
# its queue bound, the processed topic seal, and this extension's compose
# file. The env file derives an X_ENDPOINT for every X_HOST_PORT key.

# Preferred host ports for the pubsub demo servers (plain, and the one
# publishing through the processor servlet). Replaced by OS ports if in use.
# The processor itself never gets a host port.
: "${PREFERRED_PUBSUB_WS_PORT:=9110}"
: "${PREFERRED_PUBSUB_PROCESSED_WS_PORT:=9112}"

# Per-subscriber queue bound on the pubsub demo server. Small so the e2e
# suite can force a DropOldest gap with a short publish burst.
: "${PUBSUB_QUEUE_CAPACITY:=4}"

# The pre-shared AES-256-GCM key-encryption key of the processed topic, as 64
# hex digits, and the identifier that names it in each sealed envelope. The
# processor seals its rebuilt frames under the key, and the e2e suites seal
# and unseal their topics under it.
: "${PUBSUB_TOPIC_KEY:=0707070707070707070707070707070707070707070707070707070707070707}"
: "${PUBSUB_TOPIC_KEY_ID:=pubsub-demo-processed}"

# Ordered: host-port env key -> PREFERRED_* override var.
STACK_PORT_SPECS+=(
	"PUBSUB_WS_HOST_PORT:PREFERRED_PUBSUB_WS_PORT"
	"PUBSUB_PROCESSED_WS_HOST_PORT:PREFERRED_PUBSUB_PROCESSED_WS_PORT"
)

# Passed through to the compose environment and the env file unchanged.
STACK_ENV_VARS+=(
	"PUBSUB_QUEUE_CAPACITY"
	"PUBSUB_TOPIC_KEY"
	"PUBSUB_TOPIC_KEY_ID"
)

STACK_COMPOSE_FILES+=("$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docker-compose.yml")
