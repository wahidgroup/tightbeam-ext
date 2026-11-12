#!/usr/bin/env bash
# grpc contribution to the shared e2e stack: the ports, the Envoy
# configuration, the TLS material, and the compose file of this extension.

# Preferred host port of the Envoy hop. Replaced by an OS port if in use. The
# work gateway itself listens on the compose network alone.
: "${PREFERRED_GRPC_ENVOY_PORT:=9121}"

# Preferred host port of the coupled edge, which a stock gRPC caller dials
# directly over TLS.
: "${PREFERRED_GRPC_COUPLED_PORT:=9122}"

# Preferred loopback port of the admin endpoint of the Envoy hop, which the
# hop lane reads the route configuration from.
: "${PREFERRED_GRPC_ENVOY_ADMIN_PORT:=9901}"

# The Envoy configuration, mounted into the Envoy container.
: "${GRPC_ENVOY_CONFIG:=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docker/envoy.yaml}"

# Ordered: host-port env key, its PREFERRED_* override var, and the scheme of
# its endpoint.
STACK_PORT_SPECS+=(
	"GRPC_ENVOY_HOST_PORT:PREFERRED_GRPC_ENVOY_PORT:http"
	"GRPC_COUPLED_HOST_PORT:PREFERRED_GRPC_COUPLED_PORT:https"
	"GRPC_ENVOY_ADMIN_HOST_PORT:PREFERRED_GRPC_ENVOY_ADMIN_PORT:http"
)

# The TLS material of the coupled edge and of its stock caller, under
# CERT_DIR/coupled.
STACK_CERT_STEPS+=(
	"cargo run -p tightbeam-grpc --features couple,testing --example gen_coupled_certs"
)

# Passed through to the compose environment and the env file unchanged.
STACK_ENV_VARS+=(
	"GRPC_ENVOY_CONFIG"
)

STACK_COMPOSE_FILES+=("$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docker-compose.yml")
