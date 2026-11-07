#!/usr/bin/env bash
# ws contribution to the shared e2e stack (sourced by scripts/env.sh).
# Declares the echo-server ports, the demo stream cap and paywall facts, and
# this extension's compose file. The env file derives an X_ENDPOINT for every
# X_HOST_PORT key.

# Preferred host ports for the echo servers; replaced by OS ports if in use.
: "${PREFERRED_ECHO_WS_MUX_PORT:=9100}"
: "${PREFERRED_ECHO_WS_MUX_CLEAR_PORT:=9101}"
: "${PREFERRED_ECHO_WS_MUX_MUTUAL_PORT:=9102}"
: "${PREFERRED_ECHO_WS_MUX_DUPLEX_PORT:=9103}"
: "${PREFERRED_WORK_GATEWAY_WS_PORT:=9104}"

# The stream cap that every demo server grants its peer through
# `tightbeam_ws::testing::DemoConfig`. The e2e suites pass the same cap on each
# cleartext dial, because no handshake negotiates a cleartext cap.
: "${MUX_STREAMS:=8}"

# The demo session-budget paywall: the paywalled servers read it through
# `tightbeam_ws::testing::DemoConfig`, and the e2e suites read the payment and
# the ceiling through their `STACK`. This file is the one home of each value.
: "${TBWS_PAYWALL:=on}"
: "${TBWS_DEMO_INVOICE:=tbws-demo-invoice-v1}"
: "${TBWS_DEMO_PAYMENT:=tbws-demo-payment-v1}"

# The per-direction credit ceiling of the paywall. It must clear the mux drain
# reserve of `2 * (local_cap + peer_cap) + 1` records at
# `ceil(chunk / credit_unit)` credits each. With 8/8 caps, 16 KiB chunks, and
# a 1 KiB credit unit, that reserve is 528 credits, so a ceiling of 64 leaves
# no usable budget.
: "${TBWS_MUX_BUDGET_C2S:=4096}"
: "${TBWS_MUX_BUDGET_S2C:=4096}"

# Ordered: host-port env key -> PREFERRED_* override var.
STACK_PORT_SPECS+=(
	"ECHO_WS_MUX_HOST_PORT:PREFERRED_ECHO_WS_MUX_PORT"
	"ECHO_WS_MUX_CLEAR_HOST_PORT:PREFERRED_ECHO_WS_MUX_CLEAR_PORT"
	"ECHO_WS_MUX_MUTUAL_HOST_PORT:PREFERRED_ECHO_WS_MUX_MUTUAL_PORT"
	"ECHO_WS_MUX_DUPLEX_HOST_PORT:PREFERRED_ECHO_WS_MUX_DUPLEX_PORT"
	"WORK_GATEWAY_WS_HOST_PORT:PREFERRED_WORK_GATEWAY_WS_PORT"
)

# Passed through to the compose environment and the env file unchanged.
STACK_ENV_VARS+=(
	"MUX_STREAMS"
	"TBWS_PAYWALL"
	"TBWS_DEMO_INVOICE"
	"TBWS_DEMO_PAYMENT"
	"TBWS_MUX_BUDGET_C2S"
	"TBWS_MUX_BUDGET_S2C"
)

STACK_COMPOSE_FILES+=("$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docker-compose.yml")
