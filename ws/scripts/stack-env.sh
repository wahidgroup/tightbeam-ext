#!/usr/bin/env bash
# The ws facts of the shared e2e stack, which scripts/env.sh sources.

# The preferred host ports of the echo servers and of the e2e app. The stack
# takes a free port in place of one in use.
: "${PREFERRED_ECHO_WS_MUX_PORT:=9100}"
: "${PREFERRED_ECHO_WS_MUX_CLEAR_PORT:=9101}"
: "${PREFERRED_ECHO_WS_MUX_MUTUAL_PORT:=9102}"
: "${PREFERRED_ECHO_WS_MUX_DUPLEX_PORT:=9103}"
: "${PREFERRED_WORK_GATEWAY_WS_PORT:=9104}"
: "${PREFERRED_E2E_APP_PORT:=4317}"

# The stream cap that each echo server of the stack grants its peer through
# `tightbeam_ws::testing::DemoConfig`. The e2e suites pass the same cap on each
# cleartext dial, because no handshake negotiates a cleartext cap.
: "${MUX_STREAMS:=8}"

# The demo session-budget paywall: the paywalled servers read it through
# `tightbeam_ws::testing::DemoConfig`, and the e2e suites read the payment and
# the ceiling through their `STACK`. This file is the one home of each value.
: "${TBWS_PAYWALL:=on}"
: "${TBWS_DEMO_INVOICE:=tbws-demo-invoice-v1}"
: "${TBWS_DEMO_PAYMENT:=tbws-demo-payment-v1}"

# The credit ceiling of the paywall in each direction, which MUST clear the
# mux drain reserve:
#   - The reserve is `2 * (local_cap + peer_cap) + 1` records at `ceil(chunk / credit_unit)` credits each.
#   - With 8/8 caps, 16 KiB chunks, and a 1 KiB credit unit, the reserve is 528 credits.
: "${TBWS_MUX_BUDGET_C2S:=4096}"
: "${TBWS_MUX_BUDGET_S2C:=4096}"

# The servlet type that the work gateway serves its probe under, and that the
# e2e suites submit their work to.
: "${TBWS_WORK_SERVLET:=urn:tightbeam::servlet:work-probe}"

# Ordered: host-port env key, its PREFERRED_* override var, and the scheme of
# its endpoint.
STACK_PORT_SPECS+=(
	"ECHO_WS_MUX_HOST_PORT:PREFERRED_ECHO_WS_MUX_PORT:ws"
	"ECHO_WS_MUX_CLEAR_HOST_PORT:PREFERRED_ECHO_WS_MUX_CLEAR_PORT:ws"
	"ECHO_WS_MUX_MUTUAL_HOST_PORT:PREFERRED_ECHO_WS_MUX_MUTUAL_PORT:ws"
	"ECHO_WS_MUX_DUPLEX_HOST_PORT:PREFERRED_ECHO_WS_MUX_DUPLEX_PORT:ws"
	"WORK_GATEWAY_WS_HOST_PORT:PREFERRED_WORK_GATEWAY_WS_PORT:ws"
	"E2E_APP_HOST_PORT:PREFERRED_E2E_APP_PORT:http"
)

# Passed through to the compose environment and the env file unchanged.
STACK_ENV_VARS+=(
	"MUX_STREAMS"
	"TBWS_PAYWALL"
	"TBWS_DEMO_INVOICE"
	"TBWS_DEMO_PAYMENT"
	"TBWS_MUX_BUDGET_C2S"
	"TBWS_MUX_BUDGET_S2C"
	"TBWS_WORK_SERVLET"
)

# The one image of the stack: every demo server of ws, pubsub, and grpc.
STACK_IMAGES+=("ECHO_IMAGE:$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docker/echo-server/Dockerfile")

# The X.509 identities that the encrypted servers present and the suites pin.
# A certificate file publishes its identity (IdentityFiles::provision), so the
# step keeps both identities while both certificates are present.
# shellcheck disable=SC2016 # CERT_DIR expands when stack.sh runs the step.
STACK_CERT_STEPS+=(
	'[ -f "$CERT_DIR/server.cert.der" ] && [ -f "$CERT_DIR/client.cert.der" ] || cargo run -p tightbeam-ws --features testing --example gen_certs'
)

STACK_COMPOSE_FILES+=("$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docker-compose.yml")
