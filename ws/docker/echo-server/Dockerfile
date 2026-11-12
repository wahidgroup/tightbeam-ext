# Self-contained image of the e2e stack: the echo and demo servers of ws and
# pubsub, and the work gateway and the coupled gateway of grpc.

FROM rust:1-slim-bookworm AS build

RUN apt-get update \
	&& apt-get install -y --no-install-recommends build-essential clang pkg-config \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

WORKDIR /src/tightbeam-ext
RUN cargo build --example echo_server_mux -p tightbeam-ws --features testing \
	&& cargo build --example echo_server_mux_clear -p tightbeam-ws --features testing \
	&& cargo build --example work_gateway_server -p tightbeam-ws --features colony \
	&& cargo build --example pubsub_demo_server -p tightbeam-pubsub \
	&& cargo build --example pubsub_processor_server -p tightbeam-pubsub \
	&& cargo build --example grpc_work_gateway_server -p tightbeam-grpc \
	&& cargo build --example grpc_coupled_gateway_server -p tightbeam-grpc --features couple,testing

FROM debian:bookworm-slim

RUN apt-get update \
	&& apt-get install -y --no-install-recommends iproute2 \
	&& rm -rf /var/lib/apt/lists/* \
	&& useradd -r -u 10001 echo

COPY --from=build /src/tightbeam-ext/target/debug/examples/echo_server_mux /usr/local/bin/echo-server-mux
COPY --from=build /src/tightbeam-ext/target/debug/examples/echo_server_mux_clear /usr/local/bin/echo-server-mux-clear
COPY --from=build /src/tightbeam-ext/target/debug/examples/work_gateway_server /usr/local/bin/work-gateway-server
COPY --from=build /src/tightbeam-ext/target/debug/examples/pubsub_demo_server /usr/local/bin/pubsub-demo-server
COPY --from=build /src/tightbeam-ext/target/debug/examples/pubsub_processor_server /usr/local/bin/pubsub-processor-server
COPY --from=build /src/tightbeam-ext/target/debug/examples/grpc_work_gateway_server /usr/local/bin/grpc-work-gateway-server
COPY --from=build /src/tightbeam-ext/target/debug/examples/grpc_coupled_gateway_server /usr/local/bin/grpc-coupled-gateway-server

USER echo

# A probe that connects would hold an accept slot of the server until its
# handshake deadline, so liveness reads the LISTEN state of the port instead.
# The compose file of each service sets the listen port, and a service that
# sets none fails the probe.
HEALTHCHECK --interval=3s --timeout=2s --start-period=3s --retries=30 \
	CMD ss -ltn "sport = :${ECHO_WS_PORT:?}" | grep -q LISTEN || exit 1

CMD ["echo-server-mux"]
