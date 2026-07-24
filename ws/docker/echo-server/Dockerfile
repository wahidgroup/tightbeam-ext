# Self-contained tightbeam-ws echo server image.

FROM rust:1-slim-bookworm AS build

RUN apt-get update \
	&& apt-get install -y --no-install-recommends build-essential clang pkg-config \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

WORKDIR /src/tightbeam-ext
RUN cargo build --example echo_server_mux -p tightbeam-ws --features testing \
	&& cargo build --example echo_server_mux_clear -p tightbeam-ws --features testing \
	&& cargo build --example pubsub_demo_server -p tightbeam-pubsub --features testing \
	&& cargo build --example pubsub_processor_server -p tightbeam-pubsub --features testing

FROM debian:bookworm-slim

RUN apt-get update \
	&& apt-get install -y --no-install-recommends iproute2 \
	&& rm -rf /var/lib/apt/lists/* \
	&& useradd -r -u 10001 echo

COPY --from=build /src/tightbeam-ext/target/debug/examples/echo_server_mux /usr/local/bin/echo-server-mux
COPY --from=build /src/tightbeam-ext/target/debug/examples/echo_server_mux_clear /usr/local/bin/echo-server-mux-clear
COPY --from=build /src/tightbeam-ext/target/debug/examples/pubsub_demo_server /usr/local/bin/pubsub-demo-server
COPY --from=build /src/tightbeam-ext/target/debug/examples/pubsub_processor_server /usr/local/bin/pubsub-processor-server

USER echo

ENV ECHO_WS_PORT=9100
EXPOSE 9100

# The transport speaks no HTTP, and a bare TCP connect would fail the WebSocket
# handshake, so liveness is a passive LISTEN-state probe that never opens
# a connection.
HEALTHCHECK --interval=3s --timeout=2s --start-period=3s --retries=30 \
	CMD ss -ltn "sport = :${ECHO_WS_PORT:-9100}" | grep -q LISTEN || exit 1

CMD ["echo-server-mux"]
