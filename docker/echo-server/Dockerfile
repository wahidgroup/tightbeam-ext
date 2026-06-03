# Self-contained tightbeam-ws echo server image.

FROM rust:1-slim-bookworm AS build

RUN apt-get update \
	&& apt-get install -y --no-install-recommends build-essential clang pkg-config \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

WORKDIR /src/tightbeam-ws
RUN cargo build --example echo_server -p tightbeam-ws

FROM debian:bookworm-slim

RUN apt-get update \
	&& apt-get install -y --no-install-recommends iproute2 \
	&& rm -rf /var/lib/apt/lists/* \
	&& useradd -r -u 10001 echo

COPY --from=build /src/tightbeam-ws/target/debug/examples/echo_server /usr/local/bin/echo-server

USER echo

ENV ECHO_WS_PORT=9100
EXPOSE 9100

# The transport speaks no HTTP, and a bare TCP connect would fail the WebSocket
# handshake, so liveness is a passive LISTEN-state probe that never opens
# a connection.
HEALTHCHECK --interval=3s --timeout=2s --start-period=3s --retries=30 \
	CMD ss -ltn "sport = :${ECHO_WS_PORT:-9100}" | grep -q LISTEN || exit 1

CMD ["echo-server"]
