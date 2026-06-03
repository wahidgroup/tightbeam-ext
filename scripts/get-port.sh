#!/usr/bin/env bash
set -euo pipefail

# Echoes a usable TCP port. If a preferred port is given and free, it is
# returned verbatim; otherwise an OS-assigned ephemeral port is emitted.
#
# Usage: ./scripts/get-port.sh [preferred-port]

PREFERRED_PORT="${1:-}"

is_port_free() {
	! lsof -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
}

if [ -n "$PREFERRED_PORT" ] && is_port_free "$PREFERRED_PORT"; then
	echo "$PREFERRED_PORT"
	exit 0
fi

if [ -n "$PREFERRED_PORT" ]; then
	echo "Port $PREFERRED_PORT in use, requesting OS port" >&2
fi

node -e "const s=require('net').createServer();s.listen(0,()=>{process.stdout.write(String(s.address().port));s.close()})"
