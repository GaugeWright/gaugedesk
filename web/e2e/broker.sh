#!/usr/bin/env bash
# Launch the hermetic WSS relay for the federation E2E (M8). Port-scoped free so it
# never disturbs other control-plane instances: a blanket `pkill -x gaugewright-app`
# would kill a peer (or a dev) instance, so these launchers free only their own port.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$REPO/target/debug/examples/test-wss-relay"
PORT="${BROKER_PORT:-7900}"

# Free only our port; Playwright waits on the listener before starting tests.
(fuser -k "${PORT}/tcp" 2>/dev/null || lsof -ti "tcp:${PORT}" 2>/dev/null | xargs -r kill 2>/dev/null) || true
sleep 0.3

export GAUGEWRIGHT_TEST_RELAY_ADDR="127.0.0.1:${PORT}"
exec "$BIN"
