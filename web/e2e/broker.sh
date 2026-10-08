#!/usr/bin/env bash
# Launch the hermetic WSS relay for the federation E2E (M8). Port-scoped free so it
# never disturbs other control-plane instances: a blanket `pkill -x gaugedesk-app`
# would kill a peer (or a dev) instance, so these launchers free only their own port.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$REPO/target/debug/examples/test-wss-relay"
PORT="${BROKER_PORT:-7900}"

# Free only our port; Playwright waits on the listener before starting tests.
# Free an orphaned LISTENER on this port, and nothing else. `fuser -k PORT/tcp`
# and `lsof -i tcp:PORT` also match any process whose outgoing connection
# happens to use PORT as its ephemeral local port, so on a host running two
# suites (or a gate host running other bars) they killed unrelated processes,
# another run's control plane among them (WS-871).
(lsof -nP -t -iTCP:"${PORT}" -sTCP:LISTEN 2>/dev/null | xargs -r kill 2>/dev/null) || true
sleep 0.3

export GAUGEDESK_TEST_RELAY_ADDR="127.0.0.1:${PORT}"
exec "$BIN"
