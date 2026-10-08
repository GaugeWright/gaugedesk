#!/usr/bin/env bash
# Launch the hermetic stand-in Hub for the desktop account-handoff e2e
# (LOGIN-5, ADR 0123). Port-scoped free like the relay launcher, so it never
# disturbs another run's servers.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$REPO/target/debug/examples/test-account-hub"
PORT="${HUB_PORT:-7910}"

# Free an orphaned LISTENER on this port, and nothing else. `fuser -k PORT/tcp`
# and `lsof -i tcp:PORT` also match any process whose outgoing connection
# happens to use PORT as its ephemeral local port, so on a host running two
# suites (or a gate host running other bars) they killed unrelated processes,
# another run's control plane among them (WS-871).
(lsof -nP -t -iTCP:"${PORT}" -sTCP:LISTEN 2>/dev/null | xargs -r kill 2>/dev/null) || true
sleep 0.3

export GAUGEDESK_TEST_HUB_ADDR="127.0.0.1:${PORT}"
exec "$BIN"
