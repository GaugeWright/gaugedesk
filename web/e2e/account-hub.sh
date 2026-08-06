#!/usr/bin/env bash
# Launch the hermetic stand-in Hub for the desktop account-handoff e2e
# (LOGIN-5, ADR 0123). Port-scoped free like the relay launcher, so it never
# disturbs another run's servers.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$REPO/target/debug/examples/test-account-hub"
PORT="${HUB_PORT:-7910}"

(fuser -k "${PORT}/tcp" 2>/dev/null || lsof -ti "tcp:${PORT}" 2>/dev/null | xargs -r kill 2>/dev/null) || true
sleep 0.3

export GAUGEDESK_TEST_HUB_ADDR="127.0.0.1:${PORT}"
exec "$BIN"
