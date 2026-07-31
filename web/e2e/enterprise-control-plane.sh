#!/usr/bin/env bash
# Launch the SELF-HOSTED enterprise composition (`gaugewright-enterprise-server`) for the enterprise
# e2e scenarios: the open control plane plus the org admin surface (`/admin/*`,
# gaugewright-ee) — no managed planes, so enterprise coverage never needs the
# private cloud repo. Port-scoped free
# like the other launchers (no blanket pkill), parameterised by ENTERPRISE_PORT.
set -euo pipefail

PORT="${ENTERPRISE_PORT:?ENTERPRISE_PORT required}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$REPO/target/debug/gaugewright-enterprise-server"
STATE="${GAUGEWRIGHT_E2E_STATE:-/tmp/gaugewright-e2e-state-${PORT}}"

(fuser -k "${PORT}/tcp" 2>/dev/null || lsof -ti "tcp:${PORT}" 2>/dev/null | xargs -r kill 2>/dev/null) || true
sleep 0.4

rm -rf "$STATE"
mkdir -p "$STATE"
cd "$STATE"
ln -sfn "$REPO/plugin" "$STATE/plugin"

# Enable the per-scenario reset route; bind + root per env. The hosted composition
# is its own machine: pin its data root to its isolated state dir (see
# fed-control-plane.sh for why — a shared OS app-data root would collide).
export GAUGEWRIGHT_TEST_RESET=1
export GAUGEWRIGHT_TEST_IDENTITY_TOKEN="${GAUGEWRIGHT_TEST_IDENTITY_TOKEN:-gw-e2e-owner-token}"
export GAUGEWRIGHT_TEST_MEMBER_TOKEN="${GAUGEWRIGHT_TEST_MEMBER_TOKEN:-gw-e2e-member-token}"
export GAUGEWRIGHT_ADDR="127.0.0.1:${PORT}"
export GAUGEWRIGHT_ROOT="$STATE"
exec "$BIN"
