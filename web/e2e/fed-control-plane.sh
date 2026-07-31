#!/usr/bin/env bash
# Launch one control plane for the federation E2E (M8), parameterised by port so
# two instances (alice on 7878, the federation peer on 7879) coexist. Unlike
# control-plane.sh it frees ONLY its own port (no blanket `pkill -x gaugewright-app`,
# which would kill the peer instance) and reads its bind/authority/broker from env.
set -euo pipefail

PORT="${FED_PORT:?FED_PORT required}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$REPO/target/debug/gaugewright-app"
STATE="${GAUGEWRIGHT_E2E_STATE:-/tmp/gaugewright-e2e-state-${PORT}}"

(fuser -k "${PORT}/tcp" 2>/dev/null || lsof -ti "tcp:${PORT}" 2>/dev/null | xargs -r kill 2>/dev/null) || true
sleep 0.4

rm -rf "$STATE"
mkdir -p "$STATE"
cd "$STATE"
ln -sfn "$REPO/plugin" "$STATE/plugin"

# Enable the per-scenario reset route; bind + federate per env (GAUGEWRIGHT_AUTHORITY is
# left unset for the 7878 instance so it stays `local-user`, keeping the existing
# single-instance suite unchanged).
export GAUGEWRIGHT_TEST_RESET=1
# Cross-authority federation is PARKED off by default in the product (ADR 0065): its
# subsystem isn't opened and its routes aren't mounted unless opted in. The federation E2E
# (pairing/handoff/co-drive over the relay) is precisely the opt-in case — turn it on so the
# `/federation/*` surface (e.g. `POST /federation/pairing-ticket`) is reachable here.
export GAUGEWRIGHT_FEDERATION=1
export GAUGEWRIGHT_ADDR="127.0.0.1:${PORT}"
export GAUGEWRIGHT_RELAY_ENDPOINT="${GAUGEWRIGHT_RELAY_ENDPOINT:-ws://127.0.0.1:7900}"
# Each control plane is its OWN machine: pin its data root to its isolated state dir.
# Without this, `control_plane_root()` falls through to the shared OS app-data dir, so
# alice and bob would share one `instances/` tree — a relocation then tries to
# materialize an instance dir the origin already created (and pollutes the real user
# data dir). A per-machine root keeps the two homes genuinely separate.
export GAUGEWRIGHT_ROOT="$STATE"
exec "$BIN"
