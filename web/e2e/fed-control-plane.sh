#!/usr/bin/env bash
# Launch one control plane for the federation E2E (M8), parameterised by port so
# two instances (alice on 7878, the federation peer on 7879) coexist. Unlike
# control-plane.sh it frees ONLY its own port (no blanket `pkill -x gaugedesk-app`,
# which would kill the peer instance) and reads its bind/authority/broker from env.
set -euo pipefail

PORT="${FED_PORT:?FED_PORT required}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$REPO/target/debug/gaugedesk-app"
STATE="${GAUGEDESK_E2E_STATE:-/tmp/gaugewright-e2e-state-${PORT}}"

# Free an orphaned LISTENER on this port, and nothing else. `fuser -k PORT/tcp`
# and `lsof -i tcp:PORT` also match any process whose outgoing connection
# happens to use PORT as its ephemeral local port, so on a host running two
# suites (or a gate host running other bars) they killed unrelated processes,
# another run's control plane among them (WS-871).
(lsof -nP -t -iTCP:"${PORT}" -sTCP:LISTEN 2>/dev/null | xargs -r kill 2>/dev/null) || true
sleep 0.4

rm -rf "$STATE"
mkdir -p "$STATE"
cd "$STATE"
ln -sfn "$REPO/plugin" "$STATE/plugin"

# Enable the per-scenario reset route; bind + federate per env (GAUGEDESK_AUTHORITY is
# left unset for the 7878 instance so it stays `local-user`, keeping the existing
# single-instance suite unchanged).
export GAUGEDESK_TEST_RESET=1
# The controller-request scenario drives the direct phone protocol, which a
# desktop no longer serves (DR-0329); this debug binary mounts it for the test.
export GAUGEDESK_TEST_MACHINE_CONTROLLERS=1
# Federation is part of the normal product composition. This harness supplies
# explicit test identities and a hermetic relay; it does not enable a different
# route surface.
export GAUGEDESK_ADDR="127.0.0.1:${PORT}"
export GAUGEDESK_RELAY_ENDPOINT="${GAUGEDESK_RELAY_ENDPOINT:-ws://127.0.0.1:7900}"
# Each control plane is its OWN machine: pin its data root to its isolated state dir.
# Without this, `control_plane_root()` falls through to the shared OS app-data dir, so
# alice and bob would share one `instances/` tree — a relocation then tries to
# materialize an instance dir the origin already created (and pollutes the real user
# data dir). A per-machine root keeps the two homes genuinely separate.
export GAUGEDESK_ROOT="$STATE"
exec "$BIN"
