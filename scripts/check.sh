#!/usr/bin/env bash
# The green bar for gaugedesk-src. This is the complete required check set that
# gates a change, and the configured CI gates run this same script, so a passing
# run here and a passing gate cannot mean different things.
#
#   scripts/check.sh            everything below
#   scripts/check.sh rust       one section, while iterating
#   scripts/check.sh web
#   scripts/check.sh contracts
#
# The set spans what used to be three workflows: the private Tier-0 lane
# (architecture, license boundary, contracts, canaries, client calls, spec
# audit), the Tier-1 loopback integration tests, and the public mirror's Rust
# and web lanes. A developer previously had no way to run that union.
#
# Deliberately not here, because each needs something a change gate should not
# require: coverage, mobile and desktop packaging, OIDC/SAML provider matrices,
# and the deployed production canaries. The Quint models are their own
# path-triggered gate — run `scripts/check-models.sh both` when you change
# anything under specs/models.
set -euo pipefail
cd "$(dirname "$0")/.."

section="${1:-all}"

run_contracts() {
    echo "== agent guide =="
    node scripts/check-agent-guide.mjs

    echo "== architecture boundaries =="
    python3 scripts/architecture-check.py

    echo "== license boundary =="
    python3 scripts/check-license-boundary.py

    echo "== product contracts =="
    node scripts/check-product-contracts.mjs --enforce-local-evidence

    echo "== production canary contract =="
    node scripts/check-production-canaries.mjs
    node --test \
        scripts/canary-preflight.test.mjs \
        scripts/provision-canary.test.mjs \
        scripts/check-production-canaries.test.mjs \
        scripts/production-wiring-canary.test.mjs \
        scripts/run-production-wiring-canaries.test.mjs \
        scripts/wiring-canary/runners.test.mjs \
        scripts/wiring-canary/totp.test.mjs \
        scripts/wiring-canary/capture-provider-state.test.mjs \
        web/e2e/production-account-session-canary.test.mjs

    echo "== client calls =="
    node scripts/check-client-calls.mjs

    echo "== spec audit =="
    python3 scripts/audit-gate.py
}

run_rust() {
    echo "== formatting =="
    cargo fmt --all --check

    echo "== lints =="
    cargo clippy --workspace --all-targets -- -D warnings

    echo "== tests =="
    cargo test --workspace

    # The open build must stay buildable without the enterprise features.
    echo "== no-default-features =="
    cargo check -p gaugedesk-app --no-default-features --all-targets
}

run_web() {
    [ -d web/node_modules ] || npm --prefix web ci
    # The browser tunnel (DESK-7, ADR 0130) is generated and gitignored, so a
    # fresh checkout has no module for the loader's dynamic import to resolve
    # and `vite build` fails outright — it cannot bundle an unresolvable
    # specifier, and a stub is not an option because the design refuses to
    # silently degrade a Home to unreachable. Built on absence, exactly the way
    # node_modules above is: a developer pays once, CI pays every run because
    # its checkout is always fresh.
    # Both modules, because either one missing fails the build the same way.
    { [ -f web/packages/control-plane-client/src/generated/tunnel.js ] \
        && [ -f web/packages/control-plane-client/src/generated/directory.js ]; } \
        || scripts/build-wasm.sh
    echo "== web typecheck =="
    npm --prefix web run typecheck
    npm --prefix web run typecheck:split

    echo "== web tests =="
    npm --prefix web run test

    echo "== web builds =="
    npm --prefix web run build:open
    npm --prefix web run build:embed
    npm --prefix web run build:apps:open

    [ -d ee/web/node_modules ] || npm --prefix ee/web ci
    echo "== enterprise web =="
    npm --prefix ee/web run typecheck
    npm --prefix ee/web run build

    [ -d ee/sidecar/saml-verify/node_modules ] || npm --prefix ee/sidecar/saml-verify ci
    echo "== saml verify sidecar =="
    npm --prefix ee/sidecar/saml-verify test
}

case "$section" in
    all) run_contracts; run_rust; run_web ;;
    contracts) run_contracts ;;
    rust) run_rust ;;
    web) run_web ;;
    *) echo "usage: scripts/check.sh [all|contracts|rust|web]" >&2; exit 2 ;;
esac

echo "== gaugedesk green bar PASSED ($section) =="
