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
        scripts/wiring-canary/diagnostic.test.mjs \
        scripts/wiring-canary/hosted-account-session.test.mjs \
        scripts/wiring-canary/poll.test.mjs \
        web/e2e/production-account-session-canary.test.mjs \
        web/e2e/production-native-session-canary.test.mjs

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

# The dependency audit lives here rather than in a workflow step so that the
# documented local green bar and the enforced gate stay the same command. It is
# its own section because it is the one part of this script that needs the
# network and the advisory database rather than the toolchain, and because the
# security-baseline schedule runs exactly this and nothing else.
#
# `src-tauri/Cargo.lock` is deliberately absent: it fails today on
# RUSTSEC-2026-0194 and RUSTSEC-2026-0195, two high-severity denial-of-service
# advisories against `quick-xml` 0.39.4 reaching the shipped desktop binary
# through `tauri` -> `plist`. `plist` 1.10.0 closes both, but that lockfile has
# drifted from its manifest, so the bump re-resolves 35 packages in the artifact
# users install and adds `rsa`, whose advisory is risk-accepted here on a
# rationale written for a different codepath. Add the line in the same change
# that lands the bump. `.cargo/audit.toml` carries the triage record.
run_dependencies() {
    echo "== production dependency advisories =="
    command -v cargo-audit >/dev/null || {
        echo "cargo-audit is not installed; run: cargo install cargo-audit" >&2
        exit 1
    }
    cargo audit --file Cargo.lock
    cargo audit --file src-tauri-mobile/Cargo.lock

    # Production only. The dev trees are vite, wrangler, and playwright, none of
    # which reach a user.
    while IFS= read -r lock; do
        npm --prefix "${lock%/package-lock.json}" audit --omit=dev
    done < <(find . -name package-lock.json -not -path '*/node_modules/*' -print)
}

case "$section" in
    all) run_contracts; run_dependencies; run_rust; run_web ;;
    contracts) run_contracts ;;
    dependencies) run_dependencies ;;
    rust) run_rust ;;
    web) run_web ;;
    *) echo "usage: scripts/check.sh [all|contracts|dependencies|rust|web]" >&2; exit 2 ;;
esac

echo "== gaugedesk green bar PASSED ($section) =="
