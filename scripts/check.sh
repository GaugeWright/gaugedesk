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
# Deliberately not in `all`, because each needs something a change gate should
# not require: coverage, mobile and desktop packaging, OIDC/SAML provider
# matrices, and the deployed production canaries. The Quint models are their own
# path-triggered gate — run `scripts/check-models.sh both` when you change
# anything under specs/models.
#
# The desktop shell *is* in `all`, because the `desktop-shell` job makes it an
# enforced pull-request gate and a local green bar that omits an enforced gate
# is a lie. It is the one section with a prerequisite a change gate cannot
# assume — Tauri links GTK and WebKit through pkg-config on Linux — so it is
# split: the lockfile-drift half resolves the graph and runs everywhere, and the
# compile runs wherever those libraries are present, which is every CI runner
# and every machine that has ever built the shell. On a Linux box without them
# `all` says so loudly and names the packages; `scripts/check.sh desktop` (what
# CI runs) refuses to skip. Leaving the shell out of CI entirely was worse: #125
# landed a call to a crate the shell does not depend on, and nothing noticed for
# a week because only `release.yml` ever built it.
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
# All three lockfiles are audited by name rather than by discovery, so that a
# fourth is a decision someone makes here rather than something that silently
# starts or stops being covered. `.cargo/audit.toml` carries the triage record
# for anything formally risk-accepted.
run_dependencies() {
    echo "== production dependency advisories =="
    command -v cargo-audit >/dev/null || {
        echo "cargo-audit is not installed; run: cargo install cargo-audit" >&2
        exit 1
    }
    cargo audit --file Cargo.lock
    cargo audit --file src-tauri/Cargo.lock
    cargo audit --file src-tauri-mobile/Cargo.lock

    # Production only. The dev trees are vite, wrangler, and playwright, none of
    # which reach a user.
    while IFS= read -r lock; do
        npm --prefix "${lock%/package-lock.json}" audit --omit=dev
    done < <(find . -name package-lock.json -not -path '*/node_modules/*' -print)
}

# The desktop shell is its own cargo workspace, so nothing in `rust` above
# compiles it. `--locked` is half the point: it fails when `src-tauri/Cargo.lock`
# has drifted from its manifest, which is the state this section was written in
# — the committed lock did not describe what a build resolved.
#
# Only the compile needs the native libraries. `cargo metadata --locked`
# resolves the dependency graph without running a single build script, so the
# drift half of this section is portable and runs unconditionally.
desktop_prerequisites_present() {
    # Tauri uses the system webview on macOS and Windows; only Linux needs the
    # GTK/WebKit development packages.
    [ "$(uname -s)" = "Linux" ] || return 0
    command -v pkg-config >/dev/null 2>&1 || return 1
    pkg-config --exists gtk+-3.0 webkit2gtk-4.1 javascriptcoregtk-4.1 libsoup-3.0 librsvg-2.0
}

# $1 = "required" (the `desktop` section and CI) or "best-effort" (inside `all`),
# which decides whether absent GTK/WebKit libraries fail or are reported.
run_desktop() {
    local prerequisites="${1:-required}"
    echo "== desktop shell =="

    echo "-- lockfile is in sync with the manifest --"
    cargo metadata --manifest-path src-tauri/Cargo.toml --locked --format-version 1 >/dev/null

    if desktop_prerequisites_present; then
        cargo check --manifest-path src-tauri/Cargo.toml --locked
        return
    fi

    local missing="libwebkit2gtk-4.1-dev libjavascriptcoregtk-4.1-dev libgtk-3-dev libsoup-3.0-dev librsvg2-dev"
    if [ "$prerequisites" = required ]; then
        echo "desktop shell compile requires GTK and WebKit development libraries." >&2
        echo "install: sudo apt-get install -y $missing" >&2
        exit 1
    fi

    echo "-- desktop shell compile SKIPPED: GTK/WebKit development libraries absent --" >&2
    echo "   the lockfile check above still ran, and the desktop-shell CI job compiles it on every" >&2
    echo "   pull request. To close the gap locally: sudo apt-get install -y $missing" >&2
}

case "$section" in
    all) run_contracts; run_dependencies; run_rust; run_web; run_desktop best-effort ;;
    contracts) run_contracts ;;
    dependencies) run_dependencies ;;
    desktop) run_desktop ;;
    rust) run_rust ;;
    web) run_web ;;
    *) echo "usage: scripts/check.sh [all|contracts|dependencies|desktop|rust|web]" >&2; exit 2 ;;
esac

echo "== gaugedesk green bar PASSED ($section) =="
