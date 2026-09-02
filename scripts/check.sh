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
# Both native shells *are* in `all`, because the `native-shells` job makes them
# enforced pull-request gates and a local green bar that omits an enforced gate
# is a lie. They are the sections with a prerequisite a change gate cannot
# assume — Tauri links GTK and WebKit through pkg-config on Linux — so each is
# split: the lockfile-drift half resolves the graph and runs everywhere, and the
# compile runs wherever those libraries are present, which is every CI runner
# and every machine that has ever built a shell. On a Linux box without them
# `all` says so loudly and names the packages; `scripts/check.sh desktop` and
# `scripts/check.sh mobile` (what CI runs) refuse to skip. The mobile shell
# reached this gate later than the desktop one and for the same two reasons: its
# lockfile had drifted from its manifest, and only `mobile-release.yml` — on
# dispatch — ever compiled it. Leaving a shell out of CI entirely was worse: #125
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

    echo "== WhippleScript workstream host contract =="
    node scripts/check-whipplescript-workstream-contract.mjs

    echo "== TokenWright Environment bundle =="
    node scripts/check-tokenwright-environment.mjs
    node scripts/check-tokenwright-carried-surface.mjs

    # The updater endpoint is compiled into every shipped binary and cannot be
    # corrected for a client that already has it, so its mistakes are permanent
    # in the field and silent at build time. In particular an endpoint missing
    # {{current_version}} keeps working — right up until a key rotation strands
    # every client not already on the current key (DR-0080).
    echo "== updater endpoint =="
    node scripts/check-updater-endpoint.mjs

    # The other bundle fact nothing else looks at. `generate_context!` requires
    # only that an icon be RGBA, which a flattened matte satisfies, so an icon
    # whose transparency has been baked out builds and ships clean and then
    # draws a white box around the mark on every dark shell. It shipped that way
    # twice, the second time in a commit whose entire subject was these files.
    # It runs here rather than in `desktop` because reading a PNG needs none of
    # what linking a Tauri shell needs.
    echo "== app icons =="
    node scripts/check-app-icons.mjs

    # The artifact side of the same manifest: what a built bundle says about the
    # contract it holds, and the canonical digest both this section and the
    # hosted surfaces compare (DR-0051). A test no section names is a test
    # nothing runs, which is the state this one was committed in.
    echo "== release identity =="
    node --test scripts/build-release-identity.test.mjs

    # The desktop sign-in helper. It is plain node with no npm tree of its own, so
    # it runs here rather than in `web`. What it guards is the fixed loopback
    # callback port: every way the helper can fail to let go of it is a way to
    # break the next sign-in, and nothing ran this file's subject before.
    echo "== codex login helper =="
    node --test sidecar/codex-oauth-login.test.mjs

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

    # Absence has no line number: a crate nothing compiles and a lockfile
    # nothing audits look exactly like a crate and a lockfile. This enumerates
    # what is tracked, reads coverage out of this script, and fails on the
    # difference — which is how `src-tauri` and `src-tauri-mobile` should have
    # been found, rather than by a release and an advisory finding them.
    # Rendered from tools/shared-checks/build-coverage.mjs in the GaugeWright
    # repository, which owns it and tests it. A local edit fails here.
    echo "== build coverage =="
    node scripts/check-build-coverage.mjs

    # A job either blocks a merge or says why it does not, and a blocking job has
    # to be one that always reports (DR-0069 OPS-21). Reconciling the tables with
    # branch protection needs a token that can read it, which the workflow token
    # cannot, so that half is an operator command:
    #   python3 scripts/check-gate-enforcement.py --verify-protection GaugeWright/gaugedesk-src
    echo "== gate enforcement =="
    python3 scripts/check-gate-enforcement.py
    python3 scripts/check-gate-enforcement.py --self-test

    # Every place a failure is allowed not to count says which kind it is:
    # re-raised downstream, or tolerated. Whether a tolerated one has ever
    # actually worked is asked across every repository at once by
    # `tools/never-succeeded.mjs` in the GaugeWright repository, not here.
    echo "== suppressions =="
    python3 scripts/check-suppressions.py
    python3 scripts/check-suppressions.py --self-test

    # The projection is default-deny, so a published workflow can reference a
    # path that is not published and nothing here notices — the private tree
    # builds and every private gate is green. It breaks on the mirror, after the
    # merge, where `mirror-verdict` reports it (DR-0069 OPS-8). This runs in
    # `contracts` because that is a required context and this needs the private
    # tree to know what was withheld.
    echo "== mirror projection =="
    node scripts/check-mirror-projection.mjs

    echo "== spec audit =="
    python3 scripts/audit-gate.py

    # `validation.anchors: warn` in mkdocs.yml only rejects a broken heading
    # link if something runs the strict build *before* the merge, and for a
    # while nothing did: the deploy log was the first place a broken link could
    # appear, and by then the change that introduced it had already landed. It
    # runs in `contracts` because that is the section whose gate already
    # installs `docs/requirements.txt` (DOCS-1).
    #
    # This is now the only strict build of these docs that runs on a change to
    # them. The site is composed and published from gaugewright-site (DR-0094),
    # which cannot observe this repository, so a broken build caught here is
    # caught before it reaches a publish rather than by one.
    #
    # Output goes to the gitignored `site/`.
    echo "== documentation =="
    command -v mkdocs >/dev/null || {
        echo "mkdocs is not installed; run: python3 -m pip install -r docs/requirements.txt" >&2
        exit 1
    }
    mkdocs build --strict
    # Rendered from tools/docs-theme/repo-check.mjs in the GaugeWright
    # repository, which owns the documentation theme (DR-0093). It verifies both
    # that this repository still carries what was rendered into it and that the
    # theme reached the built page: --strict fails on a missing custom_dir but
    # resolves neither extra_css nor a template's own references, so a build that
    # lost its stylesheet, mark, or faces exits zero.
    node scripts/check-docs-theme.mjs
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
    # Both guard the same rule from opposite ends: nothing here writes a brand
    # value by hand. The first fails on a hex the vendored company tokens
    # already name; the second fails when the published customization file is
    # not what the panel defaults actually resolve to. The embed carried a
    # forked palette for as long as neither existed.
    echo "== brand tokens =="
    node scripts/check-brand-tokens.mjs
    node web/scripts/render-embed-theme.mjs --check

    # A stylesheet with no renderer is invisible to everything else here: the
    # brand-token scan reads it, the typecheck compiles around it, vite bundles
    # it, and the minifier ships it to a customer. Nothing asked whether anything
    # drew it, which is how two component removals left 219 rules behind.
    echo "== css renderers =="
    node scripts/check-css-renderers.mjs

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

    # cargo-deny adds the license, bans, and source policy that cargo audit does
    # not cover (deny.toml at the repo root, SOC 2 remediation 4.1). It operates
    # per-manifest, so it runs once per workspace, next to the matching audit
    # above. The advisories subcommand is deliberately excluded here: cargo audit
    # is the single enforcing advisory gate on all three lockfiles, so running a
    # moving advisory database through this gate too would only add
    # nondeterministic breakage. This gate is licenses, bans, and sources only —
    # the same split the whipplescript and cloud gates use.
    command -v cargo-deny >/dev/null || {
        echo "cargo-deny is not installed; run: cargo install cargo-deny --locked" >&2
        exit 1
    }
    for manifest in Cargo.toml src-tauri/Cargo.toml src-tauri-mobile/Cargo.toml; do
        cargo deny --manifest-path "$manifest" check licenses bans sources
    done

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
    echo "   the lockfile check above still ran, and the native-shells CI job compiles it on every" >&2
    echo "   pull request. To close the gap locally: sudo apt-get install -y $missing" >&2
}

# The release ships an MSI, and every gate above is Linux, so a change breaking
# the Windows build passes all of them and fails at release (DEVOPS.md OPS-26).
# The command lives in the script because the `windows-compiles` CI job runs
# that same script, so the two cannot drift. On a non-Windows host it says why
# it cannot answer instead of passing silently.
run_windows() {
    echo "== windows compile =="
    scripts/check-windows-compile.sh
}

# The mobile shell is a third cargo workspace, and it had the same two problems
# the desktop one did: its lockfile had drifted from its manifest, and nothing
# compiled it on a change — only `mobile-release.yml`, on dispatch.
#
# It compiles twice, because no single compile sees both halves of the crate.
# `--target aarch64-linux-android` is the half that matters, and a host check
# cannot stand in for it: only the mobile target sets `cfg(mobile)` and
# `target_os = "android"`, so only it compiles
# `plugins/device-identity/src/mobile.rs`, the plugin's command layer against
# that implementation rather than the desktop one, and the barcode-scanner
# registration behind the `cfg(any(target_os = "android", target_os = "ios"))`
# target table. Those are the release-critical paths, and a host check omits
# every one of them. The host check stays for what the mobile target drops in
# turn — `plugins/device-identity/src/desktop.rs`, which no other workspace
# compiles.
#
# Neither compile needs an Android NDK. `cargo check` emits metadata and never
# links a target artifact, so the graph's one C dependency — `ring`, through
# `rustls` — only needs a compiler that accepts its sources; nothing consumes
# the objects. `gcc-aarch64-linux-gnu` supplies one for the ~30 MB an apt
# package costs, against the ~1 GB of an SDK this check does not otherwise use.
# The iOS-only bindings and the generated platform projects still belong to
# `mobile-release.yml`, which has the SDKs and is where they are genuinely
# required.
mobile_target_prerequisites_present() {
    rustup target list --installed 2>/dev/null | grep -qx aarch64-linux-android || return 1
    command -v aarch64-linux-gnu-gcc >/dev/null 2>&1 || return 1
    command -v aarch64-linux-gnu-ar >/dev/null 2>&1
}

run_mobile() {
    local prerequisites="${1:-required}"
    echo "== mobile shell =="

    echo "-- lockfile is in sync with the manifest --"
    cargo metadata --manifest-path src-tauri-mobile/Cargo.toml --locked --format-version 1 >/dev/null

    local install_target="rustup target add aarch64-linux-android && sudo apt-get install -y gcc-aarch64-linux-gnu"
    echo "-- mobile cfg paths compile for an Android target --"
    if mobile_target_prerequisites_present; then
        # cc-rs looks up an `aarch64-linux-android-` prefixed toolchain by name,
        # which only an NDK installs; name the cross toolchain instead so
        # `ring`'s build script runs. Nothing links what it emits.
        CC_aarch64_linux_android=aarch64-linux-gnu-gcc \
        AR_aarch64_linux_android=aarch64-linux-gnu-ar \
            cargo check --manifest-path src-tauri-mobile/Cargo.toml --locked \
            --target aarch64-linux-android
    elif [ "$prerequisites" = required ]; then
        echo "mobile target compile requires the Android standard library and an aarch64 cross toolchain." >&2
        echo "install: $install_target" >&2
        exit 1
    else
        echo "-- mobile target compile SKIPPED: Android std or aarch64 cross toolchain absent --" >&2
        echo "   this is the half that compiles the mobile-only code; the native-shells CI job runs" >&2
        echo "   it on every pull request. To close the gap locally: $install_target" >&2
    fi

    # Same Tauri crates as the desktop shell, so the same native libraries and
    # the same predicate.
    echo "-- host compile --"
    if desktop_prerequisites_present; then
        cargo check --manifest-path src-tauri-mobile/Cargo.toml --locked
        return
    fi

    local missing="libwebkit2gtk-4.1-dev libjavascriptcoregtk-4.1-dev libgtk-3-dev libsoup-3.0-dev librsvg2-dev"
    if [ "$prerequisites" = required ]; then
        echo "mobile shell host compile requires GTK and WebKit development libraries." >&2
        echo "install: sudo apt-get install -y $missing" >&2
        exit 1
    fi

    echo "-- mobile shell host compile SKIPPED: GTK/WebKit development libraries absent --" >&2
    echo "   the lockfile check above still ran, and the native-shells CI job compiles it on every" >&2
    echo "   pull request. To close the gap locally: sudo apt-get install -y $missing" >&2
}

case "$section" in
    all) run_contracts; run_dependencies; run_rust; run_web; run_desktop best-effort; run_mobile best-effort; run_windows ;;
    contracts) run_contracts ;;
    dependencies) run_dependencies ;;
    desktop) run_desktop ;;
    mobile) run_mobile ;;
    rust) run_rust ;;
    web) run_web ;;
    windows) run_windows ;;
    *) echo "usage: scripts/check.sh [all|contracts|dependencies|desktop|mobile|rust|web|windows]" >&2; exit 2 ;;
esac

echo "== gaugedesk green bar PASSED ($section) =="
