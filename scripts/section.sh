#!/usr/bin/env bash
# Every section of the green bar, each stated once (GaugeWright BUILD.md, stages 2 and 3).
#
#   scripts/section.sh <name>
#
# scripts/check.sh runs a section either directly, through this script, or as
# the Buck2 target of the same name — which also runs this script, in this
# checkout, and re-runs it only when a file the target declares has changed.
# The command lives here and nowhere else. Stage 3 brought in the other lanes:
# the cargo workspace, the web trees, the desktop, mobile and windows shells,
# and the advisory sweep — which reads two live databases and is therefore a
# `check_world` target, refusing to run without a nonce naming the run.
#
# Two things are still not here, and one stage owns both: the WhippleScript
# host-action sections read a peer checkout, an input outside this cell until
# stage 4 makes it an edge.
#
# `prerequisites` is check.sh's word for whether a missing tool refuses or
# skips: `required` when the gate runs a lane directly, `best-effort` under
# `all`. It is passed in by check.sh; run any other way — through Buck2, or by
# hand — it is absent, and absent means required, because a skip is not a
# verdict and the gate must never quietly stop gating.
set -euo pipefail
cd "$(dirname "$0")/.."

# The predicates and runners the lanes share, defined once and sourced by both
# this script and scripts/check.sh. A section runs in its own process — under
# Buck2, one that inherits nothing from the shell that asked for it — so a
# helper defined in check.sh would not be here when the command needs it.
# shellcheck source=scripts/lane-helpers.sh
. scripts/lane-helpers.sh

# Whether this tree is the curated public projection rather than the trunk.
#
# `specs/` is fully private and is never published (see the ALLOW list in
# scripts/publish-public-mirror.sh), so its absence is what distinguishes the
# mirror from a checkout of this repository.
projected() { [ ! -d specs ]; }

# A section whose script this tree does not carry.
#
# On the trunk that is a broken checkout and fails, loudly, naming the file.
# On the projection it is the publish filter deliberately not carrying it, and
# until 2026-09-22 the whole bar died there: `scripts/check.sh` on the
# published mirror failed three sections with "No such file or directory", so
# anyone who cloned the public repository and ran the documented command got
# errors about files that were never meant to be there.
#
# The honest answer is the split the shared guide draws for a prerequisite the
# host cannot supply, applied to a file the tree was never given: say what was
# not established, on stdout where the fleet's ledger reads it, and let every
# other section run.
carries() {
    [ -e "$1" ] && return 0
    if projected; then
        echo "#unasserted: $2 not run: the public tree does not carry $1"
        echo "-- $2 SKIPPED: $1 is not published to the mirror --" >&2
        return 1
    fi
    echo "$2 requires $1, which this checkout does not have." >&2
    exit 1
}

case "${1:-}" in
  agent-guide)             if carries scripts/check-agent-guide.mjs "the agent guide check"; then node scripts/check-agent-guide.mjs; fi ;;
  carries-agent-guide|carries-agent-guide-checker|carries-brand-tokens|carries-brand-tokens-checker)
    # The cross-repository edge (GaugeWright DR-0124 stage 4). In a workspace
    # the bar builds the `carries` target and never reaches here; reaching here
    # means there is no `gaugewright` cell to compare against.
    echo "#unasserted: $1 needs a materialized workspace; the digest check answered instead"
    echo "-- $1 SKIPPED: no gaugewright cell outside a workspace --" >&2 ;;
  check-composition)       node --test scripts/check-lanes.test.mjs scripts/check-live-fabric.test.mjs ;;
  architecture-boundaries) python3 scripts/architecture-check.py ;;
  license-boundary)        python3 scripts/check-license-boundary.py ;;
  product-contracts)       node scripts/check-product-contracts.mjs --enforce-local-evidence ;;
  gaugeapp-contract)
    node scripts/check-gaugeapps-contract.mjs
    node scripts/check-gaugeapp-operation-coverage.mjs ;;
  action-provenance)
    node scripts/check-action-provenance.mjs
    node --test scripts/check-action-provenance.test.mjs ;;
  stats-report-contract)   node scripts/check-whipplescript-stats-report.mjs ;;
  tokenwright-metadata)
    node scripts/check-tokenwright-environment.mjs
    node scripts/check-tokenwright-carried-surface.mjs ;;
  updater-endpoint)        node scripts/check-updater-endpoint.mjs ;;
  release-version-sources) python3 scripts/check-release-version-sources.py ;;
  app-icons)               node scripts/check-app-icons.mjs ;;
  release-identity)        node --test scripts/build-release-identity.test.mjs \
                                      scripts/check-updater-signature.test.mjs ;;
  codex-login-helper)      node --test sidecar/codex-oauth-login.test.mjs ;;
  production-canary-contract)
    node scripts/check-production-canaries.mjs
    node --test \
        scripts/canary-preflight.test.mjs \
        scripts/provision-canary.test.mjs \
        scripts/check-production-canaries.test.mjs \
        scripts/production-wiring-canary.test.mjs \
        scripts/run-production-wiring-canaries.test.mjs \
        scripts/wiring-canary/runners.test.mjs \
        scripts/wiring-canary/administration-agent-erasure.test.mjs \
        scripts/wiring-canary/account-boxes.test.mjs \
        scripts/wiring-canary/totp.test.mjs \
        scripts/wiring-canary/capture-provider-state.test.mjs \
        scripts/wiring-canary/diagnostic.test.mjs \
        scripts/wiring-canary/hosted-account-session.test.mjs \
        scripts/wiring-canary/managed-entitlement-mint.test.mjs \
        scripts/wiring-canary/poll.test.mjs \
        web/e2e/production-account-session-canary.test.mjs \
        web/e2e/production-passkey-account-canary.test.mjs \
        web/e2e/production-native-session-canary.test.mjs ;;
  client-calls)
    node --test scripts/check-client-calls.test.mjs
    node scripts/check-client-calls.mjs ;;
  advisory-classification)
    node --test scripts/npm-audit-outcome.test.mjs
    bash scripts/advisory-database.test.sh
    bash scripts/apt-install-action.test.sh ;;
  build-coverage)          node scripts/check-build-coverage.mjs ;;
  gate-enforcement)
    python3 scripts/check-gate-enforcement.py
    python3 scripts/check-gate-enforcement.py --self-test ;;
  suppressions)
    python3 scripts/check-suppressions.py
    python3 scripts/check-suppressions.py --self-test ;;
  case-collisions)         node scripts/check-case-collisions.mjs ;;
  mirror-projection)       node scripts/check-mirror-projection.mjs ;;
  spec-audit)              python3 scripts/audit-gate.py ;;
  documentation)
    if command -v mkdocs >/dev/null 2>&1; then
        mkdocs build --strict
        # Rendered from tools/docs-theme/repo-check.mjs in the GaugeWright
        # repository, which owns the documentation theme (DR-0093). It verifies both
        # that this repository still carries what was rendered into it and that the
        # theme reached the built page: --strict fails on a missing custom_dir but
        # resolves neither extra_css nor a template's own references, so a build that
        # lost its stylesheet, mark, or faces exits zero.
        node scripts/check-docs-theme.mjs
    elif [ "${prerequisites:-required}" = required ]; then
        echo "the strict documentation build requires mkdocs." >&2
        echo "install: python3 -m pip install -r docs/requirements.txt" >&2
        exit 1
    else
        echo "-- documentation SKIPPED: mkdocs is not installed --" >&2
        echo "   the contracts CI job installs the docs toolchain and runs this, and the theme" >&2
        echo "   check that reads what it builds, on every pull request. To close the gap" >&2
        echo "   locally: python3 -m pip install -r docs/requirements.txt" >&2
    fi ;;
  # A lockfile that no longer satisfies the manifests is a red the gate meets
  # and the workstation does not, because every other cargo section resolves
  # freely and writes the lock on its way past. `--locked` refuses instead, so
  # the drift fails where `cargo metadata` alone repairs it, rather than after
  # a round trip through the fleet.
  lockfile)                cargo metadata --locked --format-version 1 >/dev/null ;;
  formatting)              cargo fmt --all --check ;;
  lints)                   cargo clippy --workspace --all-targets -- -D warnings ;;
  tests)
    # Where the tests write. The app crate's fixtures build a workbench on disk
    # per test — SQLite stores, worktrees, seeded files — and that file churn is
    # what the tests are bound by, not CPU: on the hosted runner the app crate's
    # unit tests alone took 246 s of a 688 s job, against a disk-backed /tmp. On
    # Linux, /dev/shm is a tmpfs, so a run whose tests fit there runs them from
    # memory. A per-run directory, removed when this script ends however it
    # ends. It is skipped, and says so, where there is no tmpfs to use or too
    # little of it, because a test failing on ENOSPC would read as a broken
    # tree; macOS has no tmpfs, so nothing changes there. What is asserted does
    # not change: the same tests, writing the same roots, on a different device.
    #
    # It asks for 1 GB free. The whole suite peaks at 48 MB of temporary files
    # across eighteen processes and leaves none behind, so that is twenty times
    # the need.
    tests_tmpdir=""
    if [ "$(uname -s)" = Linux ] && [ -d /dev/shm ] && [ -w /dev/shm ]; then
        free_kb="$(df -Pk /dev/shm | awk 'NR == 2 { print $4 }')"
        if [ "${free_kb:-0}" -ge $((1024 * 1024)) ]; then
            tests_tmpdir="$(mktemp -d /dev/shm/gaugedesk-check.XXXXXX)"
            # shellcheck disable=SC2064 # expanded now on purpose: the path is fixed.
            trap "rm -rf '$tests_tmpdir'" EXIT
            export TMPDIR="$tests_tmpdir"
            echo "-- tests write to $tests_tmpdir (tmpfs) --"
        else
            echo "-- tests write to the default TMPDIR: /dev/shm has ${free_kb:-0} KB free, under the 1 GB this asks for --"
        fi
    fi
    # cargo-nextest runs each test in its own process and schedules the whole
    # set across cores itself. Use-if-present, never a new prerequisite: its
    # absence falls back to exactly the command this has always been. nextest
    # does not run doctests and this workspace has them, so `cargo test --doc`
    # keeps them in the bar; it compiles nothing the run before it has not
    # already built.
    if command -v cargo-nextest >/dev/null 2>&1; then
        cargo nextest run --workspace --no-fail-fast
        cargo test --workspace --doc
    else
        cargo test --workspace
    fi ;;
  no-default-features)
    # The open build must stay buildable without the enterprise features. Keep
    # this feature graph out of the all-feature test graph's fingerprints:
    # cargo can otherwise remove a package fingerprint while the next graph is
    # starting its build script. The output is still owned by this worktree;
    # only the incompatible graph gets its own subdirectory.
    CARGO_TARGET_DIR="$PWD/target/no-default-features" \
        cargo check -p gaugedesk-app --no-default-features --all-targets ;;
  web)
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
    [ -d ee/web/node_modules ] || npm --prefix ee/web ci
    [ -d ee/sidecar/saml-verify/node_modules ] || npm --prefix ee/sidecar/saml-verify ci

    # Everything below reads the installed trees and the generated modules above
    # and writes only its own output — the vite builds each to their own
    # `dist-*` — so the steps are independent, and they run at once. The
    # transcripts still print in this order, each under its heading.
    #
    # Brand tokens: both guard the same rule from opposite ends — nothing here
    # writes a brand value by hand. The first fails on a hex the vendored
    # company tokens already name; the second fails when the published
    # customization file is not what the panel defaults actually resolve to.
    # The embed carried a forked palette for as long as neither existed.
    #
    # CSS renderers: a stylesheet with no renderer is invisible to everything
    # else here — the brand-token scan reads it, the typecheck compiles around
    # it, vite bundles it, and the minifier ships it to a customer. Nothing
    # asked whether anything drew it, which is how two component removals left
    # 219 rules behind.
    parallel_steps \
        "== brand tokens ==" \
        "node scripts/check-brand-tokens.mjs; node web/scripts/render-embed-theme.mjs --check" \
        "== css renderers ==" \
        "node scripts/check-css-renderers.mjs" \
        "== web typecheck ==" \
        "npm --prefix web run typecheck" \
        "== web typecheck (each client in isolation) ==" \
        "npm --prefix web run typecheck:split" \
        "== web tests ==" \
        "npm --prefix web run test" \
        "== web build: open ==" \
        "npm --prefix web run build:open" \
        "== web build: embed ==" \
        "npm --prefix web run build:embed" \
        "== web build: apps (open) ==" \
        "npm --prefix web run build:apps:open" \
        "== enterprise web tests ==" \
        "npm --prefix ee/web test" \
        "== enterprise web typecheck ==" \
        "npm --prefix ee/web run typecheck" \
        "== enterprise web build ==" \
        "npm --prefix ee/web run build" \
        "== saml verify sidecar ==" \
        "npm --prefix ee/sidecar/saml-verify test" ;;
  dependencies)
    # RustSec's advisory database is a third party, and the subject of this gate
    # is the lockfiles this repository tracks. Those are different things, and a
    # failure of the second used to be reported as a failure of the first — the
    # same shape as the npm outage handled below, which failed a green bar four
    # runs running over a tree nobody had touched.
    #
    # The cargo half recovers better, because the database is a git checkout
    # that persists: an unreachable RustSec means "audited against the copy on
    # disk", not "not audited". `resolve_advisory_database` separates reaching
    # it from auditing against it, and its own tests run in the contracts
    # section.
    carries scripts/advisory-database.sh "the cargo advisory audit" || exit 0
    # shellcheck source=scripts/advisory-database.sh
    source scripts/advisory-database.sh
    resolve_advisory_database

    # `prerequisite` is first so that it always evaluates: behind the database
    # test it would never be reached on a host whose RustSec copy is missing,
    # and the gate would pass with cargo-audit absent.
    if prerequisite cargo-audit "the cargo advisory audit" "cargo install cargo-audit" \
       && [ "$ADVISORY_DB_MISSING" -eq 0 ]; then
        # Before trusting a clean audit, check that these flags can still report
        # a dirty one.
        assert_findings_still_fail

        # Unquoted on purpose: ADVISORY_DB_FLAGS is a flag list this repository
        # sets from a fixed set of literals, never from input.
        # shellcheck disable=SC2086
        cargo audit $ADVISORY_DB_FLAGS --file Cargo.lock
        # shellcheck disable=SC2086
        cargo audit $ADVISORY_DB_FLAGS --file src-tauri/Cargo.lock
        # shellcheck disable=SC2086
        cargo audit $ADVISORY_DB_FLAGS --file src-tauri-mobile/Cargo.lock
    fi

    # cargo-deny adds the license, bans, and source policy that cargo audit does
    # not cover (deny.toml at the repo root, SOC 2 remediation 4.1). It operates
    # per-manifest, so it runs once per workspace, next to the matching audit
    # above. The advisories subcommand is deliberately excluded here: cargo audit
    # is the single enforcing advisory gate on all three lockfiles, so running a
    # moving advisory database through this gate too would only add
    # nondeterministic breakage. This gate is licenses, bans, and sources only —
    # the same split the whipplescript and cloud gates use.
    if prerequisite cargo-deny "the supply-chain policy check" "cargo install cargo-deny --locked"; then
        for manifest in Cargo.toml src-tauri/Cargo.toml src-tauri-mobile/Cargo.toml; do
            cargo deny --manifest-path "$manifest" check licenses bans sources
        done
    fi

    # Production only. The dev trees are vite, wrangler, and playwright, none of
    # which reach a user.
    #
    # npm's advisory service is a third party too, and the same split applies: a
    # finding is a fact about this repository and hard-fails; an unreachable
    # endpoint is a fact about npm, and is retried, reported in a line nobody can
    # miss, and survived. On 2026-09-04 the bulk advisories endpoint spent an
    # hour answering `Service Unavailable`, which read here as a broken tree.
    #
    # `scripts/npm-audit-outcome.mjs` decides which of the two a non-zero exit
    # was. It is a separate file with its own tests because misreading a finding
    # as an outage is the one way this could hide a known-vulnerable dependency
    # behind a warning nobody has to clear.
    while IFS= read -r lock; do
        audit_npm_tree "${lock%/package-lock.json}"
    done < <(find . -name package-lock.json -not -path '*/node_modules/*' -print)

    # The advisory database's own state, for the line check.sh closes with.
    if [ "${ADVISORY_DB_MISSING:-0}" -gt 0 ]; then
        echo "#unasserted: cargo advisories unaudited"
    elif [ "${ADVISORY_DB_STALE:-0}" -gt 0 ]; then
        echo "#unasserted: cargo advisories from an unrefreshed database"
    fi ;;
  desktop)
    echo "-- lockfile is in sync with the manifest --"
    cargo metadata --manifest-path src-tauri/Cargo.toml --locked --format-version 1 >/dev/null

    if desktop_prerequisites_present; then
        cargo check --manifest-path src-tauri/Cargo.toml --locked
        exit 0
    fi

    missing="libwebkit2gtk-4.1-dev libjavascriptcoregtk-4.1-dev libgtk-3-dev libsoup-3.0-dev librsvg2-dev"
    if [ "$prerequisites" = required ]; then
        echo "desktop shell compile requires GTK and WebKit development libraries." >&2
        echo "install: sudo apt-get install -y $missing" >&2
        exit 1
    fi

    echo "-- desktop shell compile SKIPPED: GTK/WebKit development libraries absent --" >&2
    echo "   the lockfile check above still ran, and the native-shells CI job compiles it on every" >&2
    echo "   pull request. To close the gap locally: sudo apt-get install -y $missing" >&2 ;;
  windows)
    carries scripts/check-windows-compile.sh "the Windows compile" || exit 0
    scripts/check-windows-compile.sh ;;
  mobile)
    echo "-- lockfile is in sync with the manifest --"
    cargo metadata --manifest-path src-tauri-mobile/Cargo.toml --locked --format-version 1 >/dev/null

    install_target="rustup target add aarch64-linux-android && sudo apt-get install -y gcc-aarch64-linux-gnu"
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
        exit 0
    fi

    missing="libwebkit2gtk-4.1-dev libjavascriptcoregtk-4.1-dev libgtk-3-dev libsoup-3.0-dev librsvg2-dev"
    if [ "$prerequisites" = required ]; then
        echo "mobile shell host compile requires GTK and WebKit development libraries." >&2
        echo "install: sudo apt-get install -y $missing" >&2
        exit 1
    fi

    echo "-- mobile shell host compile SKIPPED: GTK/WebKit development libraries absent --" >&2
    echo "   the lockfile check above still ran, and the native-shells CI job compiles it on every" >&2
    echo "   pull request. To close the gap locally: sudo apt-get install -y $missing" >&2 ;;
  *) echo "section.sh: unknown section '${1:-}'" >&2; exit 2 ;;
esac
