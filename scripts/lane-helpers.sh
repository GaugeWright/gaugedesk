#!/usr/bin/env bash
# The helpers every lane shares (GaugeWright BUILD.md, DR-0124, stage 3).
#
# scripts/check.sh and scripts/section.sh both source this. They have to: from
# stage 3 a section's command lives in section.sh and is run as a Buck2 action
# in its own process, which inherits nothing from the shell that asked for it,
# while check.sh still needs the same predicates to decide which lanes to run at
# all. One copy, sourced twice, rather than two that drift.
#
# Nothing here runs anything on its own. Sourcing it defines the functions and
# settles `prerequisites` — the word deciding whether a missing tool refuses or
# skips. Absent, it is `required`, because a skip is not a verdict and a gate
# must never quietly stop gating.
prerequisites="${prerequisites:-required}"

# What this process could not establish. A section runs in its own process now —
# under Buck2, one the bar's shell cannot reach — so a fact collected here is
# also announced on stdout as `#unasserted: …`, which scripts/check.sh gathers
# into the line it closes with.
advisories_unavailable=0
skipped_prerequisites=""

# The Debian archive tooling `scripts/test-apt-repository.sh` drives. On Linux,
# every runner that builds a package and every machine that installs one has it,
# so an absence there is a workstation missing `dpkg-dev`, not a platform that
# cannot answer.
apt_repository_prerequisites_present() {
    local tool
    for tool in dpkg-deb dpkg-scanpackages gpg gpgv apt-get apt-cache xz; do
        command -v "$tool" >/dev/null 2>&1 || return 1
    done
}

# Independent steps of one section, run at once.
#
# Most of `web` is single-threaded processes — six tsc runs, four vite builds,
# a vitest run, three node test runs — that read one tree and write disjoint
# outputs, and running them one after another left an eighteen-core machine
# mostly idle for the length of the section. So they run together. Each step's
# transcript is captured to its own file and printed, in the order the steps
# were given, once every one of them has finished: the output reads exactly as
# the sequential form did, and a failure appears under its own heading rather
# than interleaved with whatever else was running. Every step runs to completion
# even when another fails, for the same reason `all` runs every section — they
# are independent, and the bar reports on each of them.
#
# A step is one string, run by this same bash under errexit, so a step of
# several commands stops at its first failure exactly as it would inline; see
# the note above `run_all` for why a function call in this shell would not.
# Job control is on while the steps start so that each is its own process
# group. Without it bash gives an asynchronous list an ignored SIGINT, which is
# how an interrupted section would leave a dozen node processes running to
# completion; with it the trap can stop every step's whole tree. It is off again
# before the wait, so bash reports nothing about the jobs as they finish.
parallel_steps() {
    local dir n=0 i rc status=0
    local pids=() headings=()
    dir="$(mktemp -d)"
    set -m
    while [ $# -ge 2 ]; do
        headings[$n]="$1"
        "$BASH" -c "set -euo pipefail; $2" > "$dir/$n.log" 2>&1 &
        pids[$n]=$!
        n=$((n + 1))
        shift 2
    done
    set +m
    if [ $# -ne 0 ]; then
        echo "parallel_steps: a heading with no command: $1" >&2
        return 2
    fi
    trap 'for pid in "${pids[@]}"; do kill -TERM -- "-$pid" 2>/dev/null; done; exit 130' INT TERM
    for ((i = 0; i < n; i++)); do
        rc=0
        wait "${pids[$i]}" || rc=$?
        echo "${headings[$i]}"
        cat "$dir/$i.log"
        if [ "$rc" -ne 0 ]; then
            echo "-- FAILED (exit $rc): ${headings[$i]} --" >&2
            status=1
        fi
    done
    trap - INT TERM
    rm -rf "$dir"
    return "$status"
}

audit_npm_tree() {
    local dir="$1" output attempt

    for attempt in 1 2 3; do
        if output="$(npm --prefix "$dir" audit --omit=dev --json 2>&1)"; then
            echo "$dir: no production advisories"
            return 0
        fi

        if printf '%s' "$output" | node scripts/npm-audit-outcome.mjs; then
            # Re-run for the human-readable report: the operator needs the
            # advisory, not the JSON this classification read.
            npm --prefix "$dir" audit --omit=dev || true
            echo "production advisories found in $dir" >&2
            return 1
        fi

        if [ "$attempt" -lt 3 ]; then
            sleep "$((attempt * 5))"
        fi
    done

    advisories_unavailable=$((advisories_unavailable + 1))
    echo "#unasserted: npm advisories unaudited for $dir"
    echo "!! ADVISORIES NOT AUDITED for $dir: npm answered no report in 3 attempts." >&2
    echo "!! This says nothing about $dir — the next run audits it again." >&2
    printf '%s\n' "$output" | tail -3 >&2
    return 0
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

# How a section resolves a prerequisite the host has not got. The word is the
# same everywhere, and anything else — including a mistyped flag — resolves to
# `required`, so a typo can never quietly buy a skip.
#
# Which caller has to say it differs, and that follows from what the section
# name means. `desktop` and `mobile` exist to run a compile, so asking for one
# by name is asking for that compile: they enforce by default, and `all` names
# `best-effort`. `contracts` is two dozen checks of which the strict documentation
# build is one, so asking for it by name is not asking for mkdocs: it is
# best-effort by default, and the gate the fleet runs names `required`
# (GaugeWright DR-0131).
prerequisite_policy() {
    if [ "${1:-}" = best-effort ]; then echo best-effort; else echo required; fi
}

prerequisite() {
    command -v "$1" >/dev/null 2>&1 && return 0
    if [ "$prerequisites" = required ]; then
        echo "$2 requires $1." >&2
        echo "install: $3" >&2
        exit 1
    fi
    echo "-- $2 SKIPPED: $1 is not installed --" >&2
    echo "   the fleet installs it and runs this on every push and pull request (gaugewright/bar)." >&2
    echo "   To close the gap locally: $3" >&2
    skipped_prerequisites="${skipped_prerequisites:+$skipped_prerequisites; }$2 not run"
    echo "#unasserted: $2 not run"
    return 1
}
