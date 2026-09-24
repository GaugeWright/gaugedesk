#!/usr/bin/env bash
# The green bar for gaugedesk-src. This is the complete required check set that
# gates a change, and the configured CI gates run this same script, so a passing
# run here and a passing gate cannot mean different things.
#
#   scripts/check.sh            everything below
#   scripts/check.sh required   everything below, as the gate (every prerequisite enforced)
#   scripts/check.sh rust       one section, while iterating
#   scripts/check.sh web
#   scripts/check.sh contracts
#
# `all` runs every section even when one of them fails and names the failures
# together at the end, so a red `dependencies` — an advisory about the world,
# not about the diff — can no longer decide whether the bar says anything about
# the change under test. The sections that never touch the cargo target
# directory — contracts, web, dependencies — run alongside the ones that do,
# and their transcripts are replayed in that order once the cargo sections
# finish. See run_all.
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
#
# `contracts` carries the same split for the same reason and resolves it the
# other way round, because the section is not its documentation build: a bare
# `scripts/check.sh contracts` reports an absent mkdocs and runs everything
# else, while the contracts CI job asks for `required` and refuses. See
# prerequisite_policy.
set -euo pipefail

# `all` runs each section as a child invocation of this same script (see
# run_all), so resolve this file absolutely before the cd can make a relative
# path stale. The children are launched through $BASH rather than by executing
# the path, so the run does not depend on this file's mode bit and each child is
# the same interpreter as the parent.
#
# $BASH_SOURCE rather than $0 because this file is also sourced — see the guard
# above the dispatch — and under a source $0 is the sourcing script. Executed,
# the two are the same thing.
self="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
cd "$(dirname "${BASH_SOURCE[0]}")/.."

section="${1:-all}"

# The predicates and runners every lane shares. scripts/section.sh sources the
# same file: from stage 3 a section's command runs in its own process — under
# Buck2, one this shell cannot reach — so a helper defined here would not be
# there when the command needs it.
# shellcheck source=scripts/lane-helpers.sh
. scripts/lane-helpers.sh

# Stages 2 and 3 of the Buck2 migration (GaugeWright BUILD.md, DR-0124): every
# section of every lane is a Buck2 target declaring what it reads, except the
# two that read the sibling whipplescript checkout, which stage 4 owns. When
# this checkout is a cell of a materialized workspace, a section runs through
# Buck2, which spares the re-run when nothing the section declares has changed
# and otherwise runs scripts/section.sh exactly as the direct path does. When
# it is not — a worktree, a CI runner, a host without buck2 — the same script
# runs directly. Same order, same command, same output, same verdict; Buck2 is
# under this bar, never beside it. Inside a Buck2 action already running the
# whole bar, the direct path is taken so no nested client meets the daemon.
# (`section` is the lane variable above, hence the name.)
#
# A section whose answer comes from outside this tree is spared nothing: it is
# a `check_world` target, which refuses to run unless the invocation names the
# run, so it cannot be answered from a cache by accident.
via_buck2=""
if [ -z "${GREEN_BAR_INSIDE_BUCK2:-}" ] && command -v buck2 >/dev/null 2>&1 \
   && buck2 audit cell 2>/dev/null | grep -qx "gaugedesk: $(pwd -P)"; then
  via_buck2=1
fi
# One nonce for the whole run, and the prerequisite word beside it: the first
# is what a world-reading section demands before it will run, the second is part
# of every action's key, so a run that skipped a section is never served to one
# that required an answer.
#
# EXPORTED, because `all` runs three lanes at once and each is a fresh
# invocation of this script. Left unexported they mint three different nonces,
# which are three different Buck2 CONFIGURATIONS arriving at one daemon at
# once — and the daemon answers by cancelling a transaction, so a lane fails
# for a reason that has nothing to do with the tree. One run is one nonce.
export GREEN_BAR_RUN="${GREEN_BAR_RUN:-$(date +%s)-$$}"

# What the sections could not establish. Each announces it on stdout as
# `#unasserted: …` — it has to, because a section is a separate process now and
# under Buck2 one this shell cannot reach at all, while the bar's closing line
# has always said what a run did not assert. Output is still streamed as it
# arrives; the tee is what makes it readable twice.
section_unasserted=""
gate_section() {
  local transcript status=0
  transcript="$(mktemp)"
  if [ -n "$via_buck2" ]; then
    local log
    log="$(buck2 build "//:$1" -c "green_bar.run=$GREEN_BAR_RUN" \
      -c "green_bar.prerequisites=${prerequisites:-required}" --show-full-simple-output)" || status=$?
    [ "$status" -eq 0 ] && { cat "$log" | tee "$transcript"; status=$?; }
  else
    prerequisites="${prerequisites:-required}" scripts/section.sh "$1" 2>&1 | tee "$transcript"
    status=$?
  fi
  while IFS= read -r line; do
    case "$line" in
      "#unasserted: "*)
        section_unasserted="${section_unasserted:+$section_unasserted; }${line#\#unasserted: }" ;;
    esac
  done < "$transcript"
  rm -f "$transcript"
  return "$status"
}


# $1 = "best-effort" (a developer asking for this section, and `all`) or
# "required" (the contracts CI job), which decides whether an absent docs
# toolchain is reported or fails. See prerequisite_policy for why the default
# runs the other way from the native shells'.
run_contracts() {
    local prerequisites="${1:-best-effort}"

    echo "== agent guide =="
    gate_section agent-guide

    # What this repository carries of the GaugeWright repository's, compared
    # against what that repository builds (DR-0124 stage 4).
    echo "== agent guide, as an edge =="
    gate_section carries-agent-guide
    gate_section carries-agent-guide-checker

    # The same edge for the brand tokens and the checker that verifies them.
    # The checker seals its own body (GaugeWright#282), so an EDIT to it
    # already fails the brand-tokens section; only this says whether it is the
    # CURRENT one, which a correctly sealed older copy is not.
    echo "== brand tokens, as an edge =="
    gate_section carries-brand-tokens
    gate_section carries-brand-tokens-checker

    # This script's own composition. `all` running every section and reporting
    # the failures together is a property with no line number — it shows only in
    # what a failing run still manages to say — and reverting it leaves every
    # section working and every gate green. It is checked here because
    # `contracts` is a required context and this needs nothing but bash.
    echo "== check composition =="
    gate_section check-composition

    echo "== architecture boundaries =="
    gate_section architecture-boundaries

    echo "== license boundary =="
    gate_section license-boundary

    echo "== product contracts =="
    gate_section product-contracts

    echo "== GaugeApp page/action contract =="
    gate_section gaugeapp-contract
    # The contract being well formed is not the same as the product having
    # built it. This proves every contracted operation exists in a tracked
    # source, or is named as a gap that has not been built yet.

    echo "== action provenance inventory =="
    gate_section action-provenance

    echo "== WhippleScript workstream host contract =="
    node scripts/check-whipplescript-workstream-contract.mjs
    python3 scripts/check-whipplescript-host-action.py

    # The other direction across the same pin: WhippleScript meters, this
    # repository prices. The runtime's own records say it does not price, so
    # whether its report is sufficient to price FROM is a question only a
    # consumer can answer, and this is where the answer is kept.
    echo "== WhippleScript stats report contract =="
    gate_section stats-report-contract

    echo "== TokenWright native-control metadata =="
    gate_section tokenwright-metadata

    # The updater endpoint is compiled into every shipped binary and cannot be
    # corrected for a client that already has it, so its mistakes are permanent
    # in the field and silent at build time. In particular an endpoint missing
    # {{current_version}} keeps working — right up until a key rotation strands
    # every client not already on the current key (DR-0080).
    echo "== updater endpoint =="
    gate_section updater-endpoint

    # The neighbouring release fact, and it fails the same way: silently, in the
    # field. A release derives its version from its tag, and the version the app
    # SHOWS and REPORTS was derived separately from the version its bundle is
    # NAMED — so v0.4.6 through v0.4.8 each installed under its own name and
    # then told the user, and every Home it spoke to, that it was 0.4.5. Every
    # gate was green throughout.
    echo "== release version sources =="
    gate_section release-version-sources

    # The other bundle fact nothing else looks at. `generate_context!` requires
    # only that an icon be RGBA, which a flattened matte satisfies, so an icon
    # whose transparency has been baked out builds and ships clean and then
    # draws a white box around the mark on every dark shell. It shipped that way
    # twice, the second time in a commit whose entire subject was these files.
    # It runs here rather than in `desktop` because reading a PNG needs none of
    # what linking a Tauri shell needs.
    echo "== app icons =="
    gate_section app-icons

    # The artifact side of the same manifest: what a built bundle says about the
    # contract it holds, and the canonical digest both this section and the
    # hosted surfaces compare (DR-0051). A test no section names is a test
    # nothing runs, which is the state this one was committed in.
    echo "== release identity =="
    gate_section release-identity

    # The desktop sign-in helper. It is plain node with no npm tree of its own, so
    # it runs here rather than in `web`. What it guards is the fixed loopback
    # callback port: every way the helper can fail to let go of it is a way to
    # break the next sign-in, and nothing ran this file's subject before.
    echo "== codex login helper =="
    gate_section codex-login-helper

    echo "== production canary contract =="
    gate_section production-canary-contract

    echo "== client calls =="
    gate_section client-calls

    # Absence has no line number: a crate nothing compiles and a lockfile
    # nothing audits look exactly like a crate and a lockfile. This enumerates
    # what is tracked, reads coverage out of this script, and fails on the
    # difference — which is how `src-tauri` and `src-tauri-mobile` should have
    # been found, rather than by a release and an advisory finding them.
    # Rendered from tools/shared-checks/build-coverage.mjs in the GaugeWright
    # repository, which owns it and tests it. A local edit fails here.
    # Both halves of the advisory question: that npm's error document is not
    # read as a report, and that an unreachable RustSec degrades to an
    # unrefreshed database rather than to a pass. Each decides whether a
    # non-zero audit fails this run, so the one way either could hide a real
    # vulnerability is by being wrong in the safe-looking direction.
    echo "== advisory outcome classification =="
    gate_section advisory-classification
    # The same question one layer down: the bounded apt install decides
    # whether a runner's failing vendor index reddens a healthy tree, and
    # tolerating one must not tolerate a package that never installed.

    # The archive one layer up: that a built package is what the archive will
    # accept, that the indexes and signatures an `apt-get update` reads are the
    # ones these scripts write, and that tampered metadata is refused. It ran
    # nowhere — `sync-public-mirror.yml` names the file among its path triggers,
    # which publishes it without ever invoking it — so the distribution lane
    # every Linux install arrives through was covered by a script no gate ran.
    # It belongs in `contracts` because it needs only Debian tooling.
    echo "== apt repository =="
    # The distinction the hard failure below did not draw. On Linux an absence
    # is an incomplete workstation and is told to install the packages. On a
    # host that is not Linux it is a platform that cannot answer: `apt-get` and
    # `dpkg-scanpackages` are not tools a Mac is missing, they are tools that
    # administer a system a Mac does not have, and installing them would test an
    # archive nothing on that machine consumes. So this skips there, the way
    # `check-windows-compile.sh` skips off Windows and for the same reason —
    # the section stays runnable on every host the green bar runs on, and the
    # Linux CI job is where the command is answerable. What the gate covers is
    # unchanged: `contracts` runs on Linux in CI, where this still runs and
    # still fails on absent tooling.
    if [ "$(uname -s)" != "Linux" ]; then
        echo "-- apt repository SKIPPED: host is $(uname -s), and the Debian archive tooling is Linux-only --" >&2
        echo "   the contracts CI job runs this same section on Linux, where it does not skip" >&2
    else
        apt_repository_prerequisites_present || {
            echo "the APT repository test needs Debian archive tooling." >&2
            echo "install: sudo apt-get install -y dpkg-dev gnupg apt-utils xz-utils" >&2
            exit 1
        }
        bash scripts/test-apt-repository.sh
    fi

    echo "== build coverage =="
    gate_section build-coverage

    # A job either blocks a merge or says why it does not, and a blocking job has
    # to be one that always reports (DR-0069 OPS-21). Reconciling the tables with
    # branch protection needs a token that can read it, which the workflow token
    # cannot, so that half is an operator command:
    #   python3 scripts/check-gate-enforcement.py --verify-protection GaugeWright/gaugedesk-src
    echo "== gate enforcement =="
    gate_section gate-enforcement

    # Every place a failure is allowed not to count says which kind it is:
    # re-raised downstream, or tolerated. Whether a tolerated one has ever
    # actually worked is asked across every repository at once by
    # `tools/never-succeeded.mjs` in the GaugeWright repository, not here.
    echo "== suppressions =="
    gate_section suppressions

    # The projection is default-deny, so a published workflow can reference a
    # path that is not published and nothing here notices — the private tree
    # builds and every private gate is green. It breaks on the mirror, after the
    # merge, where `mirror-verdict` reports it (DR-0069 OPS-8). This runs in
    # `contracts` because that is a required context and this needs the private
    # tree to know what was withheld.
    # Runs before the mirror projection because it asks a question about the
    # tree itself, and the answer decides whether a bundle can build at all on
    # two of the three platforms a release targets.
    echo "== case collisions =="
    gate_section case-collisions

    echo "== mirror projection =="
    gate_section mirror-projection

    echo "== spec audit =="
    gate_section spec-audit

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
    #
    # mkdocs is not a tool this host is missing the way a Mac is missing
    # `dpkg-scanpackages`; it is one a workstation has not installed yet, which
    # is the harder case the shared agent guide draws a line through. Failing
    # every run of this section on a machine without the docs toolchain said
    # nothing about the change under test — the two dozen checks above had already
    # answered everything they could — and a red bar that is about the host is
    # how a reader learns to wave red through. So the section reports the gap
    # and names the command that closes it, and the gate refuses.
    #
    # What the gate covers is unchanged. The contracts CI job installs
    # `docs/requirements.txt` in the step immediately before it and asks for
    # `required` (ci.yml), so a dropped install step reddens the gate rather
    # than quietly buying itself a skip.
    #
    # The theme check goes with the build rather than after it, because it reads
    # the built site: with no `site/` it fails for want of a build that did not
    # run, and with a stale one it answers about an older tree. Its other half —
    # whether this repository still carries the theme it was given — is asked
    # across every repository at once by `tools/docs-theme.mjs --check` in the
    # GaugeWright repository.
    echo "== documentation =="
    gate_section documentation
}

run_rust() {
    # Reads the sibling whipplescript checkout, so it is not a target: an input
    # outside this cell until stage 4 makes it an edge.
    echo "== resolved WhippleScript action contract =="
    python3 scripts/check-whipplescript-host-action.py --resolved
    python3 scripts/test-whipplescript-host-action.py

    echo "== lockfile =="
    gate_section lockfile

    echo "== formatting =="
    gate_section formatting

    echo "== lints =="
    gate_section lints

    # cargo-nextest, the tmpfs the fixtures write to, and the doctest run
    # nextest does not do are stated once, in scripts/section.sh — including the
    # tmpfs, which a section running as a Buck2 action has to set up itself
    # because it inherits nothing from this shell.
    echo "== tests =="
    gate_section tests

    echo "== no-default-features =="
    gate_section no-default-features
}


run_web() {
    gate_section web
}

# The dependency audit lives here rather than in a workflow step so that the
# documented local green bar and the enforced gate stay the same command. It is
# its own section because it is the one part of this script that needs the
# network and the advisory database rather than the toolchain, and because the
# security-baseline schedule runs exactly this and nothing else.
#
# The three Cargo lockfiles are audited by name; the four npm trees below are
# discovered with `find`. This comment used to claim the by-name policy for both
# halves, on the reasoning that a further lockfile should be a decision someone
# makes here rather than something that silently starts or stops being covered
# — while the npm half had discovered them all along, and discovery is what
# caught GHSA-6gmq-8vp8-gcm6 in `ee/sidecar/saml-verify`, a fourth tree the
# claimed policy had never named (#551).
#
# What actually makes a new lockfile a decision is neither idiom but
# `check-build-coverage.mjs` in the `contracts` section: it enumerates every
# lockfile git tracks, reads this file for which ones it covers and how, and
# fails on the difference. So both halves are backstopped, and the choice
# between naming and discovery is free to be what suits each.
# `.cargo/audit.toml` carries the triage record for anything formally
# risk-accepted.
advisories_unavailable=0


# $1 = "best-effort" (a developer asking for this section, and `all`) or
# "required" (the security-baseline CI job), which decides whether an absent
# cargo-audit or cargo-deny is reported or fails. Same reasoning as
# run_contracts: this section is the advisory sweep over every tracked lockfile,
# not the two cargo subcommands, and `all` must not end red about the host when
# it has answered everything it could about the change.
run_dependencies() {
    local prerequisites="${1:-best-effort}"

    echo "== production dependency advisories =="
    gate_section dependencies
}


# $1 = "required" (the `desktop` section and CI) or "best-effort" (inside `all`),
# which decides whether absent GTK/WebKit libraries fail or are reported.
run_desktop() {
    local prerequisites="${1:-required}"
    echo "== desktop shell =="
    gate_section desktop
}

# The release ships an MSI, and every gate above is Linux, so a change breaking
# the Windows build passes all of them and fails at release (DEVOPS.md OPS-26).
# The command lives in the script because the `windows-compiles` CI job runs
# that same script, so the two cannot drift. On a non-Windows host it says why
# it cannot answer instead of passing silently.
run_windows() {
    echo "== windows compile =="
    gate_section windows
}


run_mobile() {
    local prerequisites="${1:-required}"
    echo "== mobile shell =="
    gate_section mobile
}


# A step whose tool this host has not installed. Returns non-zero when the
# caller must skip, so a guarded step reads `if prerequisite …; then`; under
# `required` it never returns at all. It reads `$prerequisites` from the section
# it is called in.
#
# A skip is also recorded, because the bar's last line already says what it
# could not establish — an unreachable advisory service, an unrefreshed
# database — and a step that did not run belongs in that same sentence rather
# than only in a stderr notice a long run scrolls past.
#
#   $1 the tool, $2 what it gates, $3 the command that installs it
skipped_prerequisites=""

# How `all` runs one section, named rather than inlined because it is the seam
# `scripts/check-lanes.test.mjs` replaces. Sourcing this file defines the
# sections and stops before the dispatch, so the test can override this one
# function and drive the real `run_all` against sections whose outcomes it
# chooses — the shell counterpart of `check-build-coverage.mjs` exporting
# `analyze` and running `main` only when invoked directly, and of
# `run-production-wiring-canaries.mjs` taking a `spawnImpl`.
lane_runner() {
    "$BASH" "$self" "$@"
}

# End the sections `all` started alongside the cargo ones: each is its own
# process group, so the group is what to signal. Killing what has already
# finished is not an error here.
end_alongside() {
    local pid
    for pid in "$@"; do
        kill -TERM -- "-$pid" 2>/dev/null || true
    done
}

# `all` runs every section and reports the failures together, rather than
# stopping at the first one. Under `set -e` a sequence of calls meant that the
# earliest section to fail decided how much of the bar ran at all, and the
# sections are independent — nothing here produces an input for anything below
# it. So a developer whose `dependencies` section failed got a red bar and no
# answer about the change under test, because `rust` and `web` never started.
# That is the wrong trade for `dependencies` in particular, which is a statement
# about the world rather than about the diff: an advisory published overnight
# against a transitive dependency stops the whole bar from saying anything about
# the code. It runs last here for that reason, and it is not the only section
# whose failure has nothing to do with what the developer changed.
#
# The CI gates already behave this way — ci.yml and ci.public.yml run the
# sections as separate jobs, so a red `dependencies` there does not stop `rust`
# and `web` from reporting. This makes the local bar match the gate it mirrors.
#
# Each section runs as a child invocation rather than as a function call because
# `set -e` is suppressed inside any command whose status is tested, and the
# suppression reaches into a subshell and survives an explicit `set -e` within
# it. A section collected in-process with `|| rc=$?` would therefore keep
# running past its first failed command and report the status of its last one —
# which is worse than the masking this replaces, because it reports a pass. A
# separate process has its own errexit and none of that state.
#
# The sections that never touch the cargo target directory — `contracts`,
# `web`, `dependencies` — run alongside the ones that do. `rust` is most of the
# bar and saturates the cores only while it compiles; the other three are
# single-threaded scripts, node builds and network calls that on their own
# leave the machine idle, and nothing they read or write meets what the cargo
# sections read or write (`web`'s one cargo call builds a wasm target into its
# own profile directory). So they start first, in the background, and the cargo
# sections run in the foreground with their output live, which is where a
# developer watching a long run wants to look; each background transcript is
# replayed whole, under a banner, in a fixed order once the cargo sections are
# done, so a failure lands under its own section rather than interleaved with
# rustc. Measured on the founder's machine, warm tree, under a load average of
# 15 from other sessions: 110 s sequential, 88 s overlapped — the same sections
# and the same verdict, a fifth of the wall clock less.
#
# Each background section is its own process group, for the reason
# `parallel_steps` gives: without job control an asynchronous list inherits an
# ignored SIGINT, and an interrupted bar would leave three sections running to
# completion. The trap ends every group.
run_all() {
    # One word for every lane of this run, exported for the same reason the
    # nonce is: `all` starts three lanes at once, each a fresh invocation of
    # this script, and the word is part of every Buck2 action's key. Two
    # different words are two different CONFIGURATIONS arriving at one daemon
    # together, and the daemon answers by cancelling a transaction — a lane
    # failing for a reason that has nothing to do with the tree.
    #
    # best-effort is what `all` means: it is a developer's bar, and the lanes
    # that take no word have no prerequisite-guarded step for it to change.
    # `required` is the same bar as the gate: one invocation, every
    # prerequisite enforced, which is what the shared guide's
    # `scripts/check.sh required` promises and what the bridge off the forge
    # invokes (GaugeWright DR-0131). The hosted jobs asked for lanes one at a
    # time, each with its own word.
    export prerequisites="${1:-best-effort}"
    local word=()
    [ "$prerequisites" = required ] && word=(required)

    local failed=()
    local lane rc index
    local transcripts
    transcripts="$(mktemp -d)"
    local alongside=(contracts web dependencies)
    local pids=()

    # Ctrl-C used to stop the bar as a side effect of errexit seeing the
    # interrupted section's nonzero status. Collecting that status instead would
    # send the run on to the next section and make a developer interrupt a long
    # run once per section, so say what to do with a signal rather than leaving
    # it to what bash does with one it received while waiting on a child. The
    # sections running alongside are in their own process groups, which the
    # terminal's interrupt does not reach, so the trap ends them itself.
    trap 'echo >&2; echo "== gaugedesk green bar INTERRUPTED (all) ==" >&2; end_alongside "${pids[@]}"; rm -rf "$transcripts"; exit 130' INT TERM

    set -m
    for lane in "${alongside[@]}"; do
        # Under `all`, `contracts` needs no word here: a section name alone
        # already means best-effort for it, and `all` wants exactly what a
        # developer asking for that section wants. Under `required` the word
        # travels, so the lane enforces. See prerequisite_policy.
        lane_runner "$lane" ${word[@]+"${word[@]}"} > "$transcripts/$lane" 2>&1 &
        pids+=("$!")
    done
    set +m

    for lane in rust desktop mobile windows; do
        rc=0
        case "$lane" in
            desktop|mobile) lane_runner "$lane" "$prerequisites" || rc=$? ;;
            *) lane_runner "$lane" || rc=$? ;;
        esac

        # The other half of the same case: the signal reached only the child,
        # so this shell has no trap to run and would otherwise record an
        # interrupted section as a failed one and carry on.
        if [ "$rc" -ge 128 ]; then
            echo >&2
            echo "== gaugedesk green bar INTERRUPTED (all) during: $lane ==" >&2
            end_alongside "${pids[@]}"
            rm -rf "$transcripts"
            exit "$rc"
        fi

        [ "$rc" -eq 0 ] || failed+=("$lane")
    done

    index=0
    for lane in "${alongside[@]}"; do
        rc=0
        wait "${pids[$index]}" || rc=$?
        index=$((index + 1))
        echo
        echo "== $lane ran alongside the cargo sections; its transcript follows =="
        cat "$transcripts/$lane"

        if [ "$rc" -ge 128 ]; then
            echo >&2
            echo "== gaugedesk green bar INTERRUPTED (all) during: $lane ==" >&2
            end_alongside "${pids[@]}"
            rm -rf "$transcripts"
            exit "$rc"
        fi

        [ "$rc" -eq 0 ] || failed+=("$lane")
    done
    rm -rf "$transcripts"
    trap - INT TERM

    [ ${#failed[@]} -eq 0 ] && return 0

    echo
    echo "== gaugedesk green bar FAILED (all) ==" >&2
    echo "these sections failed; every other section still ran, so the output above is" >&2
    echo "complete for each one:" >&2
    for lane in "${failed[@]}"; do
        echo "  - $lane    (re-run alone: scripts/check.sh $lane)" >&2
    done
    exit 1
}

# Which section a request names, and what runs it. A function rather than a bare
# `case` for the same reason `lane_runner` is a function: it is reachable from a
# source, so `scripts/check-lanes.test.mjs` can assert that `all` reaches
# `run_all` — and would notice `all` being reverted to the sequence of calls
# that #553 replaced, which every other test here would sit through happily.
dispatch() {
    case "${1:-all}" in
        all) run_all ;;
        required) run_all required ;;
        contracts) run_contracts "$(prerequisite_policy "${2:-best-effort}")" ;;
        dependencies) run_dependencies "$(prerequisite_policy "${2:-best-effort}")" ;;
        desktop) run_desktop "$(prerequisite_policy "${2:-}")" ;;
        mobile) run_mobile "$(prerequisite_policy "${2:-}")" ;;
        rust) run_rust ;;
        web) run_web ;;
        windows) run_windows ;;
        *) echo "usage: scripts/check.sh [all|required|contracts|dependencies|desktop|mobile|rust|web|windows]" >&2; exit 2 ;;
    esac
}

# Sourced rather than executed: define the sections and stop. What a caller
# wants from a source is `dispatch`, `run_all` and the seam above it; running a
# section is not. `scripts/check-lanes.test.mjs` is the caller, and this line is
# what lets it test the real composition rather than a copy of it.
if [ "${BASH_SOURCE[0]}" != "$0" ]; then
    return 0
fi

# Before any section: a development fabric serving THIS checkout is watching
# and running binaries from the tree the lanes below are about to rebuild.
# Neither can see the other, so nothing else was ever going to report it.
node scripts/check-live-fabric.mjs

dispatch "$section" "${2:-}"

# The bar says what it actually established. A run that could not reach an
# advisory service passed everything it could assert and must not read as though
# it had asserted that too.
# An advisory service that could not be reached, a database that was not
# refreshed, a step that did not run for want of a tool: all the same kind of
# fact, and all reported by the section that met them, as `#unasserted:` lines
# the dispatcher collected.
unasserted="$section_unasserted"

if [ -n "$unasserted" ]; then
    echo "== gaugedesk green bar PASSED ($section — $unasserted) =="
else
    echo "== gaugedesk green bar PASSED ($section) =="
fi
