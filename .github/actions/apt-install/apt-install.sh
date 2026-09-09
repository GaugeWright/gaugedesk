#!/usr/bin/env bash
# Install apt packages under a per-attempt time bound.
#
# Why this exists rather than two plain `apt-get` lines:
#
# On 2026-08-18 `apt-get update` on a GitHub-hosted runner went **silent for
# 1765 seconds** — no output, no error, no progress — immediately after
# fetching the `InRelease` files, and did it on three separate runs. The
# `native shells` job died at its 30-minute wall each time and reported as a
# failing required check on healthy changes. That step normally takes 22-106s.
#
# apt's own `Acquire::Retries` and `Acquire::*::Timeout` did not bound it, so
# the bound has to come from outside the process. `timeout` runs under `sudo`
# rather than the other way around: `timeout sudo …` signals `sudo`, which need
# not forward anything to `apt-get`, whereas `sudo timeout …` runs as root and
# can kill `apt-get` directly.
#
# The stall correlated with `azure.archive.ubuntu.com` being ignored and the
# mirrorlist falling back to `archive.ubuntu.com`, but the silence outlasted
# every timeout apt was willing to apply, so this treats the cause as unknown
# and only bounds the symptom.
#
# It lives beside the action rather than inside its YAML so that
# `scripts/apt-install-action.test.sh` can run it against stub commands.
set -uo pipefail

: "${APT_PACKAGES:?APT_PACKAGES is required}"
: "${APT_ATTEMPT_TIMEOUT:=480}"
: "${APT_ATTEMPTS:=3}"

# Fail an individual mirror fast so a retry can pick a different one, instead of
# one attempt absorbing the whole budget on a dead host.
options="-o Acquire::Retries=2 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30"

attempt=1
while [ "$attempt" -le "$APT_ATTEMPTS" ]; do
    # shellcheck disable=SC2086 # options is a deliberate word list.
    sudo timeout "$APT_ATTEMPT_TIMEOUT" apt-get $options update
    update_status=$?

    # A runner image carries vendor sources this repository never installs from
    # — Google Chrome's among them — and `apt-get update` fails as a whole when
    # any single index fails. On 2026-09-09 Google served a `Packages.gz` that
    # did not match the `Release` it had just regenerated, so every index but
    # theirs refreshed cleanly and three required jobs went red for half an hour
    # on a tree that was fine. Retrying could not help: the bad index was served
    # identically each time.
    #
    # So a failing index is not the verdict. Whether the requested packages
    # install is, and they come from the distribution's own indices, which
    # refreshed. A genuinely broken index for a package we need still fails,
    # because the install then fails.
    #
    # Exit 124 is different in kind: `timeout` killed apt at the bound, which is
    # the silent-stall case above, and it leaves the lists and locks in a state
    # only the cleanup below can clear. Installing on top of that would fail for
    # a reason that has nothing to do with the packages.
    if [ "$update_status" -ne 0 ] && [ "$update_status" -ne 124 ]; then
        echo "::warning::apt-get update reported a failing index (status ${update_status}); the install decides" >&2
    fi

    if [ "$update_status" -ne 124 ]; then
        # shellcheck disable=SC2086 # options and packages are deliberate word lists.
        if sudo timeout "$APT_ATTEMPT_TIMEOUT" apt-get $options install -y $APT_PACKAGES; then
            echo "apt install succeeded on attempt ${attempt}"
            exit 0
        fi
    fi

    if [ "$update_status" -eq 124 ]; then
        echo "::warning::apt attempt ${attempt} did not finish inside ${APT_ATTEMPT_TIMEOUT}s" >&2
    else
        echo "::warning::apt attempt ${attempt} could not install ${APT_PACKAGES}" >&2
    fi

    # A killed apt leaves its lock held and can leave dpkg half-configured; both
    # make the next attempt fail for a reason that has nothing to do with the
    # mirror.
    sudo pkill -9 -x apt-get || true
    sudo pkill -9 -x dpkg || true
    sudo rm -f /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/lib/dpkg/lock-frontend || true
    sudo dpkg --configure -a || true
    attempt=$((attempt + 1))
    sleep 5
done

echo "apt never completed in ${APT_ATTEMPTS} bounded attempts" >&2
exit 1
