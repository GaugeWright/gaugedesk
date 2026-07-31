#!/usr/bin/env bash
# Sign an APT Release file with a key already available in GNUPGHOME.
set -euo pipefail

REPO_ROOT="${1:?usage: sign-apt-repository.sh <repo-root> [key-fingerprint]}"
KEY="${2:-}"
RELEASE="$REPO_ROOT/dists/stable/Release"
[ -f "$RELEASE" ] || { echo "Release file not found: $RELEASE" >&2; exit 1; }
command -v gpg >/dev/null 2>&1 || { echo "gpg is required" >&2; exit 1; }

gpg_args=(--batch --yes --pinentry-mode loopback --digest-algo SHA256)
[ -z "$KEY" ] || gpg_args+=(--local-user "$KEY")
rm -f "$REPO_ROOT/dists/stable/InRelease" "$REPO_ROOT/dists/stable/Release.gpg"

gpg "${gpg_args[@]}" --passphrase-fd 3 --detach-sign \
  --output "$REPO_ROOT/dists/stable/Release.gpg" "$RELEASE" \
  3<<<"${APT_SIGNING_PASSPHRASE:-}"
gpg "${gpg_args[@]}" --passphrase-fd 3 --clearsign \
  --output "$REPO_ROOT/dists/stable/InRelease" "$RELEASE" \
  3<<<"${APT_SIGNING_PASSPHRASE:-}"

gpg --batch --export-options export-minimal --export ${KEY:+"$KEY"} \
  >"$REPO_ROOT/gaugewright-archive-keyring.gpg"
[ -s "$REPO_ROOT/gaugewright-archive-keyring.gpg" ] || {
  echo "failed to export archive public key" >&2
  exit 1
}

printf 'signed APT repository%s\n' "${KEY:+ with $KEY}"
