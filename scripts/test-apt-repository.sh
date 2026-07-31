#!/usr/bin/env bash
# Hermetic acceptance test for package validation, indexes, signatures, and APT.
set -euo pipefail

ROOT="$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
chmod 755 "$TMP"
sha256_file() { sha256sum "$1" | awk '{ print $1 }'; }

make_deb() {
  local version="$1"
  local package_root="$TMP/package-$version"
  mkdir -p "$package_root/DEBIAN" "$package_root/usr/bin" \
    "$package_root/usr/share/applications" \
    "$package_root/usr/share/doc/gauge-desk"
  apply_control="$package_root/DEBIAN/control"
  printf '%s\n' \
    'Package: gauge-desk' \
    "Version: $version" \
    'Architecture: amd64' \
    'Priority: optional' \
    'Maintainer: GaugeWright <support@gaugewright.com>' \
    'Depends: libc6' \
    'Provides: gauge-bench, gaugebench' \
    'Conflicts: gauge-bench, gaugebench' \
    'Replaces: gauge-bench, gaugebench' \
    'Description: GaugeDesk test package' >"$apply_control"
  printf '#!/bin/sh\nexit 0\n' >"$package_root/usr/bin/gauge-desk"
  chmod 755 "$package_root/usr/bin/gauge-desk"
  printf '%s\n' \
    '[Desktop Entry]' 'Name=GaugeDesk' 'Exec=gauge-desk' \
    'Type=Application' >"$package_root/usr/share/applications/gauge-desk.desktop"
  printf 'test changelog\n' \
    | gzip -9 -n >"$package_root/usr/share/doc/gauge-desk/changelog.gz"
  printf 'Copyright 2026 GaugeWright\nLicense: Apache-2.0\n' \
    >"$package_root/usr/share/doc/gauge-desk/copyright"
  dpkg-deb --build --root-owner-group "$package_root" \
    "$TMP/gauge-desk_${version}_amd64.deb" >/dev/null
}

make_deb 0.4.3
make_deb 0.4.4
"$ROOT/scripts/check-deb-package.sh" "$TMP/gauge-desk_0.4.4_amd64.deb"
SOURCE_DATE_EPOCH=1783987200 "$ROOT/scripts/build-apt-repository.sh" \
  "$TMP/repository" "$TMP/gauge-desk_0.4.3_amd64.deb" \
  "$TMP/gauge-desk_0.4.4_amd64.deb"

export GNUPGHOME="$TMP/gnupg"
mkdir -m 700 "$GNUPGHOME"
passphrase=test-only
gpg --batch --quiet --pinentry-mode loopback --passphrase "$passphrase" \
  --quick-gen-key 'GaugeWright APT Test <test@gaugewright.invalid>' ed25519 sign 1d
fingerprint="$(gpg --batch --with-colons --list-secret-keys \
  | awk -F: '$1 == "fpr" { print $10; exit }')"
APT_SIGNING_PASSPHRASE="$passphrase" \
  "$ROOT/scripts/sign-apt-repository.sh" "$TMP/repository" "$fingerprint"

gpgv --keyring "$TMP/repository/gaugewright-archive-keyring.gpg" \
  "$TMP/repository/dists/stable/InRelease" >/dev/null

release="$TMP/repository/dists/stable/Release"
while read -r digest size relative; do
  file="$TMP/repository/dists/stable/$relative"
  [ -f "$file" ] || { echo "Release references missing file: $relative" >&2; exit 1; }
  [ "$(sha256_file "$file")" = "$digest" ] || {
    echo "Release hash mismatch: $relative" >&2
    exit 1
  }
  [ "$(stat -c %s "$file")" = "$size" ] || {
    echo "Release size mismatch: $relative" >&2
    exit 1
  }
done < <(sed -n '/^SHA256:$/,$p' "$release" | tail -n +2)

packages="$TMP/repository/dists/stable/main/binary-amd64/Packages"
[ "$(grep -c '^Package: gauge-desk$' "$packages")" -eq 2 ]
grep -q '^Version: 0.4.4$' "$packages"
for index in Packages Packages.gz Packages.xz; do
  digest="$(sha256_file "$(dirname "$packages")/$index")"
  [ -f "$(dirname "$packages")/by-hash/SHA256/$digest" ]
done

apt_root="$TMP/apt"
mkdir -p "$apt_root/lists/partial" "$apt_root/cache/archives/partial" "$apt_root/etc"
printf 'deb [signed-by=%s] file:%s stable main\n' \
  "$TMP/repository/gaugewright-archive-keyring.gpg" "$TMP/repository" \
  >"$apt_root/etc/sources.list"
apt_options=(
  -o Debug::NoLocking=1
  -o Dir::Etc::sourcelist="$apt_root/etc/sources.list"
  -o Dir::Etc::sourceparts=-
  -o Dir::State::lists="$apt_root/lists"
  -o Dir::State::status=/dev/null
  -o Dir::Cache="$apt_root/cache"
  -o APT::Sandbox::User=
)
apt-get "${apt_options[@]}" update >/dev/null
policy="$(apt-cache "${apt_options[@]}" policy gauge-desk)"
grep -q 'Candidate: 0.4.4' <<<"$policy"

cp "$TMP/repository/dists/stable/InRelease" "$TMP/InRelease.valid"
printf '\ntampered\n' >>"$TMP/repository/dists/stable/InRelease"
rm -rf "$apt_root/lists" && mkdir -p "$apt_root/lists/partial"
if apt-get "${apt_options[@]}" update >/dev/null 2>&1; then
  echo "APT accepted tampered signed metadata" >&2
  exit 1
fi
mv "$TMP/InRelease.valid" "$TMP/repository/dists/stable/InRelease"

echo 'APT repository acceptance test passed'
