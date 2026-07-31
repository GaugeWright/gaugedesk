#!/usr/bin/env bash
# Generate the versioned, reproducible Debian changelog payload consumed by Tauri.
set -euo pipefail

ROOT="$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)"
version="$(node -p "require('$ROOT/src-tauri/tauri.conf.json').version")"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+~-][A-Za-z0-9.+:~-]+)?$ ]] || {
  echo "invalid GaugeDesk bundle version: $version" >&2
  exit 1
}

sed -E "1s/^gauge-desk \([^)]+\)/gauge-desk ($version)/" \
  "$ROOT/src-tauri/linux/changelog" \
  | gzip -9 -n >"$ROOT/src-tauri/linux/changelog.gz"

echo "prepared Debian changelog for $version"
