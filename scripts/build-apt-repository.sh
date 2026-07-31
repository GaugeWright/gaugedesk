#!/usr/bin/env bash
# Add GaugeDesk .deb files and regenerate an unsigned static APT repository.
set -euo pipefail

REPO_ROOT="${1:?usage: build-apt-repository.sh <repo-root> <deb> [deb ...]}"
shift
[ "$#" -gt 0 ] || { echo "at least one .deb is required" >&2; exit 1; }

for tool in dpkg-deb dpkg-scanpackages gzip xz sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || { echo "$tool is required" >&2; exit 1; }
done
sha256_file() { sha256sum "$1" | awk '{ print $1 }'; }

mkdir -p "$REPO_ROOT/pool/main/g/gauge-desk"
for source_deb in "$@"; do
  [ -f "$source_deb" ] || { echo "package not found: $source_deb" >&2; exit 1; }
  package="$(dpkg-deb --field "$source_deb" Package)"
  version="$(dpkg-deb --field "$source_deb" Version)"
  architecture="$(dpkg-deb --field "$source_deb" Architecture)"
  [ "$package" = "gauge-desk" ] || {
    echo "refusing non-canonical package $package from $source_deb" >&2
    exit 1
  }
  [[ "$architecture" =~ ^(amd64|arm64)$ ]] || {
    echo "refusing unsupported architecture $architecture" >&2
    exit 1
  }
  destination="$REPO_ROOT/pool/main/g/gauge-desk/${package}_${version}_${architecture}.deb"
  if [ -f "$destination" ]; then
    [ "$(sha256_file "$source_deb")" = "$(sha256_file "$destination")" ] || {
      echo "immutable package collision: $destination" >&2
      exit 1
    }
  else
    cp "$source_deb" "$destination"
  fi
done

mapfile -t all_debs < <(find "$REPO_ROOT/pool" -type f -name '*.deb' -print | sort)
[ "${#all_debs[@]}" -gt 0 ] || { echo "repository has no packages" >&2; exit 1; }

architectures=()
for deb in "${all_debs[@]}"; do
  [ "$(dpkg-deb --field "$deb" Package)" = "gauge-desk" ] || {
    echo "unexpected package in pool: $deb" >&2
    exit 1
  }
  architecture="$(dpkg-deb --field "$deb" Architecture)"
  [[ "$architecture" =~ ^(amd64|arm64)$ ]] || {
    echo "unexpected architecture in pool: $architecture" >&2
    exit 1
  }
  architectures+=("$architecture")
done
mapfile -t architectures < <(printf '%s\n' "${architectures[@]}" | sort -u)

stage="$(mktemp -d "$REPO_ROOT/.apt-dists.XXXXXX")"
trap 'rm -rf "$stage"' EXIT
stable="$stage/dists/stable"
mkdir -p "$stable/main"

for architecture in "${architectures[@]}"; do
  binary_dir="$stable/main/binary-$architecture"
  mkdir -p "$binary_dir"
  (
    cd "$REPO_ROOT"
    dpkg-scanpackages --multiversion --arch "$architecture" pool /dev/null
  ) >"$binary_dir/Packages"
  gzip -9 -n -c "$binary_dir/Packages" >"$binary_dir/Packages.gz"
  xz -9 -c "$binary_dir/Packages" >"$binary_dir/Packages.xz"

  mkdir -p "$binary_dir/by-hash/SHA256"
  for index in Packages Packages.gz Packages.xz; do
    digest="$(sha256_file "$binary_dir/$index")"
    cp "$binary_dir/$index" "$binary_dir/by-hash/SHA256/$digest"
  done
done

if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
  release_date="$(date --utc --date="@$SOURCE_DATE_EPOCH" --rfc-email)"
else
  release_date="$(date --utc --rfc-email)"
fi

{
  echo "Origin: GaugeWright"
  echo "Label: GaugeWright"
  echo "Suite: stable"
  echo "Codename: stable"
  echo "Date: $release_date"
  echo "Architectures: ${architectures[*]}"
  echo "Components: main"
  echo "Description: GaugeWright GaugeDesk packages"
  echo "Acquire-By-Hash: yes"
  echo "SHA256:"
  while IFS= read -r path; do
    relative="${path#"$stable/"}"
    printf ' %s %16d %s\n' "$(sha256_file "$path")" "$(stat -c %s "$path")" "$relative"
  done < <(find "$stable/main" -type f -print | sort)
} >"$stable/Release"

rm -rf "$REPO_ROOT/dists"
mv "$stage/dists" "$REPO_ROOT/dists"
printf 'built APT repository with %d package(s) for %s\n' \
  "${#all_debs[@]}" "${architectures[*]}"
