#!/usr/bin/env bash
# Validate the GaugeDesk Debian artifact before it can enter the APT archive.
set -euo pipefail

DEB="${1:?usage: check-deb-package.sh <gauge-desk.deb>}"
[ -f "$DEB" ] || { echo "package not found: $DEB" >&2; exit 1; }

field() { dpkg-deb --field "$DEB" "$1"; }
require_token() {
  local control_field="$1" expected="$2" value
  value="$(field "$control_field")"
  tr ',' '\n' <<<"$value" | sed -E 's/^ +| +$//g; s/ +\([^)]*\)$//' \
    | grep -Fxq "$expected" || {
      echo "$control_field must include $expected (found: $value)" >&2
      exit 1
    }
}

[ "$(field Package)" = "gauge-desk" ] || {
  echo "Package must be gauge-desk (found: $(field Package))" >&2
  exit 1
}
[[ "$(field Version)" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+~-][A-Za-z0-9.+:~-]+)?$ ]] || {
  echo "Version is not a supported release version: $(field Version)" >&2
  exit 1
}
[[ "$(field Architecture)" =~ ^(amd64|arm64)$ ]] || {
  echo "unsupported Architecture: $(field Architecture)" >&2
  exit 1
}
[[ "$(field Maintainer)" =~ ^[^\<]+\ \<[^\>]+@[^\>]+\>$ ]] || {
  echo "Maintainer must contain a name and email (found: $(field Maintainer))" >&2
  exit 1
}
[ -n "$(field Description)" ] || { echo "Description is required" >&2; exit 1; }
require_token Depends libc6

for legacy in gauge-bench gaugebench; do
  require_token Provides "$legacy"
  require_token Conflicts "$legacy"
  require_token Replaces "$legacy"
done

contents="$(dpkg-deb --contents "$DEB")"
grep -Eq 'usr/bin/gaugedesk$' <<<"$contents" || {
  echo "package must install the gaugedesk command at /usr/bin/gaugedesk" >&2
  exit 1
}
grep -Eq 'usr/share/applications/[^/]+\.desktop$' <<<"$contents" || {
  echo "package contains no desktop entry" >&2
  exit 1
}
for document in changelog.gz copyright; do
  grep -Eq "usr/share/doc/gauge-desk/$document$" <<<"$contents" || {
      echo "package contains no /usr/share/doc/gauge-desk/$document" >&2
      exit 1
    }
done

if command -v lintian >/dev/null 2>&1; then
  # lintian finds embedded libraries by scanning for byte signatures, and the
  # binary carries `unsafe-libyaml` — a Rust transliteration of libyaml, reached
  # through `serde_yaml_ng`. It matches the signature and is not the C library:
  # there is no shared object to link against instead, and no C-side CVE that
  # could apply to code that is not C. Reported as an error, it failed the
  # v0.4.9 release lane's Linux job after the .deb had already built.
  #
  # Allowlisted by exact tag, library, and path rather than by suppressing the
  # tag, so a genuinely embedded copy of anything — including a real libyaml at
  # another path — still fails. Every other lintian error still fails too, which
  # is why this parses the report instead of relaxing `--fail-on`.
  ALLOWED_LINTIAN_ERROR='^E: gauge-desk: embedded-library libyaml usr/bin/gaugedesk$'

  lintian_report="$(lintian "$DEB" 2>&1 || true)"
  printf '%s\n' "$lintian_report"

  unexpected="$(printf '%s\n' "$lintian_report" | grep '^E: ' | grep -vE "$ALLOWED_LINTIAN_ERROR" || true)"
  if [ -n "$unexpected" ]; then
    echo "lintian reported errors that are not allowlisted:" >&2
    printf '%s\n' "$unexpected" >&2
    exit 1
  fi
fi

printf 'validated %s %s (%s)\n' "$(field Package)" "$(field Version)" "$(field Architecture)"
