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
  lintian --fail-on error "$DEB"
fi

printf 'validated %s %s (%s)\n' "$(field Package)" "$(field Version)" "$(field Architecture)"
