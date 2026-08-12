#!/usr/bin/env python3
"""Fail closed when the GaugeDesk public/commercial license boundary drifts."""

from __future__ import annotations

import hashlib
import json
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
AGPL = "AGPL-3.0-only"
APACHE = "Apache-2.0"
AGPL_TEXT_SHA256 = "0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0"
APACHE_PACKAGES = {
    Path("web/packages/control-plane-client/package.json"),
    Path("web/packages/gw-embed/package.json"),
}
APACHE_LICENSES = {
    Path("web/packages/control-plane-client/LICENSE"),
    Path("web/packages/gw-embed/LICENSE"),
}
# Directories that are never part of this checkout's licensed surface. `.claude`
# holds agent worktrees — whole nested copies of this repository — and the root
# AGENTS.md forbids committing it. A nested copy is the sharp case: the Apache
# SDK exceptions above are keyed by exact relative path, so the same two
# packages read as unlicensed AGPL violations at any other prefix, and the check
# fails on files that are not in the repository at all.
EXCLUDED_DIRS = {".claude", ".git", "dist", "node_modules", "target"}
PUBLIC_DRIFT_TERMS = ("BUSL-1.1", "Business Source License", "Enterprise Use Grant")
PUBLIC_DRIFT_ROOTS = (
    Path("README.public.md"),
    Path("NOTICE"),
    Path("docs"),
    Path("crates"),
    Path("ee"),
    Path("src-tauri"),
    Path("src-tauri-mobile"),
    Path("web"),
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def excluded(path: Path) -> bool:
    """True when a path lies inside a directory that is not licensed surface.

    Only the part of the path below ROOT is inspected. The checkout itself may
    sit inside an excluded directory — an agent worktree under `.claude` is
    exactly that — and those enclosing components say nothing about whether the
    file is part of this checkout's licensed surface.
    """
    try:
        relative = path.relative_to(ROOT)
    except ValueError:
        return False
    return any(
        part in EXCLUDED_DIRS or part.startswith("dist-") for part in relative.parts
    )


def text_files(path: Path):
    if path.is_file():
        yield path
        return
    for candidate in sorted(path.rglob("*")):
        if not candidate.is_file() or excluded(candidate):
            continue
        try:
            candidate.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        yield candidate


def check(errors: list[str]) -> None:
    license_path = ROOT / "LICENSE"
    if not license_path.is_file() or digest(license_path) != AGPL_TEXT_SHA256:
        errors.append("root LICENSE is not the pinned verbatim GNU AGPLv3 text")

    permissions = ROOT / "LICENSE-ADDITIONAL-PERMISSIONS"
    permission_text = permissions.read_text(encoding="utf-8") if permissions.is_file() else ""
    for required in (
        "additional permissions under section 7",
        "Public Extension Interface",
        "unmodified GaugeDesk Embed Client",
        "may remove these additional permissions",
    ):
        if required not in permission_text:
            errors.append(f"additional-permissions text is missing: {required}")

    if (ROOT / "ee/LICENSE").exists():
        errors.append("retired ee/LICENSE must not exist")

    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    if workspace.get("workspace", {}).get("package", {}).get("license") != AGPL:
        errors.append(f"Cargo workspace license must be {AGPL}")
    for manifest in sorted(ROOT.rglob("Cargo.toml")):
        if excluded(manifest):
            continue
        data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        package = data.get("package")
        if not package:
            continue
        declared = package.get("license")
        if declared == AGPL or declared == {"workspace": True}:
            continue
        errors.append(f"{manifest.relative_to(ROOT)} must declare or inherit {AGPL}")

    for manifest in sorted(ROOT.rglob("package.json")):
        if excluded(manifest):
            continue
        relative = manifest.relative_to(ROOT)
        data = json.loads(manifest.read_text(encoding="utf-8"))
        expected = APACHE if relative in APACHE_PACKAGES else AGPL
        if data.get("license") != expected:
            errors.append(f"{relative} license must be {expected}")
        target = data.get("gaugewright", {}).get("licenseTarget")
        if target is not None and target != expected:
            errors.append(f"{relative} gaugewright.licenseTarget must be {expected}")

    apache_digests = {
        digest(ROOT / path) for path in APACHE_LICENSES if (ROOT / path).is_file()
    }
    if len(apache_digests) != 1 or not apache_digests:
        errors.append("both Apache SDK packages must carry the same license text")
    for path in APACHE_LICENSES:
        if not (ROOT / path).is_file():
            errors.append(f"missing Apache SDK license: {path}")

    seen: set[Path] = set()
    apache_paths = {ROOT / item for item in APACHE_LICENSES}
    for root in PUBLIC_DRIFT_ROOTS:
        for path in text_files(ROOT / root):
            if path in seen or path in apache_paths:
                continue
            seen.add(path)
            content = path.read_text(encoding="utf-8")
            for term in PUBLIC_DRIFT_TERMS:
                if term in content:
                    errors.append(
                        f"retired public license term {term!r} in {path.relative_to(ROOT)}"
                    )

    projection_path = ROOT / "scripts/publish-public-mirror.sh"
    if projection_path.is_file():
        projection = projection_path.read_text(encoding="utf-8")
        if "LICENSE-ADDITIONAL-PERMISSIONS" not in projection:
            errors.append("public projection omits LICENSE-ADDITIONAL-PERMISSIONS")


def main() -> int:
    errors: list[str] = []
    check(errors)
    for error in errors:
        print(f"FAIL  {error}", file=sys.stderr)
    if errors:
        return 1
    print("license boundary: AGPL platform, section-7 permissions, Apache SDK exceptions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
