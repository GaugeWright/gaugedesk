#!/usr/bin/env python3
"""Enforce the small set of repository boundaries that must not drift by accident.

This is deliberately a narrow structural check, not a second architecture
description. The canonical meaning lives in specs/architecture.md and the
linked primitive/lifecycle contracts. A new top-level crate, a changed allowed
dependency edge, or a new browser transport owner is an architecture change and
must update this check alongside that canonical documentation.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent

# Crate names are intentionally explicit. An omitted crate or edge is a prompt
# to decide its architectural role rather than silently accepting a new layer.
CRATES = {
    "gaugewright-core": ROOT / "crates/core/Cargo.toml",
    "gaugewright-store": ROOT / "crates/store/Cargo.toml",
    "gaugewright-workspace": ROOT / "crates/workspace/Cargo.toml",
    "gaugewright-boundary": ROOT / "crates/boundary/Cargo.toml",
    "gaugewright-harness": ROOT / "crates/harness/Cargo.toml",
    "gaugewright-pi-bridge": ROOT / "crates/pi-bridge/Cargo.toml",
    "gaugewright-tracker": ROOT / "crates/tracker/Cargo.toml",
    "gaugewright-whip-runtime": ROOT / "crates/whip-runtime/Cargo.toml",
    "gaugewright-directory-protocol": ROOT / "crates/directory-protocol/Cargo.toml",
    "gaugewright-relay-transport": ROOT / "crates/relay-transport/Cargo.toml",
    "gaugewright-app": ROOT / "crates/app/Cargo.toml",
    "gaugewright-ee": ROOT / "ee/app/Cargo.toml",
    "gaugedesk-desktop": ROOT / "src-tauri/Cargo.toml",
    "gaugedesk-mobile": ROOT / "src-tauri-mobile/Cargo.toml",
}

ALLOWED_LOCAL_EDGES = {
    "gaugewright-core": set(),
    "gaugewright-store": {"gaugewright-core"},
    "gaugewright-workspace": set(),
    "gaugewright-boundary": {"gaugewright-core"},
    "gaugewright-harness": set(),
    "gaugewright-pi-bridge": {"gaugewright-core", "gaugewright-harness"},
    "gaugewright-tracker": set(),
    "gaugewright-whip-runtime": {"gaugewright-core", "gaugewright-harness"},
    "gaugewright-directory-protocol": {"gaugewright-core"},
    "gaugewright-relay-transport": set(),
    "gaugewright-app": {
        "gaugewright-core",
        "gaugewright-store",
        "gaugewright-workspace",
        "gaugewright-boundary",
        "gaugewright-harness",
        "gaugewright-tracker",
        "gaugewright-whip-runtime",
        "gaugewright-directory-protocol",
        "gaugewright-relay-transport",
        # Test/conformance-only dependency; it is not in the runtime dependency set.
        "gaugewright-pi-bridge",
    },
    "gaugewright-ee": {
        "gaugewright-core",
        "gaugewright-store",
        "gaugewright-app",
        "gaugewright-workspace",  # test-only enterprise fixture support
    },
    "gaugedesk-desktop": {"gaugewright-app"},
    "gaugedesk-mobile": {
        "tauri-plugin-gaugedesk-device-identity",
        "gaugewright-relay-transport",
    },
}

CORE_FORBIDDEN_IMPORT = re.compile(
    r"\b(?:"
    r"std::(?:fs|net|process|io)|"
    r"(?:tokio|axum|rusqlite|ureq|reqwest|hyper|tower|tracing)::|"
    r"std::thread"
    r")"
)
BROWSER_TRANSPORT = re.compile(r"(?<![-\w])(?:fetch|WebSocket|XMLHttpRequest)\s*\(")
TRANSPORT_OWNERS = (
    ROOT / "web/packages/control-plane-client/src",
    ROOT / "web/packages/gw-embed/src",
)


def local_dependencies(manifest: Path) -> set[str]:
    data = tomllib.loads(manifest.read_text(encoding="utf-8"))
    found: set[str] = set()
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        for name, declaration in data.get(section, {}).items():
            if not isinstance(declaration, dict) or "path" not in declaration:
                continue
            dependency_path = (manifest.parent / declaration["path"]).resolve()
            if is_under(dependency_path, ROOT):
                found.add(name)
    return found


def is_under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def check_crate_edges(errors: list[str]) -> None:
    for crate, manifest in CRATES.items():
        if not manifest.is_file():
            errors.append(f"missing manifest for architecture crate {crate}: {manifest.relative_to(ROOT)}")
            continue
        actual = local_dependencies(manifest)
        unexpected = actual - ALLOWED_LOCAL_EDGES[crate]
        if unexpected:
            errors.append(
                f"{crate} has forbidden local dependencies: {', '.join(sorted(unexpected))}"
            )


def check_core_purity(errors: list[str]) -> None:
    for source in sorted((ROOT / "crates/core/src").rglob("*.rs")):
        for line_number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
            if CORE_FORBIDDEN_IMPORT.search(line):
                errors.append(
                    f"core purity violation: {source.relative_to(ROOT)}:{line_number}: {line.strip()}"
                )


def check_browser_transport_owners(errors: list[str]) -> None:
    roots = (ROOT / "web/apps", ROOT / "web/packages", ROOT / "web/src")
    for root in roots:
        for source in sorted(root.rglob("*.ts*")):
            if any(part in {"node_modules", "dist"} or part.startswith("dist-") for part in source.parts):
                continue
            if any(is_under(source, owner) for owner in TRANSPORT_OWNERS):
                continue
            for line_number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
                if BROWSER_TRANSPORT.search(line):
                    errors.append(
                        "browser transport bypass: "
                        f"{source.relative_to(ROOT)}:{line_number} must use control-plane-client "
                        "or the gw-embed session transport"
                    )


def check_retired_and_canonical_paths(errors: list[str]) -> None:
    required = ROOT / "web/index.html"
    duplicate = ROOT / "web/apps/workbench-web/index.html"
    retired_reducer = ROOT / "crates/core/src/public_session.rs"
    if not required.is_file():
        errors.append("missing canonical workbench entrypoint: web/index.html")
    if duplicate.exists():
        errors.append(
            "duplicate workbench entrypoint: remove web/apps/workbench-web/index.html "
            "and point staged builds at web/index.html"
        )
    if retired_reducer.exists():
        errors.append(
            "retired fused public-session reducer is present: "
            "runtime lifecycle belongs at the GaugeDesk/WhippleScript seam"
        )


def main() -> int:
    errors: list[str] = []
    check_crate_edges(errors)
    check_core_purity(errors)
    check_browser_transport_owners(errors)
    check_retired_and_canonical_paths(errors)
    if errors:
        for error in errors:
            print(f"FAIL  {error}", file=sys.stderr)
        return 1
    print("architecture check passed: crate directions, core purity, browser transport ownership, canonical paths")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
