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
BDD_FEATURE_ROOTS = (
    ROOT / "web/e2e/features",
    ROOT / "ee/web/e2e/features",
)
BDD_SUPPORT_ROOTS = (
    ROOT / "web/e2e",
    ROOT / "ee/web/e2e",
)
BDD_STEPS_ROOT = ROOT / "web/e2e/steps"
BDD_FIDELITY_GUARD = BDD_STEPS_ROOT / "fidelity-guard.ts"
BDD_AUTHENTICATED_PROOF = ROOT / "web/e2e/authenticated-transport-proof.ts"
BDD_FIDELITY_TAGS = {
    "@ui-mocked",
    "@contract",
    "@transport",
    "@staging",
    "@production",
}
BDD_REAL_TRANSPORT_TAGS = {"@transport", "@staging", "@production"}
BDD_REPORT_TAGS = BDD_FIDELITY_TAGS | {"@authenticated", "@live-provider"}
BDD_SCENARIO = re.compile(r"^\s*Scenario(?: Outline)?:")
BDD_TAG = re.compile(r"@[\w-]+")
BDD_PROHIBITED_STEP_MECHANISMS = (
    (
        "Playwright route interception",
        re.compile(r"\b(?:page|context|browserContext)\.(?:route|routeFromHAR|routeWebSocket)\s*\("),
    ),
    (
        "global fetch replacement",
        re.compile(r"\b(?:globalThis|window)\.fetch\s*=|Object\.defineProperty\(\s*(?:globalThis|window)\s*,\s*['\"]fetch['\"]"),
    ),
    (
        "test framework fetch replacement",
        re.compile(r"\b(?:vi|jest)\.(?:stubGlobal|spyOn)\([^\n]*['\"]fetch['\"]"),
    ),
    (
        "fake route client",
        re.compile(r"\b(?:Fake|Mock)(?:Route|Transport|ControlPlane)Client\b"),
    ),
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


def check_bdd_fidelity(errors: list[str]) -> tuple[int, dict[str, int]]:
    """Require explicit scenario fidelity and isolate presentation-only seams."""
    scenario_count = 0
    fidelity_counts = {tag: 0 for tag in sorted(BDD_REPORT_TAGS)}

    for feature_root in BDD_FEATURE_ROOTS:
        for feature in sorted(feature_root.rglob("*.feature")):
            feature_tags: set[str] = set()
            pending_tags: set[str] = set()
            for line_number, line in enumerate(
                feature.read_text(encoding="utf-8").splitlines(), 1
            ):
                stripped = line.strip()
                if stripped.startswith("@"):
                    pending_tags.update(BDD_TAG.findall(stripped))
                    continue
                if stripped.startswith("Feature:"):
                    feature_tags = set(pending_tags)
                    pending_tags.clear()
                    continue
                if not BDD_SCENARIO.match(line):
                    continue

                scenario_count += 1
                tags = feature_tags | pending_tags
                pending_tags.clear()
                location = f"{feature.relative_to(ROOT)}:{line_number}"
                declared = tags & BDD_FIDELITY_TAGS
                for tag in tags & BDD_REPORT_TAGS:
                    fidelity_counts[tag] += 1

                if not declared:
                    errors.append(
                        f"BDD fidelity missing: {location} must declare one of "
                        f"{', '.join(sorted(BDD_FIDELITY_TAGS))}"
                    )
                if "@live" in tags:
                    errors.append(
                        f"BDD legacy fidelity tag: {location} must use @live-provider"
                    )
                if "@ui-mocked" in tags and tags & (
                    BDD_REAL_TRANSPORT_TAGS | {"@authenticated", "@live-provider"}
                ):
                    errors.append(
                        f"BDD contradictory fidelity: {location} mixes @ui-mocked "
                        "with real transport, authentication, or provider tags"
                    )
                if "@authenticated" in tags and not tags & BDD_REAL_TRANSPORT_TAGS:
                    errors.append(
                        f"BDD authenticated fidelity: {location} needs @transport, "
                        "@staging, or @production"
                    )
                if "@live-provider" in tags and not tags & BDD_REAL_TRANSPORT_TAGS:
                    errors.append(
                        f"BDD provider fidelity: {location} needs @transport, "
                        "@staging, or @production"
                    )
                if {"@staging", "@production"} <= tags:
                    errors.append(
                        f"BDD contradictory environment: {location} cannot be both "
                        "@staging and @production"
                    )

    if not BDD_FIDELITY_GUARD.is_file():
        errors.append(
            "missing BDD runtime fidelity guard: web/e2e/steps/fidelity-guard.ts"
        )
    if not BDD_AUTHENTICATED_PROOF.is_file():
        errors.append(
            "missing authenticated request proof: "
            "web/e2e/authenticated-transport-proof.ts"
        )

    for support_root in BDD_SUPPORT_ROOTS:
        for source in sorted(support_root.rglob("*.ts")):
            if source.name.endswith(".mocked-steps.ts"):
                continue
            text = source.read_text(encoding="utf-8")
            for label, pattern in BDD_PROHIBITED_STEP_MECHANISMS:
                match = pattern.search(text)
                if not match:
                    continue
                line_number = text.count("\n", 0, match.start()) + 1
                errors.append(
                    f"BDD {label}: {source.relative_to(ROOT)}:{line_number} must move "
                    "to a *.mocked-steps.ts module under an @ui-mocked scenario"
                )

    return scenario_count, fidelity_counts


def main() -> int:
    errors: list[str] = []
    check_crate_edges(errors)
    check_core_purity(errors)
    check_browser_transport_owners(errors)
    check_retired_and_canonical_paths(errors)
    scenario_count, fidelity_counts = check_bdd_fidelity(errors)
    if errors:
        for error in errors:
            print(f"FAIL  {error}", file=sys.stderr)
        return 1
    fidelity_summary = ", ".join(
        f"{tag}={count}" for tag, count in fidelity_counts.items() if count
    )
    print(
        "architecture check passed: crate directions, core purity, browser transport "
        f"ownership, canonical paths, {scenario_count} BDD scenarios ({fidelity_summary})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
