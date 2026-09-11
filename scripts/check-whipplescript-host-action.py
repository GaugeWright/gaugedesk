#!/usr/bin/env python3
"""Verify the consumer pin; --resolved also executes the owning runtime's checks."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
PIN = "contracts/whipplescript-host-action-pin.json"


def require(condition, message):
    if not condition:
        raise SystemExit(f"WhippleScript action pin: {message}")


def check_pin(root=ROOT):
    pin = json.loads((root / PIN).read_text())
    workstream = json.loads((root / "contracts/whipplescript-workstream-host-pin.json").read_text())
    require(pin.get("schema") == "gaugedesk.whipplescript_host_action_pin.v1", "unsupported pin schema")
    for field in ("source_repository", "source_commit", "source_pull_request", "public_repository", "public_commit"):
        require(pin.get(field) == workstream.get(field), f"{field} disagrees with the workstream runtime pin")
    for field, size in (("source_commit", 40), ("public_commit", 40), ("contract_digest", 64)):
        require(re.fullmatch(f"[0-9a-f]{{{size}}}", pin.get(field, "")), f"invalid {field}")
    require(pin.get("contract_path") == "spec/host-action-contract-v3.json", "unexpected contract path")
    require(pin.get("contract_revision") == "whipplescript-host-action/v3.0.0", "unsupported contract revision")
    adapter = (root / "crates/whip-runtime/src/host_actions.rs").read_text()
    for name, field in (("REVISION", "contract_revision"), ("DIGEST", "contract_digest")):
        require(f'pub const {name}: &str = "{pin[field]}";' in adapter, f"adapter {name} differs from its pin")
    expected_source = f'git+{pin["public_repository"]}?rev={pin["public_commit"]}#{pin["public_commit"]}'
    for directory in (root, root / "src-tauri"):
        manifest = (directory / "Cargo.toml").read_text()
        lock = (directory / "Cargo.lock").read_text()
        for name in ("whipplescript", "whipplescript-kernel", "whipplescript-parser", "whipplescript-store"):
            expected = f'{name} = {{ git = "{pin["public_repository"]}", rev = "{pin["public_commit"]}" }}'
            require(expected in manifest.splitlines(), f"{directory.name} does not pin {name}")
            blocks = [block for block in lock.split("[[package]]") if f'\nname = "{name}"\n' in block]
            require(len(blocks) == 1 and f'source = "{expected_source}"' in blocks[0], f"{directory.name} lock differs for {name}")
    return pin, expected_source


def check_resolved(pin, expected_source, consumer_root=ROOT):
    # Cargo tells us which package the product actually resolves. No peer
    # checkout or caller-supplied alternate runtime may stand in for that pin.
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--format-version", "1"], cwd=consumer_root, text=True,
    ))
    packages = [item for item in metadata["packages"] if item["name"] == "whipplescript-kernel"]
    require(len(packages) == 1 and packages[0]["source"] == expected_source, "Cargo resolved a different runtime")
    runtime = Path(packages[0]["manifest_path"]).resolve().parents[2]
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=runtime, text=True).strip()
    require(commit == pin["public_commit"], "resolved checkout is not the pinned public commit")
    publication = subprocess.check_output(["git", "show", "-s", "--format=%B", "HEAD"], cwd=runtime, text=True)
    require(pin["source_commit"] in publication, "public snapshot does not name the pinned source commit")
    require(subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], cwd=runtime).returncode == 0,
            "resolved runtime has modified tracked files")
    bundle = json.loads((runtime / pin["contract_path"]).read_text())
    for field in ("contract_revision", "contract_digest"):
        require(bundle.get(field) == pin[field], f"resolved bundle has a different {field}")
    # The recording bundle pins its predecessors. Verify all three with the
    # owner's validators; legacy checks alone cannot qualify the v3 pin.
    for validator in ("check-host-action-contract.py", "check-host-action-contract-v2.py",
                      "check-host-action-contract-v3.py"):
        subprocess.run([sys.executable, str(runtime / "scripts" / validator)], cwd=runtime, check=True)
    # Execute the published owner's fixture driver rather than copy its wire
    # schema, normalization or vector assertions into a consumer implementation.
    # Its build output belongs to this consumer worktree, never the Cargo cache.
    # Each publication is a distinct source tree. Cargo's relative dep-info can
    # otherwise reuse the prior publication's path-dependency artifacts when
    # their package versions are unchanged, even after this pin is verified.
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(consumer_root / "target/host-action-contract" / commit)
    subprocess.run([
        "cargo", "test", "--locked", "--manifest-path", str(runtime / "crates/whipplescript-kernel/Cargo.toml"),
        "-p", "whipplescript-kernel", "--test", "host_action_contract",
        "--test", "host_action_contract_v2", "--test", "host_action_contract_v3",
    ], cwd=runtime, env=environment, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resolved", action="store_true")
    parser.add_argument("--consumer-root", type=Path, default=ROOT,
                        help="Cargo consumer to verify against this SDK's pins (defaults to GaugeDesk)")
    args = parser.parse_args()
    pin, expected_source = check_pin()
    if args.resolved:
        check_resolved(pin, expected_source, args.consumer_root.resolve())
    print(f'WhippleScript {pin["contract_revision"]} @ {pin["public_commit"][:12]}: pinned')


if __name__ == "__main__":
    main()
