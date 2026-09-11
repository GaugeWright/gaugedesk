"""Consumer pin drift controls; runtime codec/schema assertions stay upstream."""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("action_pin", ROOT / "scripts/check-whipplescript-host-action.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)

FILES = [
    checker.PIN, "contracts/whipplescript-workstream-host-pin.json",
    "crates/whip-runtime/src/host_actions.rs", "Cargo.toml", "Cargo.lock",
    "src-tauri/Cargo.toml", "src-tauri/Cargo.lock",
]


class PinTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for name in FILES:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)

    def test_current_native_and_desktop_pins_are_one_resolved_identity(self):
        checker.check_pin(self.root)

    def test_another_consumer_cannot_borrow_the_sdks_successful_resolution(self):
        # A real, independent Cargo workspace with no runtime dependency. If
        # --consumer-root is ignored, the SDK's own valid dependency would
        # falsely qualify this consumer instead of refusing it.
        consumer = self.root / "unrelated-consumer"
        (consumer / "src").mkdir(parents=True)
        (consumer / "src/lib.rs").write_text("")
        (consumer / "Cargo.toml").write_text(
            '[package]\nname = "unrelated-consumer"\nversion = "0.1.0"\nedition = "2021"\n[workspace]\n'
        )
        subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=consumer, check=True,
                       capture_output=True, text=True)
        result = subprocess.run([
            sys.executable, str(ROOT / "scripts/check-whipplescript-host-action.py"),
            "--resolved", "--consumer-root", str(consumer),
        ], cwd=ROOT, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Cargo resolved a different runtime", result.stderr)

    def test_changed_source_public_revision_and_digest_are_refused(self):
        path = self.root / checker.PIN
        original = json.loads(path.read_text())
        for field, value in (
            ("source_commit", "0" * 40), ("public_commit", "0" * 40),
            ("contract_digest", "0" * 64),
            ("contract_path", "spec/host-action-contract-v1.json"),
            ("contract_path", "spec/host-action-contract-v2.json"),
            ("contract_revision", "whipplescript-host-action/v1.0.0"),
            ("contract_revision", "whipplescript-host-action/v2.0.0"),
        ):
            with self.subTest(field=field):
                changed = dict(original)
                changed[field] = value
                path.write_text(json.dumps(changed))
                with self.assertRaises(SystemExit):
                    checker.check_pin(self.root)

    def test_neither_manifest_nor_lock_can_leave_a_platform_on_the_old_runtime(self):
        public = json.loads((self.root / checker.PIN).read_text())["public_commit"]
        for name in ("Cargo.toml", "Cargo.lock", "src-tauri/Cargo.toml", "src-tauri/Cargo.lock"):
            with self.subTest(path=name):
                path = self.root / name
                original = path.read_text()
                path.write_text(original.replace(public, "0" * 40, 1))
                with self.assertRaises(SystemExit):
                    checker.check_pin(self.root)
                path.write_text(original)


if __name__ == "__main__":
    unittest.main()
