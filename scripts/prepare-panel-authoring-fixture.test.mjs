import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";
import { cargoArgs, preparePanelAuthoringFixture, resolveCargoFixture } from "./prepare-panel-authoring-fixture.mjs";

function fixture(t) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "ws71-fixture-prep-")));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(join(root, "crates/app/src"), { recursive: true });
  writeFileSync(join(root, "crates/app/Cargo.toml"), "[package]\nname='gaugedesk-app'\n");
  writeFileSync(join(root, "crates/app/src/lib.rs"), "// fixture source\n");
  mkdirSync(join(root, "target/panel-authoring-fixture"), { recursive: true });
  const exe = join(root, "target/panel-authoring-fixture/app-test"); writeFileSync(exe, "fixture binary identity supplied by producer\n"); chmodSync(exe, 0o700);
  const artifact = { reason: "compiler-artifact", package_id: `path+${pathToFileURL(join(root, "crates/app"))}#gaugedesk-app@0.7.1`,
    manifest_path: join(root, "crates/app/Cargo.toml"), target: { name: "gaugedesk_app", kind: ["lib"], src_path: join(root, "crates/app/src/lib.rs") },
    profile: { test: true }, executable: exe };
  const output = (...records) => records.map((r) => JSON.stringify(r)).join("\n") + '\n{"reason":"build-finished","success":true}\n';
  return { root, exe, artifact, output };
}

test("native artifact uses supplied path and never invokes Cargo", (t) => {
  const f = fixture(t);
  assert.equal(preparePanelAuthoringFixture({ native: true, env: { GAUGEDESK_PANEL_AUTHORING_FIXTURE: f.exe },
    runCargo: () => assert.fail("native mode invoked Cargo") }), f.exe);
});

test("native missing/nonexecutable artifact refuses without Cargo fallback", (t) => {
  const f = fixture(t); const runCargo = () => assert.fail("fallback invoked");
  assert.throws(() => preparePanelAuthoringFixture({ native: true, env: {}, runCargo }), /keyed/);
  chmodSync(f.exe, 0o600);
  assert.throws(() => preparePanelAuthoringFixture({ native: true, env: { GAUGEDESK_PANEL_AUTHORING_FIXTURE: f.exe }, runCargo }));
});

test("ordinary web resolves only successful exact own library test and locked argv", (t) => {
  const f = fixture(t);
  assert.equal(preparePanelAuthoringFixture({ repositoryRoot: f.root, env: { CARGO_TARGET_DIR: "/unowned/shared" }, runCargo: (args, options) => {
    assert.deepEqual(args, ["test", "--locked", "-p", "gaugedesk-app", "--lib", "--no-run", "--message-format=json"]);
    assert.equal(options.cwd, f.root);
    assert.equal(options.env.CARGO_TARGET_DIR, join(f.root, "target/panel-authoring-fixture"));
    return { status: 0, stdout: f.output({ ...f.artifact, target: { name: "dependency", kind: ["lib"] } }, f.artifact) };
  } }), f.exe);
  assert(cargoArgs.includes("--locked"));
});

test("ordinary web refuses unkeyed supplied executable and compiler failure", (t) => {
  const f = fixture(t);
  assert.throws(() => preparePanelAuthoringFixture({ repositoryRoot: f.root, env: { GAUGEDESK_PANEL_AUTHORING_FIXTURE: f.exe },
    runCargo: () => assert.fail("unkeyed executable accepted") }), /own/);
  assert.throws(() => preparePanelAuthoringFixture({ repositoryRoot: f.root, env: {}, runCargo: () => ({ status: 1, stdout: f.output(f.artifact) }) }), /failed/);
});

test("JSON resolver refuses malformed, missing, wrong-source and wrong-package artifacts", (t) => {
  const f = fixture(t);
  for (const output of ["not JSON", f.output(), f.output({ ...f.artifact, profile: { test: false } }),
    f.output({ ...f.artifact, target: { ...f.artifact.target, src_path: f.exe } }),
    f.output({ ...f.artifact, package_id: "registry+https://example.invalid#index#other@1" }),
    JSON.stringify(f.artifact)]) assert.throws(() => resolveCargoFixture(output, f.root));
});

test("JSON resolver refuses ambiguous executables; repeated identical artifact is harmless", (t) => {
  const f = fixture(t); const second = join(f.root, "target/panel-authoring-fixture/other-test"); writeFileSync(second, "fixture\n"); chmodSync(second, 0o700);
  assert.throws(() => resolveCargoFixture(f.output(f.artifact, { ...f.artifact, executable: second }), f.root), /ambiguous/);
  assert.equal(resolveCargoFixture(f.output(f.artifact, f.artifact), f.root), f.exe);
});

test("Cargo executable outside own target is refused despite matching compiler identity", (t) => {
  const f = fixture(t); const outside = join(f.root, "borrowed-test"); writeFileSync(outside, "fixture\n"); chmodSync(outside, 0o700);
  assert.throws(() => resolveCargoFixture(f.output({ ...f.artifact, executable: outside }), f.root), /outside/);
});

test("redirected target is refused before invoking Cargo", (t) => {
  const f = fixture(t); const target = join(f.root, "target/panel-authoring-fixture");
  rmSync(target, { recursive: true });
  const other = join(f.root, "other-target"); mkdirSync(other); symlinkSync(other, target, "dir");
  assert.throws(() => preparePanelAuthoringFixture({ repositoryRoot: f.root, env: {},
    runCargo: () => assert.fail("Cargo wrote through redirected target") }), /redirects/);
});
