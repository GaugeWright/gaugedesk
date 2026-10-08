// Resolve the produced app-library test executable, never an ambient fixture.
// Native-web supplies a keyed Buck artifact; ordinary web owns the Cargo tree.
import { accessSync, constants, existsSync, realpathSync, statSync } from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const fixtureVariable = "GAUGEDESK_PANEL_AUTHORING_FIXTURE";
export const cargoArgs = ["test", "--locked", "-p", "gaugedesk-app", "--lib",
  "--no-run", "--message-format=json"];

function executable(path) {
  if (!path || !isAbsolute(path)) throw new Error("panel fixture requires an absolute executable path");
  const canonical = realpathSync(path);
  if (!statSync(canonical).isFile()) throw new Error("panel fixture artifact is not a regular file");
  accessSync(canonical, constants.X_OK);
  return canonical;
}

export function resolveCargoFixture(output, repositoryRoot) {
  const manifest = realpathSync(resolve(repositoryRoot, "crates/app/Cargo.toml"));
  const source = realpathSync(resolve(repositoryRoot, "crates/app/src/lib.rs"));
  const candidates = new Set();
  let finished = false;
  for (const line of output.split("\n")) {
    if (!line.trim()) continue;
    let record;
    try { record = JSON.parse(line); } catch { throw new Error("invalid Cargo compiler JSON"); }
    if (record.reason === "build-finished") finished = record.success === true;
    if (record.reason !== "compiler-artifact" || record.target?.name !== "gaugedesk_app"
      || !record.target?.kind?.includes("lib") || record.profile?.test !== true) continue;
    if (!record.manifest_path || realpathSync(record.manifest_path) !== manifest
      || !record.target.src_path || realpathSync(record.target.src_path) !== source) {
      throw new Error("panel fixture artifact does not belong to the current app library");
    }
    const packageSource = record.package_id?.split("#")[0];
    if (!packageSource?.startsWith("path+file://")
      || realpathSync(resolve(fileURLToPath(packageSource.slice(5)), "Cargo.toml")) !== manifest) {
      throw new Error("panel fixture package identity does not match the current app");
    }
    if (record.executable) {
      const path = executable(record.executable);
      const ownTarget = resolve(realpathSync(repositoryRoot), "target/panel-authoring-fixture");
      if (realpathSync(ownTarget) !== ownTarget) {
        throw new Error("panel fixture target directory redirects outside its owned path");
      }
      const inside = relative(ownTarget, path);
      if (!inside || inside === ".." || inside.startsWith(`..${sep}`) || isAbsolute(inside)) {
        throw new Error("panel fixture executable is outside this checkout's target directory");
      }
      candidates.add(path);
    }
  }
  if (!finished) throw new Error("Cargo did not report a successful test build");
  if (candidates.size !== 1) throw new Error("missing or ambiguous app-library test executable");
  return [...candidates][0];
}

export function preparePanelAuthoringFixture({ repositoryRoot = process.cwd(),
  env = process.env, native = false,
  runCargo = (args, options) => spawnSync("cargo", args, options),
} = {}) {
  const supplied = env[fixtureVariable];
  if (native) {
    if (!supplied) throw new Error("native-web requires its keyed panel fixture artifact");
    return executable(supplied);
  }
  // Ordinary web deliberately does not trust a caller's unkeyed artifact.
  if (supplied) throw new Error("ordinary web must produce its own panel fixture artifact");
  // This preparation alone owns a target below its checkout. Never inherit a
  // service/shared build directory, and do not change the outer web environment.
  const root = realpathSync(repositoryRoot);
  const ownTarget = resolve(root, "target/panel-authoring-fixture");
  for (const path of [resolve(root, "target"), ownTarget]) {
    if (existsSync(path) && realpathSync(path) !== path) {
      throw new Error("panel fixture target directory redirects outside its owned path");
    }
  }
  const cargoEnv = { ...env, CARGO_TARGET_DIR: ownTarget };
  const result = runCargo(cargoArgs, { cwd: repositoryRoot, env: cargoEnv, encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"], maxBuffer: 64 * 1024 * 1024 });
  if (result.error || result.status !== 0) throw new Error("panel fixture Cargo preparation failed");
  return resolveCargoFixture(result.stdout, repositoryRoot);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.slice(2).some((arg) => arg !== "--native")) throw new Error("unsupported fixture preparation option");
    console.log(preparePanelAuthoringFixture({ native: process.argv.includes("--native") }));
  } catch (error) {
    console.error(`panel authoring fixture preparation refused: ${error.message}`);
    process.exitCode = 1;
  }
}
