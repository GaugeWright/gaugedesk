// Retained fleet workspaces keep node_modules. Directory existence is not an
// install receipt: accept only a successful install for these source/runtime
// inputs, and reject missing package manifests or a changed npm hidden lock.
import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { isAbsolute, join, relative, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const digest = (value) => createHash("sha256").update(value).digest("hex");
const stampName = ".gaugedesk-npm-ready.json";
const installArgs = ["ci", "--include=dev", "--include=optional", "--no-audit", "--no-fund"];

export function prepareNpmDependencies(project, {
  repositoryRoot = process.cwd(),
  runtime = { node: process.version, abi: process.versions.modules,
    platform: process.platform, arch: process.arch },
  runNpm = (args, options) => spawnSync("npm", args, {
    ...options, shell: process.platform === "win32",
  }),
  report = (record) => console.log(`NPM_DEPS: ${JSON.stringify(record)}`),
} = {}) {
  const started = performance.now();
  const root = resolve(project);
  const modules = join(root, "node_modules");
  const stamp = join(modules, stampName);
  if (existsSync(modules) && lstatSync(modules).isSymbolicLink()) {
    throw new Error("npm dependency directory must not be a symlink");
  }
  const sourceInputs = () => {
    const lockBytes = readFileSync(join(root, "package-lock.json"));
    const lock = JSON.parse(lockBytes);
    if (!lock.packages) throw new Error("npm preparation requires a packages lock index");
    const manifests = [["package.json", readFileSync(join(root, "package.json"), "utf8")]];
    for (const key of Object.keys(lock.packages).sort()) {
      if (!key || key.split("/").includes("node_modules")) continue;
      const path = resolve(root, key, "package.json");
      const inside = relative(resolve(repositoryRoot), path);
      if (inside === ".." || inside.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`)
        || isAbsolute(inside)) throw new Error("npm workspace manifest is outside the repository");
      manifests.push([key, readFileSync(path, "utf8")]);
    }
    return { lockBytes, lock, manifests };
  };
  const { lockBytes, lock, manifests } = sourceInputs();
  const version = runNpm(["--version"], { cwd: root, encoding: "utf8" });
  if (version.status !== 0) throw new Error("npm version check failed");
  const identity = digest(JSON.stringify({ schema: 1, lock: digest(lockBytes),
    manifests, runtime, npm: version.stdout.trim(), installArgs }));
  const complete = () => {
    const hidden = join(modules, ".package-lock.json");
    if (!existsSync(hidden)) return null;
    const hiddenBytes = readFileSync(hidden);
    const installed = JSON.parse(hiddenBytes).packages;
    if (!installed) return null;
    for (const [key, entry] of Object.entries(lock.packages)) {
      if (!key.split("/").includes("node_modules")) continue;
      // Unsupported optional OS/CPU packages need not be installed. Every
      // required/dev package and every actually installed optional package does.
      if (!installed[key] && entry.optional) continue;
      const packageManifest = join(root, key, "package.json");
      if (!installed[key] || !existsSync(packageManifest)) return null;
      if (!entry.link && entry.version
        && JSON.parse(readFileSync(packageManifest, "utf8")).version !== entry.version) return null;
    }
    return digest(hiddenBytes);
  };
  const record = (outcome) => report({ project: relative(repositoryRoot, root), outcome,
    elapsedMs: Math.max(0, Math.round(performance.now() - started)) });
  let previous;
  try { previous = JSON.parse(readFileSync(stamp, "utf8")); } catch { /* no valid receipt */ }
  let integrity;
  try { integrity = complete(); } catch { /* invalid install cannot be reused */ }
  if (previous?.identity === identity && integrity && previous.integrity === integrity) {
    record("reused"); return "reused";
  }
  // Invalidate before npm runs: failed or partial installs never get a receipt.
  rmSync(stamp, { force: true });
  const result = runNpm(installArgs, { cwd: root, stdio: "inherit" });
  if (result.status !== 0) {
    record("failed"); throw new Error("npm dependency installation failed");
  }
  const after = sourceInputs();
  if (digest(after.lockBytes) !== digest(lockBytes) || JSON.stringify(after.manifests) !== JSON.stringify(manifests)) {
    record("failed"); throw new Error("npm inputs changed during installation");
  }
  try { integrity = complete(); } catch { integrity = null; }
  if (!integrity) {
    record("failed"); throw new Error("npm installation left an incomplete package index");
  }
  writeFileSync(stamp, JSON.stringify({ identity, integrity }) + "\n");
  record("installed"); return "installed";
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  for (const project of process.argv.slice(2)) prepareNpmDependencies(project);
}
