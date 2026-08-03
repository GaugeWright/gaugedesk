/**
 * Concurrency-safe e2e launcher (the `npm run e2e` entrypoint).
 *
 * Resolves the harness ports ONCE — honoring `GW_E2E_{ALICE,BOB,BROKER,PREVIEW,ENTERPRISE,
 * ENTERPRISE_APP}` if set (CI reproducibility), else binding `:0` to grab free ones —
 * then runs the pipeline (the open + enterprise workbench `vite build`s → `bddgen` →
 * `playwright test`) as children that inherit the resolved values.
 * Because every port is chosen up front and exported, a parallel run / second worktree picks a
 * disjoint set and the two never collide. `VITE_CP_BASE` points the built client at this run's
 * control plane; the playwright config derives CORS + state dirs from the same vars.
 *
 * Pass extra args straight through to `playwright test`, e.g.
 * `npm run e2e -- --grep @live-provider`.
 */

import { execSync, spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { createServer } from "node:net";
import { fileURLToPath } from "node:url";
import path from "node:path";

/** A free TCP port from the OS (bind :0, read the assignment, release). */
function freePort() {
    return new Promise((resolve, reject) => {
        const srv = createServer();
        srv.unref();
        srv.on("error", reject);
        srv.listen(0, "127.0.0.1", () => {
            const { port } = srv.address();
            srv.close(() => resolve(port));
        });
    });
}

async function resolve(name, dflt) {
    if (process.env[name]) return Number(process.env[name]);
    // No explicit port: grab a free one (default kept only as a last-resort fallback).
    try {
        return await freePort();
    } catch {
        return dflt;
    }
}

const alice = await resolve("GW_E2E_ALICE", 7878);
const bob = await resolve("GW_E2E_BOB", 7879);
const broker = await resolve("GW_E2E_BROKER", 7900);
const preview = await resolve("GW_E2E_PREVIEW", 4173);
// The combined enterprise workbench preview and its enterprise control plane.
const enterprise = await resolve("GW_E2E_ENTERPRISE", 7882);
const enterpriseApp = await resolve("GW_E2E_ENTERPRISE_APP", 4174);

const env = {
    ...process.env,
    GW_E2E_ALICE: String(alice),
    GW_E2E_BOB: String(bob),
    GW_E2E_BROKER: String(broker),
    GW_E2E_PREVIEW: String(preview),
    GW_E2E_ENTERPRISE: String(enterprise),
    GW_E2E_ENTERPRISE_APP: String(enterpriseApp),
    // The built client talks to THIS run's control plane (overrides SOLO_CONTROL_PLANE).
    VITE_CP_BASE: `http://127.0.0.1:${alice}`,
};
if (process.env.GW_E2E_LIVE) {
    // The live lane exercises the selected WhippleScript runtime and a real model.
    delete env.GAUGEWRIGHT_FAKE_AGENT;
} else {
    env.GAUGEWRIGHT_FAKE_AGENT = process.env.GAUGEWRIGHT_FAKE_AGENT ?? "1";
    env.GAUGEWRIGHT_FAKE_MANAGEMENT_AGENT =
        process.env.GAUGEWRIGHT_FAKE_MANAGEMENT_AGENT ?? "1";
}

// The enterprise lane (`GW_E2E_COMPOSITION=enterprise`, `npm run e2e:enterprise`)
// serves the combined enterprise workbench at the preview origin and skips the
// @open-only features (surfaces that ship only in the open bundle).
const enterpriseLane = process.env.GW_E2E_COMPOSITION === "enterprise";

console.log(
    `[e2e] ports → alice:${alice} bob:${bob} broker:${broker} preview:${preview} ` +
        `enterprise:${enterprise} enterpriseApp:${enterpriseApp}`,
);
console.log(
    `[e2e] composition at preview origin → ${enterpriseLane ? "enterprise workbench" : "open workbench"}`,
);

const passthrough = process.argv.slice(2);
// Default run skips real-model @live-provider scenarios; `GW_E2E_LIVE=1` runs only those.
const invert = [
    ...(process.env.GW_E2E_LIVE ? [] : ["@live-provider"]),
    ...(enterpriseLane ? ["@open-only"] : []),
];
const grep = [
    ...(process.env.GW_E2E_LIVE ? ["--grep", "@live-provider"] : []),
    ...(invert.length ? ["--grep-invert", invert.join("|")] : []),
];

// The standalone app workspaces (each its own npm workspace consuming the platform
// packages via file: deps). Their bundles are built here so Playwright's static
// previews (playwright.config.ts webServer) have a dist to serve.
const repoRoot = path.resolve(fileURLToPath(new URL(".", import.meta.url)), "../..");
const eeWeb = path.join(repoRoot, "ee", "web");

/** `npm ci` steps for app workspaces whose node_modules are absent (fresh checkout). */
const installs = [eeWeb]
    .filter((dir) => !existsSync(path.join(dir, "node_modules")))
    .map((dir) => ["npm", ["ci"], { cwd: dir }]);

const steps = [
    ...installs,
    // The open harness scripts exec target/debug/gaugewright-app directly.
    // Build that exact binary first: building the enterprise server can refresh
    // the app library dependency without refreshing the standalone executable,
    // which otherwise lets browser acceptance exercise a stale route surface.
    [
        "cargo",
        ["build", "-p", "gaugewright-app", "--bin", "gaugewright-app"],
        { cwd: repoRoot },
    ],
    // The enterprise webServer likewise launches this exact debug binary.
    [
        "cargo",
        ["build", "-p", "gaugewright-ee", "--bin", "gaugewright-enterprise-server"],
        { cwd: repoRoot },
    ],
    [
        "cargo",
        [
            "build",
            "-p",
            "gaugewright-relay-transport",
            "--features",
            "test-relay",
            "--example",
            "test-wss-relay",
        ],
        { cwd: repoRoot },
    ],
    ["npx", ["vite", "build"]],
    // The combined enterprise workbench (ee/web).
    ["npx", ["vite", "build", "--config", "apps/enterprise-workbench/vite.config.ts"], { cwd: eeWeb }],
    ["npx", ["bddgen"]],
    ["npx", ["playwright", "test", ...grep, ...passthrough]],
];

// Interrupt-safe teardown (orphan hygiene): with the blocking spawnSync this used to use, a
// SIGINT/SIGTERM (Ctrl-C, a `timeout` expiry) could not be handled until the child exited, so
// an interrupted run orphaned the harness servers (the broker + control planes + preview) —
// and enough orphans starve a later run's control plane. Two moves on a signal:
//   1. kill the step's process group (the Playwright runner + vite build/bddgen);
//   2. free THIS run's four resolved ports — Playwright spawns its webServers *detached* (their
//      own process groups), so the only reliable way to reap them is by the ports they hold.
// Both are scoped to this run alone (its group + its ports) — never a name-based sweep (the
// landmine `control-plane.sh` carried).
let activeChild = null;
let tearingDown = false;

function killGroup(child, signal) {
    if (!child || child.exitCode !== null) return;
    try {
        process.kill(-child.pid, signal); // negative pid → the child's process group
    } catch {
        /* group already gone */
    }
}

/** Free this run's own ports (kills whatever's listening on them) — port-scoped, never by name. */
function freeOwnPorts() {
    for (const port of [alice, bob, broker, preview, enterprise, enterpriseApp]) {
        try {
            execSync(
                `fuser -k ${port}/tcp 2>/dev/null || lsof -ti tcp:${port} 2>/dev/null | xargs -r kill -9`,
                { stdio: "ignore", shell: "/bin/bash" },
            );
        } catch {
            /* nothing on that port */
        }
    }
}

function teardown(exitCode) {
    if (tearingDown) return;
    tearingDown = true;
    console.log("\n[e2e] interrupted — tearing down this run's servers…");
    killGroup(activeChild, "SIGTERM");
    freeOwnPorts();
    killGroup(activeChild, "SIGKILL");
    process.exit(exitCode);
}
process.on("SIGINT", () => teardown(130));
process.on("SIGTERM", () => teardown(143));

function runStep(cmd, args, opts = {}) {
    return new Promise((resolve, reject) => {
        // detached → a new process group we can signal as a whole on interrupt.
        const child = spawn(cmd, args, { stdio: "inherit", env, detached: true, ...opts });
        activeChild = child;
        child.on("error", reject);
        child.on("exit", (code, signal) => {
            activeChild = null;
            // If we're tearing down, the child exited from our signal — finish the exit.
            if (tearingDown) process.exit(code ?? 130);
            resolve(code ?? (signal ? 1 : 0));
        });
    });
}

for (const [cmd, args, opts] of steps) {
    if (tearingDown) break;
    const code = await runStep(cmd, args, opts);
    if (code !== 0) process.exit(code);
}
