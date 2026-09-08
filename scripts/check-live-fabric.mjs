#!/usr/bin/env node
/**
 * Refuse to run a check lane over a checkout a development fabric is serving.
 *
 * The fabric runs this checkout: `devctl up --composition desktop --platform
 * <here>` builds this repository's binaries, serves its web packages through a
 * vite dev server, and watches the tree. A check lane then runs four vite
 * builds and a cargo build over that same tree. On 2026-09-04 a fabric died
 * mid-request during exactly that overlap, with no shutdown line and no kernel
 * kill to explain it, and the session that did it spent its time diagnosing a
 * crash rather than the collision that caused one.
 *
 * The lane is not wrong and the fabric is not wrong. Running them over one
 * working tree is, and neither can see the other, so nothing was ever going to
 * report it. This is that report.
 *
 * WHAT THIS READS IS A CROSS-REPOSITORY CONTRACT. gaugewright-cloud's devctl
 * publishes `<state root>/<instance>/status.json`, and its `platform` field
 * names the checkout that instance serves. This repository cannot import that
 * one — a developer may not even have it — so the shape is duplicated here on
 * purpose. It is pinned on the owning side by `devctl.test.mjs`, which asserts
 * the field names this file reads, because a rename there is not a compile
 * error anywhere and would otherwise disarm this guard in silence.
 *
 * Refusing rather than stopping the fabric is deliberate: it is somebody's
 * running demo, quite possibly another session's, and taking it down to run a
 * check is a worse trade than making the check say so.
 */

import { readFileSync, readdirSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** Where devctl keeps per-instance state. Mirrors its own derivation, env
 *  override included, so a developer who moved it is not silently unguarded. */
export function stateRootFrom(env, home) {
    return resolve(
        env.GAUGEWRIGHT_DEV_STATE_ROOT
            ?? resolve(env.XDG_STATE_HOME ?? resolve(home, ".local/state"), "gaugewright-dev"),
    );
}

/** The same path by any name. A worktree reached through a symlink is the same
 *  tree the builds will write to, so compare what the filesystem resolves to
 *  rather than the strings. Unresolvable paths fall back to the input: a
 *  checkout that no longer exists cannot be the one being served. */
export function samePath(left, right) {
    const real = (value) => {
        try {
            return realpathSync(value);
        } catch {
            return value;
        }
    };
    return real(left) === real(right);
}

/** Whether this status record describes a live fabric serving `checkout`.
 *
 *  `alive` is injected so the decision is pure and a test can exercise both
 *  sides of it without a real process to point at. */
export function servingThisCheckout(status, checkout, alive) {
    if (!status || status.phase !== "ready") return false;
    if (typeof status.platform !== "string" || !status.platform) return false;
    if (!Number.isInteger(status.pid) || status.pid <= 1) return false;
    if (!alive(status.pid)) return false;
    return samePath(status.platform, checkout);
}

function processExists(pid) {
    try {
        process.kill(pid, 0);
        return true;
    } catch {
        return false;
    }
}

/** Every live fabric serving `checkout`, by instance name. */
export function liveFabricsServing(stateRoot, checkout, io) {
    let entries;
    try {
        entries = io.readdir(stateRoot);
    } catch {
        // No state directory at all is the ordinary case, and CI's: nobody on
        // this machine has ever run a fabric.
        return [];
    }
    const found = [];
    for (const instance of [...entries].sort()) {
        let status;
        try {
            status = JSON.parse(io.readFile(resolve(stateRoot, instance, "status.json")));
        } catch {
            continue;
        }
        if (servingThisCheckout(status, checkout, io.alive)) found.push({ instance, status });
    }
    return found;
}

export function refusalMessage(found, checkout) {
    const lines = [
        "A development fabric is serving this checkout, and a check lane would run over it.",
        "",
        `  checkout: ${checkout}`,
    ];
    for (const { instance, status } of found) {
        lines.push(`  serving:  ${instance} (pid ${status.pid}) at ${status.panel_url ?? "an unknown url"}`);
    }
    lines.push(
        "",
        "The lane runs vite and cargo builds over the tree that fabric is watching and",
        "running binaries from. That overlap has already killed a fabric mid-session.",
        "",
        "Either stop it, from the gaugewright-cloud checkout:",
        ...found.map(({ instance }) => {
            const index = instance === "fabric" ? "" : ` --instance ${instance.replace("fabric-", "")}`;
            return `  node scripts/devctl.mjs down${index}`;
        }),
        "",
        "or run the lane in a different worktree, which is what they are for.",
    );
    return lines.join("\n");
}

function main() {
    const here = dirname(fileURLToPath(import.meta.url));
    const checkout = resolve(here, "..");
    const stateRoot = stateRootFrom(process.env, homedir());
    const found = liveFabricsServing(stateRoot, checkout, {
        readdir: (path) => readdirSync(path),
        readFile: (path) => readFileSync(path, "utf8"),
        alive: processExists,
    });
    if (!found.length) return;
    console.error(refusalMessage(found, checkout));
    process.exit(1);
}

if (process.argv[1] && samePath(process.argv[1], fileURLToPath(import.meta.url))) main();
