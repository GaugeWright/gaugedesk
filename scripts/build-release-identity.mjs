#!/usr/bin/env node

// Stamp the built workbench with the contract it was built against.
//
// The systems specification has required since DR-0051 that candidate and
// deployed artifacts expose contract and schema digests, so a deployment gate
// can detect frontend-backend version skew. The hosted surfaces do: each
// publishes `gaugewright-release.json` and the production monitor holds all
// four to one identity. The desktop bundle exposed nothing at all, which is
// the half of the rule that was never implemented.
//
// It matters more here than there, because a hosted surface can be corrected
// by deploying again and an installed client cannot. The desktop bundle embeds
// this same workbench composition (`src-tauri/tauri.conf.json` points
// `frontendDist` at the directory this writes into) and reaches
// `auth.gaugewright.com`, which the platform release moves on its own
// schedule — deliberately, under DR-0078. Two release units over one product
// is a supported arrangement only if the artifacts say which contract they
// hold.
//
// This writes the platform half of the hosted identity: the same field names,
// the same canonical digest, so the two are comparable without translation. It
// carries no cloud revision because nothing here is built from that tree.

import { readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawn } from "node:child_process";

import { manifestDigest } from "./manifest-digest.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** Where the built workbench lands, and what the desktop bundle embeds. */
export const FRONTEND_DIST = "ee/web/dist-enterprise-workbench";

async function capture(command, args, cwd) {
    return await new Promise((ok, fail) => {
        const child = spawn(command, args, { cwd, stdio: ["ignore", "pipe", "inherit"], shell: false });
        let stdout = "";
        child.stdout.setEncoding("utf8");
        child.stdout.on("data", (chunk) => { stdout += chunk; });
        child.once("error", fail);
        // `close`, not `exit`: an identity assembled from a truncated read
        // describes nothing, and would still look like a valid one.
        child.once("close", (code) => code === 0
            ? ok(stdout.trim())
            : fail(new Error(`${command} ${args.join(" ")} exited ${code}`)));
    });
}

/**
 * Every reason a stamped identity would be a claim this tree cannot support.
 *
 * Only checked under `--require-clean`, which the release lane passes. This
 * runs after every frontend build, including the dozens a day that happen over
 * a dirty tree, so refusing by default would make an ordinary local build fail
 * for a reason that does not apply to it.
 */
export function identityFaults({ revision, dirty }) {
    const faults = [];
    if (!/^[0-9a-f]{40}$/.test(revision ?? "")) {
        faults.push(`platform revision is not a full revision: ${revision || "(empty)"}`);
    }
    if (dirty) {
        faults.push(
            `the tree has ${dirty} uncommitted change${dirty === 1 ? "" : "s"}, so `
                + `${revision?.slice(0, 12)} does not describe what would be built`,
        );
    }
    return faults;
}

/**
 * The identity, which says outright when it does not describe a revision.
 *
 * A dirty build gets `dirty: true` rather than a refusal or a silent lie. The
 * revision names committed state, so an artifact built over uncommitted edits
 * carries a digest of what is on disk under the name of what is in git — a
 * gate comparing them would see an agreement that is not there. Saying so is
 * what lets a gate reject it without also breaking every local build.
 */
export function releaseIdentity({ revision, manifest, dirty = 0, surface = "desktop" }) {
    return {
        schemaVersion: 1,
        surface,
        platformRevision: revision,
        platformManifestSha256: manifestDigest(manifest),
        ...(dirty ? { dirty: true } : {}),
    };
}

async function main() {
    const requireClean = process.argv.includes("--require-clean");
    const [revision, status, manifest] = await Promise.all([
        capture("git", ["rev-parse", "HEAD"], root),
        capture("git", ["status", "--porcelain"], root),
        readFile(resolve(root, "contracts/product-routes.json"), "utf8"),
    ]);
    const dirty = status.split("\n").filter(Boolean).length;

    const faults = identityFaults({ revision, dirty: requireClean ? dirty : 0 });
    if (faults.length > 0) {
        console.error(
            "\nThis tree cannot stamp a release identity:\n\n"
                + faults.map((fault) => `  - ${fault}`).join("\n")
                + "\n\nA released artifact must describe a revision someone can check out.\n",
        );
        process.exit(1);
    }

    const identity = releaseIdentity({ revision, manifest, dirty });
    const destination = resolve(root, FRONTEND_DIST, "gaugewright-release.json");
    try {
        await writeFile(destination, `${JSON.stringify(identity, null, 2)}\n`);
    } catch (error) {
        if (error.code !== "ENOENT") throw error;
        // This runs as `postbuild`, so the directory it writes into is the one
        // the build just produced. Missing means the build did not run or did
        // not emit — a stack trace here would send someone looking at this
        // script instead of at the build that came before it.
        console.error(
            `\nThere is no built workbench to stamp: ${FRONTEND_DIST} does not exist.\n\n`
                + "  - run `npm --prefix ee/web run build`, which stamps the identity itself\n",
        );
        process.exit(1);
    }
    console.log(
        `${FRONTEND_DIST}/gaugewright-release.json: platform=${revision.slice(0, 12)} `
            + `manifest=${identity.platformManifestSha256.slice(0, 12)}${dirty ? " (dirty)" : ""}`,
    );
}

// `pathToFileURL`, not string concatenation: the release lane bundles on
// Windows too, where `process.argv[1]` is `D:\a\...` and `import.meta.url` is
// `file:///D:/a/...`. Concatenating would never match there, so the script
// would exit 0 having stamped nothing and the lane would fail afterwards, on
// the JSON read, describing the wrong thing.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
    await main();
}
