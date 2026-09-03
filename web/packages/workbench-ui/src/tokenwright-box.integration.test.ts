/** The client against a real TokenWright box.
 *
 * Everything else about this integration is checked against fixtures, which
 * proves the shapes agree with what this repository *believes* the box sends.
 * This drives an actual supervisor over HTTP, so a disagreement between the two
 * repositories fails here rather than the first time an operator opens the panel.
 *
 * Skipped unless a TokenWright checkout is present, since that repository is not
 * a dependency of this one. `TOKENWRIGHT_ROOT` overrides the default location.
 */

import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
    browserRouteJson,
    openManagementEnvironment,
    proposeManagementDocumentChange,
    readManagementDocument,
    submitManagementCommand,
    type ManagementEnvironmentSession,
    type RouteJson,
} from "@gaugewright/control-plane-client";
import { TOKENWRIGHT_MANIFEST, TOKENWRIGHT_SCHEMAS } from "./tokenwright-environment";
import { tokenwrightCommandsFrom } from "./tokenwright-box";

const ROOT = process.env.TOKENWRIGHT_ROOT ?? "/home/jack/code/TokenWright";
const available = existsSync(join(ROOT, "src", "tokenwright", "__main__.py"));

let box: ChildProcess | undefined;
let state = "";
let key = "";
let base = "";
let session: ManagementEnvironmentSession;
let invitePrinted = "";
/** The real browser transport, pointed at the box once its port is known. */
let json: RouteJson;

/**
 * A port the operating system says is free, rather than one this file picked.
 *
 * A fixed port made the box shared rather than owned. The state root is already
 * per-run, so two runs on one machine each started a box and then both spoke to
 * whichever won the bind — pairing against it, reading a revision from it, and
 * having the *other* run's command move that revision on. The visible symptom
 * was a `conflict` receipt where the test expected `applied` or `rejected`, and
 * the invisible one is worse: a run that passes while exercising a process it
 * did not start.
 */
async function ownPort(): Promise<number> {
    return await new Promise((resolve, reject) => {
        const server = createServer();
        server.on("error", reject);
        server.listen(0, "127.0.0.1", () => {
            const address = server.address();
            const chosen = typeof address === "object" && address ? address.port : 0;
            server.close(() =>
                chosen ? resolve(chosen) : reject(new Error("no loopback port was assigned")),
            );
        });
    });
}


async function run(command: string, args: readonly string[]): Promise<string> {
    return await new Promise((resolve, reject) => {
        const child = spawn(command, [...args], {
            cwd: ROOT, env: { ...process.env, PYTHONPATH: "src" },
        });
        let out = "";
        child.stdout.on("data", (chunk) => { out += String(chunk); });
        child.stderr.on("data", (chunk) => { out += String(chunk); });
        child.on("close", (code) => (code === 0 ? resolve(out) : reject(new Error(out))));
    });
}

/**
 * Every test in this file makes real HTTP round-trips to a spawned Python
 * supervisor. The 5s default is a timeout on *this machine's load*, not on the
 * box: these passed alone and failed inside the full suite, which is the worst
 * shape of flake — it looks like the box got slower when what changed was how
 * many other files were running.
 */
vi.setConfig({ testTimeout: 30_000 });

describe.skipIf(!available)("the client against a real TokenWright box", () => {
    beforeAll(async () => {
        const port = await ownPort();
        base = `http://127.0.0.1:${port}`;
        // Deliberately not a hand-rolled `fetch` wrapper. The point of this test
        // is that the client this repository ships reaches a real box, and a
        // transport written for the test would be the one thing in the path that
        // nobody ships.
        json = browserRouteJson(base, { bearer: () => key || null });
        state = await mkdtemp(join(tmpdir(), "tokenwright-it-"));
        // A relay endpoint only so the box prints a pairing string to parse. It
        // is never dialled: this invocation prints and exits, and the box
        // started below has no relay at all.
        const printed = await run("python3", [
            "-m", "tokenwright", "--state-root", state, "--schemas", "schemas",
            "--no-systemd", "--print-claim-code",
            "--relay-endpoint", "wss://relay.invalid/r",
        ]);
        invitePrinted = /(tw1_[A-Za-z0-9_-]+)/u.exec(printed)?.[1] ?? "";
        if (!invitePrinted) throw new Error(`no pairing string in: ${printed}`);
        const code = /([0-9A-Z]{4}(?:-[0-9A-Z]{4}){4})/u.exec(printed)?.[1];
        if (!code) throw new Error(`no claim code in: ${printed}`);

        box = spawn("python3", [
            "-m", "tokenwright", "--state-root", state, "--schemas", "schemas",
            "--loopback-port", String(port), "--no-systemd",
        ], { cwd: ROOT, env: { ...process.env, PYTHONPATH: "src" } });

        // An unpaired box refuses `/v1/models` with 409, and the transport
        // raises on that — which is the signal that it is listening.
        for (let attempt = 0; attempt < 100; attempt += 1) {
            try {
                await json("GET", "/v1/models");
                break;
            } catch (error) {
                if ((error as { status?: number }).status !== undefined) break;
                await new Promise((resolve) => setTimeout(resolve, 100));
            }
        }

        // Claiming is bootstrap, and bootstrap is the Home's work now: nothing
        // this package ships derives a claim proof any more, because nothing in
        // a browser should be dialling a box. The Rust side owns that
        // derivation and cross-checks it against the box's own
        // (`crates/app/src/tokenwright.rs`), so here the box computes its own
        // proof and this test gets on with what it is for — proving the shipped
        // *client* reaches a real box.
        const proof = await run("python3", [
            "-c", `from tokenwright.pairing import proof_for; print(proof_for(${JSON.stringify(code)}))`,
        ]);
        const claim = await json("POST", "/pair/claim", {
            proof: proof.trim(),
            home: { id: "home_integration", key: "home-root-key" },
        }) as { key: { secret: string }; paired: { fingerprint: string } };
        key = claim.key.secret;
        expect(claim.paired.fingerprint).toMatch(/^sha256:[0-9a-f]{64}$/u);

        session = await openManagementEnvironment(json, "tokenwright");
    }, 60_000);

    afterAll(async () => {
        box?.kill("SIGTERM");
        if (state) await rm(state, { recursive: true, force: true });
    });

    it("opens a session the client can read", () => {
        expect(session.environment).toBe("tokenwright");
        expect(session.actor).toBe("paired-home");
        expect(session.capabilities).toContain("AdministerBox");
    });

    it("grants exactly the documents this repository carries a View for", () => {
        // The two repositories agreeing on the document set is the thing that
        // silently rots. A box adding a document nobody carries a View for
        // renders as generic JSON; one removing a document leaves a dead entry.
        const granted = session.documents.map((document) => document.id).sort();
        const carried = TOKENWRIGHT_MANIFEST.documents.map((document) => document.id).sort();
        expect(granted).toEqual(carried);
    });

    it("serves documents the carried schemas admit", async () => {
        for (const binding of TOKENWRIGHT_MANIFEST.documents) {
            const document = await readManagementDocument(json, session, binding.id);
            expect(document.schema, binding.id).toBe(binding.schema);
            const validate = TOKENWRIGHT_SCHEMAS[binding.schema]!;
            // If this fails, the panel would fall back to generic JSON in front
            // of an operator, and the reason would not be visible anywhere.
            expect(validate(document.content), `${binding.id} against ${binding.schema}`).toBe(true);
        }
    });

    it("runs a granted command end to end", async () => {
        const inference = await readManagementDocument(json, session, "tokenwright.inference");
        const receipt = await submitManagementCommand(json, {
            session_id: session.id, environment: "tokenwright", scope: session.scope,
            document_id: "tokenwright.inference",
            command_id: "tokenwright.posture.rescan",
            base_revision: inference.revision, payload: {}, client: "browser",
        }, "integration-1");
        // A rescan cannot start without systemd, so the box refuses it —
        // deliberately, and as a receipt rather than an error.
        expect(["applied", "rejected"]).toContain(receipt.status);
    });

    it("refuses a command against a stale revision, as a conflict receipt", async () => {
        const receipt = await submitManagementCommand(json, {
            session_id: session.id, environment: "tokenwright", scope: session.scope,
            document_id: "tokenwright.inference",
            command_id: "tokenwright.engine.restart",
            base_revision: "definitely-not-current", payload: {}, client: "browser",
        }, "integration-2");
        expect(receipt.status).toBe("conflict");
    });

    it("declares a key by literal edit and reads the reveal back", async () => {
        const access = await readManagementDocument(json, session, "tokenwright.access");
        // Only the editable block. Spreading the read document back in here is
        // what made this test flaky: `tokenwright.access` projects live relay
        // and direct status, and every key's `last_used_at`, which the box
        // stamps at whole-second granularity. Cross a second boundary between
        // this read and the write below — which authenticating the write can
        // itself cause — and the echoed projection no longer matches what the
        // box holds, so a correct edit takes a 422 `projected_field`. It
        // passed or failed on where the wall clock happened to be.
        await proposeManagementDocumentChange(json, {
            session, documentId: "tokenwright.access", baseRevision: access.revision,
            content: { desired: { keys: ["paired-home", "workstation-editor"] } },
            client: "edit",
        }, "integration-3");

        const after = await readManagementDocument(json, session, "tokenwright.access");
        const value = after.content as {
            keys: readonly { name: string; prefix: string; state: string }[];
            reveal: { key_id: string; secret: string } | null;
        };
        expect(value.keys.map((entry) => entry.name)).toContain("workstation-editor");
        expect(value.reveal).not.toBeNull();
        // The single deliberate secret in any document, and it matches the
        // prefix the same document projects for that key.
        const minted = value.keys.find((entry) => entry.name === "workstation-editor")!;
        expect(value.reveal!.secret.startsWith(minted.prefix)).toBe(true);
    });

    it("binds the box's own grant into runnable controls", async () => {
        const inference = await readManagementDocument(json, session, "tokenwright.inference");
        const commands = tokenwrightCommandsFrom({
            json, session, revisionOf: () => inference.revision,
        });
        // Every command the live grant carries is bound, and nothing else.
        const granted = session.documents.flatMap((document) => document.commands).sort();
        expect(Object.keys(commands).sort()).toEqual(granted);
        expect(granted.length).toBeGreaterThan(0);
        expect(commands["tokenwright.unpair"]?.label).toBe("Unpair this box");
    });

    it("refuses the model surface without a key", async () => {
        const anonymous = browserRouteJson(base, { bearer: () => null });
        await expect(anonymous("GET", "/v1/models")).rejects.toThrow();
    });
});
