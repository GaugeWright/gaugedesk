// @vitest-environment node
// WS-71: shipped shared helpers and request transport against the real native
// router. A missing declared native producer is a failure, never a skipped test.
import { spawn, type ChildProcess } from "node:child_process";
import { access } from "node:fs/promises";
import { constants } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { RemoteControlPlane } from "./remote-control-plane";
import {
    copyAgentAsPanel, createArchetype, getPanelProfile, previewAgent,
    setPanelProfile, type WorkbenchTransport,
} from "./control-plane-workbench";
import type { PlacementId } from "./control-plane-domain";

interface Ready {
    protocol: "gaugedesk.panel-authoring-home-fixture.v1";
    base: string;
    owner: string;
    other: string;
}
let child: ChildProcess | undefined;
let closed: Promise<{ code: number | null; signal: NodeJS.Signals | null }>;
let ready: Ready;
let owner: HomeAuthor;
let other: HomeAuthor;
let missing: HomeAuthor;
let raw = "";

// Exposes only the existing protected production transport. No route override,
// fetch interceptor, admission mint, or actor extension exists in this adapter.
class HomeAuthor extends RemoteControlPlane {
    authoring(): WorkbenchTransport { return this.transport(); }
}
// The fixture opens a fresh workbench before it answers, which writes and
// syncs a new state root. On the Legion the whole file takes about 3 s. On
// elitemini, whose synchronous writes are five times slower at rest and far
// slower beside another bar's build, a passing file took 21 to 32 s, and the
// start alone overran the old 20 s bound in five of its last twelve bars
// (WS-1050). The bound is the one the e2e harness gives a control plane to
// start, which elitemini's disk once held for over 40 s (WS-871).
const FIXTURE_READY_MS = 120_000;
async function within<T>(promise: Promise<T>, ms: number, message: string): Promise<T> {
    let timer: ReturnType<typeof setTimeout>;
    try {
        return await Promise.race([promise, new Promise<never>((_, reject) => {
            timer = setTimeout(() => reject(new Error(`${message}\n${raw}`)), ms);
        })]);
    } finally { clearTimeout(timer!); }
}
async function stop() {
    if (!child) return;
    child.stdin?.end();
    try {
        const result = await within(closed, 5000, "native fixture did not stop on EOF");
        expect(result).toEqual({ code: 0, signal: null });
    } catch (error) {
        child.kill("SIGTERM");
        try { await within(closed, 2000, "native fixture did not terminate"); }
        catch { child.kill("SIGKILL"); await within(closed, 2000, "native fixture did not die"); }
        throw error;
    } finally { child = undefined; }
}

beforeAll(async () => {
    const executable = process.env.GAUGEDESK_PANEL_AUTHORING_FIXTURE;
    if (!executable) throw new Error("GAUGEDESK_PANEL_AUTHORING_FIXTURE requires the declared native tool or owning web preparation");
    await access(executable, constants.X_OK);
    child = spawn(executable, ["--ignored", "--exact", "panel_authoring_contract_tests::serve_home", "--nocapture"], { stdio: ["pipe", "pipe", "pipe"] });
    closed = new Promise((resolve, reject) => {
        child!.once("error", reject);
        child!.once("close", (code, signal) => resolve({ code, signal }));
    });
    const line = new Promise<Ready>((resolve, reject) => {
        let buffer = "";
        child!.stdout!.on("data", (bytes: Buffer) => {
            const text = bytes.toString(); raw += text; buffer += text;
            const lines = buffer.split("\n"); buffer = lines.pop()!;
            for (const line of lines) if (line.startsWith("WS71_HOME_READY ")) {
                try { resolve(JSON.parse(line.slice("WS71_HOME_READY ".length)) as Ready); }
                catch (error) { reject(error); }
            }
        });
        child!.stderr!.on("data", (bytes: Buffer) => { raw += bytes.toString(); });
        closed.then((result) => reject(new Error(`fixture closed before ready: ${JSON.stringify(result)}\n${raw}`)), reject);
    });
    try {
        ready = await within(line, FIXTURE_READY_MS, "native fixture readiness timed out");
        expect(ready.protocol).toBe("gaugedesk.panel-authoring-home-fixture.v1");
        expect(new URL(ready.base).hostname).toBe("127.0.0.1");
        expect(ready.owner).not.toBe(ready.other);
        owner = new HomeAuthor(ready.base, { bearer: ready.owner });
        other = new HomeAuthor(ready.base, { bearer: ready.other });
        missing = new HomeAuthor(ready.base, { bearer: ready.owner });
        const home = await owner.admitHome();
        expect(await other.admitHome()).toBe(home);
    } catch (error) {
        try { await stop(); }
        catch (cleanupError) {
            throw new AggregateError([error, cleanupError], "native fixture setup and cleanup failed");
        }
        throw error;
    }
}, FIXTURE_READY_MS + 30_000);
afterAll(stop, 15000);


describe("Panel authoring through actual private Home admission transport", () => {
    it("uses POST-issued admissions for all four routes and preserves state on missing, principal-mismatched and revoked credentials", async () => {
        const own = owner.authoring();
        const alien = other.authoring();
        const otherPanel = await createArchetype(alien, "Other admitted author", "panel");
        expect(await alien.json("GET", `/archetypes/${otherPanel}`)).toMatchObject({ id: otherPanel });
        const source = await createArchetype(own, "Home client work source", "work");
        const sourceBefore = await own.json("GET", `/archetypes/${source}`);
        const id = await copyAgentAsPanel(own, source, "Home client copy");
        expect(id).not.toBe(source);
        const profile = await getPanelProfile(own, id);
        const saved = await setPanelProfile(own, id, { ...profile, panels: { ...profile.panels, components: ["gw-chat", "gw-viewer"] } });
        expect(await getPanelProfile(own, id)).toEqual(saved);
        const published = await own.json("POST", `/archetypes/${id}/publish`, {}) as { version: number };
        const project = await own.json("POST", "/projects", { name: "Home client project" }) as { id: string };
        const placement = await own.json("POST", `/projects/${project.id}/placements`, { agent_id: id }) as { instance_id: string };
        const before = await own.json("GET", "/workspace") as { projects: unknown; recent: unknown; archetypes: { id: string; previews: { chat_id: string; version: number | null }[] }[] };
        const pinned = await previewAgent(own, id, placement.instance_id as PlacementId);
        const draft = await previewAgent(own, id);
        const replacement = await previewAgent(own, id);
        expect(replacement).not.toBe(draft);
        const current = await own.json("GET", "/workspace") as typeof before;
        const previews = current.archetypes.find((a) => a.id === id)!.previews;
        expect(previews).toHaveLength(2);
        expect(previews.find((p) => p.chat_id === pinned)?.version).toBe(published.version);
        expect(previews.map((p) => p.chat_id)).not.toContain(draft);
        expect(current.projects).toEqual(before.projects);
        expect(current.recent).toEqual(before.recent);

        async function denied(client: HomeAuthor) {
            const transport = client.authoring();
            await expect(copyAgentAsPanel(transport, source, "Denied copy")).rejects.toThrow();
            await expect(getPanelProfile(transport, id)).rejects.toThrow();
            await expect(setPanelProfile(transport, id, saved)).rejects.toThrow();
            await expect(previewAgent(transport, id)).rejects.toThrow();
            expect(await own.json("GET", "/workspace")).toEqual(current);
            expect(await own.json("GET", `/archetypes/${source}`)).toEqual(sourceBefore);
            expect(await getPanelProfile(own, id)).toEqual(saved);
        }
        await denied(missing); // Valid account, no Home admission.
        await denied(other); // Valid distinct Home admission, foreign author.
        const mismatched = new HomeAuthor(ready.base, { bearer: ready.owner });
        await mismatched.admitHome();
        mismatched.setBearer(ready.other); // Issued owner admission, different authenticated principal.
        await denied(mismatched);
        // Retain an actually POST-issued token, not a fabricated header. The
        // production RemoteControlPlane sends it and revokes it through DELETE.
        const issued = await own.json("POST", "/home/admissions") as { admission: string };
        const retiring = new HomeAuthor(ready.base, { bearer: ready.owner, homeAdmission: issued.admission });
        const stale = new HomeAuthor(ready.base, { bearer: ready.owner, homeAdmission: issued.admission });
        expect(await getPanelProfile(retiring.authoring(), id)).toEqual(saved);
        await retiring.revokeHomeAdmission();
        await denied(retiring); // Client clears retired credential.
        await denied(stale); // Server refuses the exact retained revoked credential.
        await retiring.admitHome();
        expect(await getPanelProfile(retiring.authoring(), id)).toEqual(saved);
        for (const chat of [pinned, replacement]) await owner.deleteChat(chat);
        const ended = await own.json("GET", "/workspace") as typeof before;
        expect(ended.archetypes.find((a) => a.id === id)!.previews).toEqual([]);
        expect(ended.projects).toEqual(before.projects);
        expect(ended.recent).toEqual(before.recent);
    }, 60000);
});
