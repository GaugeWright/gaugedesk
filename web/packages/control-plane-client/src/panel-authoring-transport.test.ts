// @vitest-environment node
// WS-71: shipped shared helpers and request transport against the real native
// router. A missing declared native producer is a failure, never a skipped test.
import { spawn, type ChildProcess } from "node:child_process";
import { access } from "node:fs/promises";
import { constants } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { browserRouteJson } from "./browser-route-json";
import {
    copyAgentAsPanel, createArchetype, getPanelProfile, previewAgent,
    setPanelProfile, type WorkbenchTransport,
} from "./control-plane-workbench";
import type { ArchetypeId, PlacementId } from "./control-plane-domain";

interface Ready {
    protocol: "gaugedesk.panel-authoring-fixture.v1";
    base: string;
    owner: string;
    other: string;
}
let child: ChildProcess | undefined;
let closed: Promise<{ code: number | null; signal: NodeJS.Signals | null }>;
let ready: Ready;
let owner: WorkbenchTransport;
let other: WorkbenchTransport;
let unsigned: WorkbenchTransport;
let raw = "";

function transport(base: string, token: string | null): WorkbenchTransport {
    return { base, json: browserRouteJson(base, { bearer: () => token }) };
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
    child = spawn(executable, ["--ignored", "--exact", "panel_authoring_contract_tests::serve", "--nocapture"], { stdio: ["pipe", "pipe", "pipe"] });
    closed = new Promise((resolve, reject) => {
        child!.once("error", reject);
        child!.once("close", (code, signal) => resolve({ code, signal }));
    });
    const line = new Promise<Ready>((resolve, reject) => {
        let buffer = "";
        child!.stdout!.on("data", (bytes: Buffer) => {
            const text = bytes.toString(); raw += text; buffer += text;
            const lines = buffer.split("\n"); buffer = lines.pop()!;
            for (const line of lines) if (line.startsWith("WS71_READY ")) {
                try { resolve(JSON.parse(line.slice("WS71_READY ".length)) as Ready); }
                catch (error) { reject(error); }
            }
        });
        child!.stderr!.on("data", (bytes: Buffer) => { raw += bytes.toString(); });
        closed.then((result) => reject(new Error(`fixture closed before ready: ${JSON.stringify(result)}\n${raw}`)), reject);
    });
    try {
        ready = await within(line, FIXTURE_READY_MS, "native fixture readiness timed out");
        expect(ready.protocol).toBe("gaugedesk.panel-authoring-fixture.v1");
        expect(new URL(ready.base).hostname).toBe("127.0.0.1");
        expect(ready.owner).not.toBe(ready.other);
        owner = transport(ready.base, ready.owner);
        other = transport(ready.base, ready.other);
        unsigned = transport(ready.base, null);
    } catch (error) {
        try { await stop(); }
        catch (cleanupError) {
            throw new AggregateError([error, cleanupError], "native fixture setup and cleanup failed");
        }
        throw error;
    }
}, FIXTURE_READY_MS + 30_000);
afterAll(stop, 15000);

describe("Panel authoring real production-client transport", () => {
    // panel-authoring-production-client / panel-authoring-authority
    it("copies an owned Agent into a new Panel lineage and refuses foreign or unsigned callers", async () => {
        const source = await createArchetype(owner, "Shared-client work source", "work");
        const before = await owner.json("GET", `/archetypes/${source}`);
        for (const denied of [other, unsigned]) {
            await expect(copyAgentAsPanel(denied, source, "Forbidden copy")).rejects.toThrow();
            expect(await owner.json("GET", `/archetypes/${source}`)).toEqual(before);
        }
        const copy = await copyAgentAsPanel(owner, source, "Shared-client Panel copy");
        expect(copy).not.toBe(source);
        expect(await owner.json("GET", `/archetypes/${source}`)).toEqual(before);
        expect(await owner.json("GET", `/archetypes/${copy}`)).toMatchObject({ id: copy, kind: "panel", name: "Shared-client Panel copy" });
    }, 60000);

    // panel-authoring-contract / panel-authoring-property
    it("roundtrips the real profile wire and preserves saved state after invalid or denied edits", async () => {
        const id = await createArchetype(owner, "Shared-client profile", "panel");
        const original = await getPanelProfile(owner, id);
        for (const components of [["gw-chat"], ["gw-chat", "gw-files"], ["gw-chat", "gw-viewer"]] as const) {
            const saved = await setPanelProfile(owner, id, { ...original, panels: { ...original.panels, components } });
            expect(await getPanelProfile(owner, id)).toEqual(saved);
            for (const denied of [other, unsigned]) {
                await expect(getPanelProfile(denied, id)).rejects.toThrow();
                await expect(setPanelProfile(denied, id, saved)).rejects.toThrow();
            }
            await expect(setPanelProfile(owner, id, { ...saved, panels: { ...saved.panels, components: [] } })).rejects.toThrow();
            await expect(setPanelProfile(owner, id, { ...saved, public_abilities: ["command.run"] })).rejects.toThrow();
            expect(await getPanelProfile(owner, id)).toEqual(saved);
        }
    }, 60000);

    // panel-authoring-preview / panel-authoring-journey
    it("opens draft and pinned-version previews only under their author, replaces drafts, and ends them", async () => {
        const id = await createArchetype(owner, "Shared-client preview", "panel");
        const published = await owner.json("POST", `/archetypes/${id}/publish`, {}) as { version: number };
        const project = await owner.json("POST", "/projects", { name: "Shared-client preview project" }) as { id: string };
        const placed = await owner.json("POST", `/projects/${project.id}/placements`, { agent_id: id }) as { instance_id: string };
        const before = await owner.json("GET", "/workspace") as { projects: unknown; recent: unknown };
        for (const denied of [other, unsigned]) await expect(previewAgent(denied, id)).rejects.toThrow();
        const pinned = await previewAgent(owner, id, placed.instance_id as PlacementId);
        const draft = await previewAgent(owner, id);
        const ws = await owner.json("GET", "/workspace") as typeof before & { archetypes: { id: ArchetypeId; previews: { chat_id: string; version: number | null }[] }[] };
        expect(ws.projects).toEqual(before.projects);
        expect(ws.recent).toEqual(before.recent);
        const previews = ws.archetypes.find((agent) => agent.id === id)!.previews;
        expect(previews).toHaveLength(2);
        expect(previews.find((preview) => preview.chat_id === pinned)?.version).toBe(published.version);
        const replacement = await previewAgent(owner, id);
        expect(replacement).not.toBe(draft);
        const replacementWs = await owner.json("GET", "/workspace") as typeof ws;
        expect(replacementWs.archetypes.find((agent) => agent.id === id)!.previews.map((preview) => preview.chat_id)).not.toContain(draft);
        for (const chat of [pinned, replacement]) await owner.json("DELETE", `/chats/${chat}`);
        const ended = await owner.json("GET", "/workspace") as typeof ws;
        expect(ended.archetypes.find((agent) => agent.id === id)!.previews).toEqual([]);
        expect(ended.projects).toEqual(before.projects);
    }, 60000);
});
