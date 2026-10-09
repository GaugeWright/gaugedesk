import { afterEach, describe, expect, it, vi } from "vitest";
import { setDirectoryModuleLoader, type EngagementId, type ArchetypeId, type WorkTargetId, type ProjectId, type PlacementId, type WorkspaceChange } from "@gaugewright/control-plane-client";
import { WorkbenchControlPlane } from "./workbench-control-plane";

const HUB = "https://hub.example";
const OWN = "https://own.example";
const OWN_ROUTED = "https://own-routed.example";
const A = "https://a.example";
const B = "https://b.example";
const C = "https://c.example";
const ID = "home:local-user"; // Deliberately identical on unrelated computers.
const project = (id: string, chatId: string) => ({ id, home_id: ID, name: id, is_personal: false, targets: [], placements: [{
    placement_id: `placement-${id}`, archetype_id: `agent-${id}`, archetype_name: id, is_default: false,
    pinned_version: null, target_ids: [], chats: [chat(chatId, `placement-${id}`)],
}] });
function chat(id: string, placement: string | null = null) {
    return { id, title: id, kind: "work", placement, workspace_root: `root-${id}`, targets: [{ target_id: `target-${id}`, root: `targets/target-${id}`, name: id, kind: "managed", adapter: "managed", adapter_family: "managed", basis: "main", path_scope: ["."], capability_ceiling: { read: true, propose: true, apply: true, publish: false, release: false }, participation: "writable" }], candidate_revision: "rev", available_acts: [] };
}
function workspace(id: string, chatId: string) {
    const own = id === "own-project";
    return { archetypes: own ? [{ id: "own-agent", name: "own-agent", instance_id: "own-agent-instance", authoring_target_id: "own-target", is_default: false, chats: [chat("own-edit")], previews: [{ chat: chat("own-preview") }] }] : [],
        projects: [project(id, chatId)], recent: [], workstreams: [],
        work_targets: own ? [{ id: "other-own-target", name: "Mine", owner_kind: "archetype", owner_id: "own-agent", authority: "person", parties: [], kind: "managed", adapter: "managed", adapter_family: "managed", vcs_posture: "managed", current_basis: "main", path_scope: ["."], capabilities: { read: true, propose: true, apply: true, publish: false, release: false }, status: "available", concurrency: "serialized" }] : [], personal_placement: null };

}

/** The actual browser HTTP and SSE readers run against controlled endpoints.
 * Admissions bind each request to its origin and current account. Directory
 * verification is an installed test codec, not a live account or issuer proof. */
function fixture(hasOwn = true, routedOwn = false) {
    const held = new Map<string, string>();
    const pin = (id: string, endpoint: string) => ({ project: id, homeId: ID, projectKey: `key-${id}`,
        route: { project: id, home_id: ID, endpoint, placement: { project_key: `key-${id}` } } });
    const pins = { "shared-a": pin("shared-a", A), "shared-b": pin("shared-b", B) };
    held.set("gw.shared-projects.v1", JSON.stringify({ person: pins }));
    vi.stubGlobal("localStorage", { getItem: (key: string) => held.get(key) ?? null, setItem: (key: string, value: string) => held.set(key, value) });
    setDirectoryModuleLoader(async () => ({ verify_signed_put_json: () => true }));
    const calls: Array<{ origin: string; method: string; path: string; bearer: string; admission: string }> = [];
    const streams: Array<{ origin: string; closed: boolean; controller: ReadableStreamDefaultController<Uint8Array>; bearer: string; admission: string }> = [];
    const revoked = new Set<string>();
    const unavailable = new Set<string>();
    const admissions = new Map<string, string>();
    let selected = hasOwn;
    let ownData = workspace("own-project", "own-chat");
    let releaseOwn: (() => void) | null = null;
    let holdOwn = false;
    let holdCreate = false;
    let releaseCreate: ((expired: boolean) => void) | null = null;
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(String(input));
        const method = init?.method ?? "GET";
        const headers = new Headers(init?.headers);
        const bearer = headers.get("authorization") ?? "";
        const admission = headers.get("x-gaugewright-home-admission") ?? "";
        calls.push({ origin: url.origin, method, path: url.pathname, bearer, admission });
        if (url.origin === HUB) {
            if (url.pathname === "/account/directory") return Response.json({ root_pubkey: "root", origin: "https://directory.example", subject: "person" });
            if (url.pathname === "/account/home-routes") return Response.json({ routes: routedOwn ? [{ project: "own-project", home_id: ID, endpoint: OWN_ROUTED }] : [] });
            if (url.pathname === "/account/homes") return Response.json({ homes: selected ? [{ id: ID, endpoint: OWN, kind: "registered" }] : [], selected_home: selected ? ID : null });
            if (url.pathname.endsWith("/homes/selected")) return new Response(null, { status: 204 });
            throw new Error(`unexpected Hub ${method} ${url.pathname}`);
        }
        if (url.origin === "https://directory.example") return Response.json({ version: 1, puts: [JSON.stringify({ entry: { directory: { root_pubkey: "root", home_routes: [] } } })] });
        if (unavailable.has(url.origin)) throw new Error("controlled unavailable origin");
        if (method === "POST" && url.pathname === "/home/admissions") {
            if (revoked.has(url.origin) || bearer !== "Bearer account-one") return Response.json({ error: "current standing required" }, { status: 403 });
            const next = `${url.origin}:${calls.filter((call) => call.path === "/home/admissions").length}`;
            admissions.set(url.origin, next);
            return Response.json({ home: ID, admission: next }, { status: 201 });
        }
        if (method === "POST" && url.pathname === "/chats" && holdCreate) {
            holdCreate = false;
            const expired = await new Promise<boolean>((resolve) => { releaseCreate = resolve; });
            if (expired) return Response.json({ error: "target Home admission required" }, { status: 401 });
        }
        if (revoked.has(url.origin) || bearer !== "Bearer account-one") return Response.json({ error: "current standing required" }, { status: 403 });
        if (method === "DELETE" && url.pathname === "/home/admissions") return new Response(null, { status: 204 });
        if (admission !== admissions.get(url.origin)) return Response.json({ error: "target Home admission required" }, { status: 401, headers: { "content-length": String(JSON.stringify({ error: "target Home admission required" }).length) } });
        if (url.pathname === "/workspace/events" || url.pathname.endsWith("/events")) {
            const stream = { origin: url.origin, closed: false, controller: null as unknown as ReadableStreamDefaultController<Uint8Array>, bearer, admission };
            const body = new ReadableStream<Uint8Array>({ start(controller) { stream.controller = controller; }, cancel() { stream.closed = true; } });
            init?.signal?.addEventListener("abort", () => { if (!stream.closed) { stream.closed = true; stream.controller.close(); } });
            streams.push(stream);
            return new Response(body, { headers: { "content-type": "text/event-stream" } });
        }
        if (url.pathname === "/workspace" || url.pathname === "/projections/library/workspace") {
            const data = (url.origin === OWN || url.origin === OWN_ROUTED) ? structuredClone(ownData) : workspace(url.origin === A || url.origin === C ? "shared-a" : "shared-b", url.origin === A || url.origin === C ? "shared-chat-a" : "shared-chat-b");
            if (url.origin === OWN && holdOwn) await new Promise<void>((resolve) => { releaseOwn = resolve; });
            return Response.json(url.pathname === "/workspace" ? data : { value: data, freshness: { marker: "live", generated_at: 1 } });
        }
        if (url.pathname.endsWith("/transcript")) return Response.json([]);
        if (method === "POST" && url.pathname === "/chats") return Response.json({ id: "own-created" });
        if (method === "POST" && url.pathname === "/archetypes") return Response.json({ id: "own-created-agent" });
        if (method === "POST" && url.pathname === "/projects") return Response.json({ id: "own-created-project" });
        if (method === "DELETE" && url.pathname === "/projects/own-created-project") return new Response(null, { status: 204 });
        if (method === "PUT" && url.pathname.startsWith("/chats/")) return new Response(null, { status: 204 });
        if (method === "POST" && url.pathname === "/archetypes/own-agent/fork") return Response.json({ id: "own-fork-agent" });
        if (method === "POST" && url.pathname === "/projects/own-project/fork") return Response.json({ id: "own-fork-project" });
        if (method === "DELETE" && url.pathname === "/projects/own-fork-project") return new Response(null, { status: 204 });
        if (method === "POST" && /\/(?:preview|fork(?:\/7)?)$/.test(url.pathname)) return Response.json({ id: "own-fork-chat" });
        if (method === "POST" && url.pathname === "/placements/own-placement/workstreams") return Response.json({ id: "own-line", name: "Line", placement_id: "own-placement", workspace_root: "root-line", chats: [] });
        if (method === "POST" && url.pathname === "/workstreams/own-line/join") return new Response(null, { status: 204 });
        if (method === "POST" && url.pathname === "/archetypes/own-agent/copy-as-panel") return Response.json({ id: "own-panel" });
        if (method === "GET" && (url.pathname === "/archetypes/own-agent" || url.pathname === "/archetypes/own-panel" || url.pathname === "/archetypes/own-created-agent" || url.pathname === "/archetypes/own-fork-agent")) return Response.json({ config: "own config" });
        if (method === "GET" && url.pathname === "/targets/own-target/acts") return Response.json({ acts: [] });
        if (method === "GET" && url.pathname.endsWith("/file")) return new Response("owned bytes");
        throw new Error(`unexpected ${method} ${url}`);
    }));
    const api = new WorkbenchControlPlane(HUB, { splitHomes: true });
    api.setBearer("account-one");
    return { api, calls, streams, revoked, unavailable, admissions, held, pins,
        emit(origin: string, id = "changed") { for (const stream of streams.filter((s) => s.origin === origin && !s.closed)) stream.controller.enqueue(new TextEncoder().encode(`data: ${JSON.stringify({ type: "workspacechanged", record: "chat", id, op: "upsert" })}\n\n`)); },
        disconnect(origin: string) { for (const stream of streams.filter((s) => s.origin === origin && !s.closed)) { stream.closed = true; stream.controller.close(); } },
        dropPin() { delete (pins as Partial<typeof pins>)["shared-b"]; held.set("gw.shared-projects.v1", JSON.stringify({ person: pins })); },
        movePin() { pins["shared-a"].route.endpoint = C; held.set("gw.shared-projects.v1", JSON.stringify({ person: pins })); },
        replaceOwn(data: typeof ownData) { ownData = data; },
        holdOwn() { holdOwn = true; },
        get ownHeld() { return releaseOwn !== null; },
        releaseOwn() { holdOwn = false; releaseOwn?.(); },
        noOwn() { selected = false; },
        pauseCreate() { holdCreate = true; },
        get createHeld() { return releaseCreate !== null; },
        releaseCreate(expired = false) { releaseCreate?.(expired); },
    };
}

afterEach(() => { setDirectoryModuleLoader(null); vi.unstubAllGlobals(); });

describe("own item origins and composed workspace streams (WS1049)", () => {
    it.each([false, true])("retains actual creator before listing and shared switch (routed=%s)", async (routed) => {
        const f = fixture(true, routed);
        f.api.setCurrentProject("own-project" as ProjectId);
        const made = await f.api.createEngagement();
        const agent = await f.api.createArchetype("New own Agent");
        const project = await f.api.createProject("New own Project");
        // No workspace read lists the new IDs before changing the open project.
        f.api.setCurrentProject("shared-a" as ProjectId);
        await f.api.getTranscript(made.id);
        await f.api.getArchetypeConfig(agent);
        await f.api.deleteProject(project);
        const own = routed ? OWN_ROUTED : OWN;
        expect(f.calls.filter((call) => ["/chats", "/archetypes", "/projects"].includes(call.path)).map((call) => call.origin)).toEqual([own, own, own]);
        expect(f.calls.filter((call) => /own-created/.test(call.path)).map((call) => call.origin)).toEqual([own, own, own]);
    });

    it.each([false, true])("retries the captured creator after project switch (routed=%s)", async (routed) => {
        const f = fixture(true, routed);
        f.api.setCurrentProject("own-project" as ProjectId);
        f.pauseCreate();
        const pending = f.api.createEngagement();
        await vi.waitFor(() => expect(f.createHeld).toBe(true));
        f.api.setCurrentProject("shared-a" as ProjectId);
        f.releaseCreate(true);
        const made = await pending;
        await f.api.getTranscript(made.id);
        const own = routed ? OWN_ROUTED : OWN;
        expect(f.calls.filter((call) => call.path === "/chats" || call.path.includes("own-created")).map((call) => call.origin)).toEqual([own, own, own]);
        expect(f.calls.filter((call) => call.origin === own && call.path === "/home/admissions" && call.method === "POST")).toHaveLength(2);
    });

    it("refuses stale credentials before a creation retry and does not retain its ID", async () => {
        const f = fixture(true, true);
        f.api.setCurrentProject("own-project" as ProjectId);
        f.pauseCreate();
        const pending = f.api.createEngagement();
        const refused = expect(pending).rejects.toThrow();
        await vi.waitFor(() => expect(f.createHeld).toBe(true));
        f.api.setBearer("account-two");
        f.api.setCurrentProject("shared-a" as ProjectId);
        f.releaseCreate(true);
        await refused;
        expect(f.calls.filter((call) => call.path === "/chats")).toHaveLength(1);
        expect(f.calls.filter((call) => call.path === "/home/admissions" && call.method === "POST")).toHaveLength(1);
    });

    it("does not remember a successful creation after own-origin invalidation", async () => {
        const f = fixture(true, true);
        f.api.setCurrentProject("own-project" as ProjectId);
        f.pauseCreate();
        const pending = f.api.createEngagement();
        await vi.waitFor(() => expect(f.createHeld).toBe(true));
        f.api.setHomeAdmission("new-own-context");
        f.api.setCurrentProject("shared-a" as ProjectId);
        f.releaseCreate();
        const made = await pending;
        await f.api.getTranscript(made.id);
        expect(f.calls.at(-1)?.origin).toBe(A);
        expect(f.calls.filter((call) => call.path === "/chats")).toHaveLength(1);
    });

    it("refuses an expired creation retry after own-origin invalidation", async () => {
        const f = fixture(true, true);
        f.api.setCurrentProject("own-project" as ProjectId);
        f.pauseCreate();
        const pending = f.api.createEngagement();
        const refused = expect(pending).rejects.toThrow();
        await vi.waitFor(() => expect(f.createHeld).toBe(true));
        f.api.setHomeAdmission("new-own-context");
        f.api.setCurrentProject("shared-a" as ProjectId);
        f.releaseCreate(true);
        await refused;
        expect(f.calls.filter((call) => call.path === "/chats")).toHaveLength(1);
        expect(f.calls.filter((call) => call.path === "/home/admissions" && call.method === "POST")).toHaveLength(1);
    });

    it("keeps an explicitly shared created chat at the shared origin", async () => {
        const f = fixture();
        await f.api.getWorkspaceCarriage();
        f.api.setCurrentProject("shared-a" as ProjectId);
        const made = await f.api.forkChat("shared-chat-a" as EngagementId);
        f.api.setCurrentProject("shared-b" as ProjectId);
        await f.api.getTranscript(made);
        expect(f.calls.filter((call) => call.path === "/chats/shared-chat-a/fork" || call.path.includes("own-fork-chat")).map((call) => call.origin)).toEqual([A, A]);
    });

    it("retains returned fork, preview and workstream namespaces before listing", async () => {
        const f = fixture(true, true);
        f.api.setCurrentProject("own-project" as ProjectId);
        const agent = await f.api.forkArchetype("own-agent" as ArchetypeId);
        const project = await f.api.forkProject("own-project" as ProjectId);
        const preview = await f.api.previewAgent("own-agent" as ArchetypeId);
        const fork = await f.api.forkChatAt("own-chat" as EngagementId, 7);
        const line = await f.api.createWorkstream("own-placement" as PlacementId, "Line");
        f.api.setCurrentProject("shared-a" as ProjectId);
        await f.api.getArchetypeConfig(agent);
        await f.api.deleteProject(project.id);
        await f.api.getTranscript(preview);
        await f.api.getTranscript(fork);
        await f.api.joinWorkstream(line.id, preview);
        expect(f.calls.filter((call) => /own-fork|workstreams\/own-line/.test(call.path)).map((call) => call.origin)).toEqual(Array(5).fill(OWN_ROUTED));
    });

    it("acts on observed own chats and collisions at the own origin while a shared project is open", async () => {
        const f = fixture();
        f.replaceOwn(workspace("own-project", "shared-chat-a"));
        await f.api.getWorkspaceCarriage();
        f.api.setCurrentProject("shared-a" as ProjectId);
        await f.api.renameChat("shared-chat-a" as EngagementId, "Mine");
        await f.api.getTranscript("shared-chat-a" as EngagementId);
        await f.api.getTranscript("shared-chat-b" as EngagementId);
        expect(f.calls.filter((call) => /chats\//.test(call.path)).map((call) => [call.origin, call.method, call.path])).toEqual([
            [OWN, "PUT", "/chats/shared-chat-a/title"], [OWN, "GET", "/chats/shared-chat-a/transcript"], [B, "GET", "/chats/shared-chat-b/transcript"],
        ]);
        // Unknown items still belong to the open project, not a guessed own Home.
        await f.api.getTranscript("unknown-chat" as EngagementId);
        expect(f.calls.at(-1)?.origin).toBe(A);
        // A new authoritative own read no longer lists the collision; it now
        // belongs to the visible shared row, not an obsolete own observation.
        f.replaceOwn(workspace("own-project", "own-chat"));
        await f.api.getWorkspaceCarriage();
        await f.api.getTranscript("shared-chat-a" as EngagementId);
        expect(f.calls.at(-1)?.origin).toBe(A);
    });

    it("routes own Agent, target, raw bytes, newly created chat and item stream by their own origin", async () => {
        const f = fixture();
        await f.api.getWorkspaceCarriage();
        f.api.setCurrentProject("shared-a" as ProjectId);
        await expect(f.api.getArchetypeConfig("own-agent" as ArchetypeId)).resolves.toBe("own config");
        await expect(f.api.getTargetActs("own-target" as WorkTargetId)).resolves.toEqual([]);
        const panel = await f.api.copyAgentAsPanel("own-agent" as ArchetypeId);
        await expect(f.api.getArchetypeConfig(panel)).resolves.toBe("own config");
        await expect(f.api.getFile("own-edit" as EngagementId, "a.txt")).resolves.toBe("owned bytes");
        const made = await f.api.createEngagement();
        expect(made.id).toBe("own-created");
        await f.api.getTranscript(made.id);
        const stop = f.api.subscribe("own-preview" as EngagementId, () => {});
        try {
            await vi.waitFor(() => expect(f.streams.filter((stream) => !stream.closed).map((stream) => stream.origin)).toEqual([OWN]));
            expect(f.calls.filter((call) => /own-agent|own-panel|own-target|own-edit|own-created|own-preview/.test(call.path)).every((call) => call.origin === OWN)).toBe(true);
            expect(f.calls.find((call) => call.path === "/chats" && call.method === "POST")?.origin).toBe(OWN);
        } finally { stop(); }
        expect(f.streams.every((stream) => stream.closed)).toBe(true);
    });

    it("provides both no-own-Home workspace event streams without opening a project", async () => {
        const f = fixture(false);
        await f.api.getWorkspaceCarriage();
        const changes: WorkspaceChange[] = [];
        const stop = f.api.subscribeWorkspace((change) => changes.push(change));
        try {
            await vi.waitFor(() => expect(f.streams.filter((s) => !s.closed).map((s) => s.origin).sort()).toEqual([A, B]));
            changes.length = 0;
            f.emit(A, "collision"); f.emit(B, "collision");
            await vi.waitFor(() => expect(changes).toHaveLength(2));
            expect(changes).toEqual([{ record: "chat", id: "", op: "upsert" }, { record: "chat", id: "", op: "upsert" }]);
            expect(f.streams.every((s) => s.bearer === "Bearer account-one" && s.admission.startsWith(s.origin))).toBe(true);
            expect(f.calls.filter((call) => call.origin === HUB && call.method !== "GET")).toEqual([]);
            f.api.setCurrentProject("shared-a" as ProjectId);
            await new Promise((resolve) => setTimeout(resolve, 20));
            expect(f.streams.filter((s) => !s.closed).map((s) => s.origin).sort()).toEqual([A, B]);
        } finally { stop(); }
        expect(f.streams.every((s) => s.closed)).toBe(true);
    });

    it("keeps live origins independent, removes pins, re-admits and closes every child before account change", async () => {
        const f = fixture();
        await f.api.getWorkspaceCarriage();
        const changes: WorkspaceChange[] = [];
        const stop = f.api.subscribeWorkspace((change) => changes.push(change));
        try {
            await vi.waitFor(() => expect(f.streams.filter((s) => !s.closed)).toHaveLength(3));
            const admitted = f.calls.filter((call) => call.origin === A && call.method === "POST" && call.path === "/home/admissions").length;
            f.admissions.set(A, "rotated"); f.disconnect(A);
            await vi.waitFor(() => expect(f.streams.filter((s) => s.origin === A && !s.closed)).toHaveLength(1));
            expect(f.calls.filter((call) => call.origin === A && call.method === "POST" && call.path === "/home/admissions")).toHaveLength(admitted + 1);
            f.dropPin();
            // An ordinary fresh route read observes the removed pin.
            await f.api.setCurrentProject(null);
            f.api.setBearer("account-one");
            await f.api.bootstrapHome();
            // Expire A again to request the pool's ordinary fresh route read.
            f.admissions.set(A, "rotated-again"); f.disconnect(A);
            await vi.waitFor(() => expect(f.streams.filter((s) => s.origin === B && !s.closed)).toHaveLength(0));
            f.api.suspendEventStreams();
            expect(f.streams.every((s) => s.closed)).toBe(true);
            const before = f.streams.length;
            await new Promise((resolve) => setTimeout(resolve, 280));
            expect(f.streams).toHaveLength(before);
            f.api.resumeEventStreams();
            await vi.waitFor(() => expect(f.streams.filter((s) => !s.closed)).toHaveLength(2));
            await f.api.closeAccountConnections();
            expect(f.streams.every((s) => s.closed)).toBe(true);
            const delivered = changes.length;
            f.api.setBearer("account-two");
            await new Promise((resolve) => setTimeout(resolve, 300));
            expect(f.streams.every((s) => s.closed)).toBe(true);
            expect(changes).toHaveLength(delivered);
        } finally { stop(); }
    });

    it("replaces a stream when the same project's exact pinned origin changes", async () => {
        const f = fixture(false);
        await f.api.getWorkspaceCarriage();
        const changes: WorkspaceChange[] = [];
        const stop = f.api.subscribeWorkspace((change) => changes.push(change));
        try {
            await vi.waitFor(() => expect(f.streams.filter((stream) => !stream.closed)).toHaveLength(2));
            f.movePin();
            f.admissions.set(A, "expired"); f.disconnect(A);
            await vi.waitFor(() => expect(f.streams.filter((stream) => !stream.closed).map((stream) => stream.origin).sort()).toEqual([B, C]));
            changes.length = 0; f.emit(A); f.emit(C);
            await vi.waitFor(() => expect(changes).toHaveLength(1));
            expect(changes[0]?.id).toBe("");
            expect(f.calls.some((call) => call.origin === C && call.method === "POST" && call.path === "/home/admissions")).toBe(true);
        } finally { stop(); }
    });

    it("keeps available origins live while another is unavailable or its grant is revoked", async () => {
        const f = fixture(false);
        f.unavailable.add(B);
        await f.api.getWorkspaceCarriage();
        const changes: WorkspaceChange[] = [];
        const stop = f.api.subscribeWorkspace((change) => changes.push(change));
        try {
            await vi.waitFor(() => expect(f.streams.filter((stream) => !stream.closed).map((stream) => stream.origin)).toEqual([A]));
            changes.length = 0; f.emit(A);
            await vi.waitFor(() => expect(changes).toHaveLength(1));
            f.unavailable.delete(B);
            await vi.waitFor(() => expect(f.streams.some((stream) => stream.origin === B && !stream.closed)).toBe(true));
            f.revoked.add(A); f.disconnect(A);
            await vi.waitFor(() => expect(f.calls.some((call) => call.origin === A && call.path === "/workspace/events" && call.admission !== "")).toBe(true));
            // Wait for the first bounded retry to actually receive the refusal.
            await new Promise((resolve) => setTimeout(resolve, 300));
            expect(f.streams.filter((stream) => stream.origin === A && !stream.closed)).toEqual([]);
            changes.length = 0; f.emit(A); f.emit(B);
            await vi.waitFor(() => expect(changes).toHaveLength(1));
            expect(changes[0]?.id).toBe("");
        } finally { stop(); }
        expect(f.streams.every((stream) => stream.closed)).toBe(true);
    });

    it("invalidates own observations on a changed selected Home without changing unknown-item fallback", async () => {
        const f = fixture();
        await f.api.getWorkspaceCarriage();
        f.api.setCurrentProject("shared-a" as ProjectId);
        f.noOwn();
        await f.api.selectHome("missing" as never);
        await f.api.getTranscript("own-chat" as EngagementId);
        expect(f.calls.at(-1)?.origin).toBe(A);
    });

    it("does not install own holdings from a read completed under a retired account", async () => {
        const f = fixture();
        f.holdOwn();
        const pending = f.api.getWorkspaceCarriage();
        await vi.waitFor(() => expect(f.ownHeld).toBe(true));
        f.api.setBearer("account-two");
        f.releaseOwn();
        await expect(pending).rejects.toThrow("Workspace context changed");
        f.api.setCurrentProject("shared-a" as ProjectId);
        await expect(f.api.renameChat("own-chat" as EngagementId, "stale")).rejects.toThrow("current standing required");
        expect(f.calls.filter((call) => call.method === "PUT")).toEqual([]);
    });
});
