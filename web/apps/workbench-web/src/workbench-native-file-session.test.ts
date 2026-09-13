import { afterEach, describe, expect, it, vi } from "vitest";
import type { NativeSaveJournal, NativeSaveSlot, RetainedNativeSave } from "@gaugewright/control-plane-client";
import { WorkbenchControlPlane } from "./workbench-control-plane";

afterEach(() => vi.unstubAllGlobals());

function deferred<T>() {
    let resolve!: (value: T) => void;
    const promise = new Promise<T>((done) => { resolve = done; });
    return { promise, resolve };
}

function setup(splitHomes = true) {
    const rows = new Map<string, RetainedNativeSave>();
    const key = (slot: NativeSaveSlot) => JSON.stringify([slot.owner, slot.chat, slot.path]);
    const same = (row: RetainedNativeSave) => {
        const current = rows.get(key(row.slot));
        return current?.identity.request_id === row.identity.request_id
            && current?.dispatch_request_id === row.dispatch_request_id;
    };
    const journal: NativeSaveJournal = {
        load: vi.fn(async (slot) => rows.get(key(slot)) ?? null),
        reserve: vi.fn(async (row) => {
            const current = rows.get(key(row.slot));
            if (current) return { row: current, created: false };
            rows.set(key(row.slot), row);
            return { row, created: true };
        }),
        markSubmitted: vi.fn(async (row) => {
            if (!same(row) || rows.get(key(row.slot))?.phase !== "prepared") return false;
            rows.set(key(row.slot), { ...row, phase: "submitted" });
            return true;
        }),
        discardPrepared: vi.fn(async (row) => {
            if (!same(row) || rows.get(key(row.slot))?.phase !== "prepared") return false;
            return rows.delete(key(row.slot));
        }),
        forgetSaved: vi.fn(async (row) => {
            if (!same(row) || rows.get(key(row.slot))?.phase !== "submitted") return false;
            return rows.delete(key(row.slot));
        }),
        close: vi.fn(async () => {}),
    };
    const calls: { url: URL; method: string; init?: RequestInit }[] = [];
    const hooks = {
        actor: "verified-alice",
        routes: true,
        registered: false,
        wrongHome: false,
        beforeRoutes: async () => {},
        beforePreflight: async () => {},
        beforePostReply: async () => {},
        beforeContent: async () => {},
    };
    const fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(String(input));
        const method = init?.method ?? "GET";
        calls.push({ url, method, init });
        if (url.pathname === "/account/home-routes") {
            await hooks.beforeRoutes();
            return Response.json({ routes: hooks.routes ? [
            { project: "project-a", home_id: "home:a", endpoint: "https://a.example" },
            { project: "project-b", home_id: "home:b", endpoint: "https://b.example" },
        ] : [] });
        }
        if (url.pathname === "/account/homes") return Response.json({
            homes: [{ id: "home:z", kind: "registered", endpoint: "https://z.example" },
                ...(hooks.registered ? [{ id: "home:a", kind: "registered", endpoint: "https://a.example" }] : [])],
            selected_home: "home:z",
        });
        const home = `home:${url.hostname[0]}`;
        if (url.pathname === "/home/admissions") return method === "DELETE"
            ? new Response(null, { status: 204 })
            : Response.json({ home: hooks.wrongHome ? "home:wrong" : home, admission: `admission-${home}` });
        if (url.pathname === "/file-actions/actor") return Response.json({ home, actor: hooks.actor });
        if (url.pathname.endsWith("/file-actions/request")) {
            await hooks.beforePreflight();
            return Response.json({ home, issuer: "home-authority", scope: "chat-scope", request_id: url.searchParams.get("request_id") });
        }
        if (url.pathname.endsWith("/file-actions/save")) {
            const body = JSON.parse(String(init?.body));
            const row = [...rows.values()].find((row) => row.identity.request_id === body.identity.request_id);
            expect(row?.phase).toBe("submitted");
            expect(body.expected_actor).toBe("verified-alice");
            await hooks.beforePostReply();
            return Response.json({ identity: body.identity, actor: body.expected_actor, admission: "admitted",
                replayed: false, dispatch_request_id: body.dispatch_request_id, dispatch: { state: "unavailable" } }, { status: 202 });
        }
        const identity = Object.fromEntries(["home", "issuer", "scope", "request_id"].map((key) => [key, url.searchParams.get(key)]));
        if (url.pathname === "/file-actions/saved-content") {
            await hooks.beforeContent();
            return Response.json({ identity, cut: url.searchParams.get("cut"), content: "accepted merged bytes",
                content_hash: "accepted-hash", merged: true, observer: hooks.actor, restrictions: {} });
        }
        if (url.pathname.startsWith("/file-actions/requests/")) {
            const view = url.pathname.split("/").at(-1);
            if (view === "execution") return new Response("runtime unavailable", { status: 503 });
            return Response.json({ identity, view, observer: hooks.actor, restrictions: {}, evidence: view === "saved" ? [{
                effect_id: "effect", run_id: "run", result: { protocol: "gaugedesk.native-editor-saved-result.v1",
                    cut_id: "saved-cut", product_command_id: "product-command", content_hash: "accepted-hash" },
            }] : {} });
        }
        throw new Error(`unexpected fetch ${method} ${url}`);
    });
    vi.stubGlobal("fetch", fetch);
    const api = new WorkbenchControlPlane(splitHomes ? "https://hub.example" : "https://a.example", { splitHomes });
    api.setBearer("opaque-account-session");
    api.setHomeAdmission("original-admission");
    return { api, journal, rows, calls, hooks };
}

describe("app-owned native file save sessions", () => {
    it("submits through the bound Home and recovers its original request after the project moves", async () => {
        const { api, journal, rows, calls } = setup();
        const session = await api.openNativeFileSaveSession("home:a", journal);
        expect(session.actor).toBe("verified-alice");
        api.setCurrentProject("project-b" as never);
        const started = await session.begin("chat", "note.txt", "base-cut", "private draft");
        expect(started.kind).toBe("admitted");
        expect([...rows.values()][0].identity.home).toBe("home:a");
        const moved = await api.openNativeFileSaveSession("home:b", journal);
        const recovered = await moved.recover("chat", "note.txt");
        expect(recovered?.row).toEqual(started.row);
        expect(recovered?.execution.kind).toBe("unavailable");
        expect(recovered?.saved.kind).toBe("observed");
        expect((await moved.savedContent(started.row, "saved-cut")).content).toBe("accepted merged bytes");
        expect(rows.size).toBe(1);
        expect(await moved.acknowledgeSaved(started.row, "saved-cut")).toBe(true);
        expect(rows.size).toBe(0);
        const work = calls.filter(({ url }) => url.pathname.includes("file-actions") && !url.pathname.endsWith("/actor"));
        expect(work.every(({ url }) => url.hostname === "a.example")).toBe(true);
        expect(work.filter(({ method }) => method === "POST")).toHaveLength(1);
        expect(work.some(({ url }) => url.hostname === "hub.example" || url.hostname === "z.example")).toBe(false);
    });

    it("keeps a direct connection's original admission rather than following a changed header", async () => {
        const { api, journal, calls } = setup(false);
        const session = await api.openNativeFileSaveSession("home:a", journal);
        api.setHomeAdmission("another-home-admission");
        await session.begin("chat", "note.txt", "base-cut", "draft");
        const post = calls.find(({ method, url }) => method === "POST" && url.pathname.endsWith("/save"))!;
        expect(new Headers(post.init?.headers).get("x-gaugewright-home-admission")).toBe("original-admission");
        expect(new Headers(post.init?.headers).get("authorization")).toBe("Bearer opaque-account-session");
    });

    it("does not install an old account's route pool after a credential change", async () => {
        const { api, journal, hooks, calls } = setup();
        const entered = deferred<void>(), release = deferred<void>();
        hooks.beforeRoutes = async () => { entered.resolve(); await release.promise; };
        const pending = api.openNativeFileSaveSession("home:a", journal);
        const refused = expect(pending).rejects.toThrow("session changed");
        await entered.promise;
        api.setBearer("bob-session");
        release.resolve();
        await refused;
        expect(calls.some(({ url }) => url.pathname === "/home/admissions")).toBe(false);
        hooks.beforeRoutes = async () => {};
        hooks.actor = "verified-bob";
        const bob = await api.openNativeFileSaveSession("home:b", journal);
        expect(bob.actor).toBe("verified-bob");
        expect(calls.filter(({ url }) => url.pathname === "/account/home-routes")).toHaveLength(2);
    });

    it("refuses a late preflight after credentials change without reserving or transmitting", async () => {
        const { api, journal, hooks, calls, rows } = setup();
        const entered = deferred<void>(), release = deferred<void>();
        hooks.beforePreflight = async () => { entered.resolve(); await release.promise; };
        const session = await api.openNativeFileSaveSession("home:a", journal);
        const pending = session.begin("chat", "note.txt", "base-cut", "draft");
        const refused = expect(pending).rejects.toThrow("session changed");
        await entered.promise;
        api.setBearer("bob-session");
        release.resolve();
        await refused;
        expect(session.current()).toBe(false);
        expect(rows.size).toBe(0);
        expect(journal.reserve).not.toHaveBeenCalled();
        expect(calls.filter(({ url }) => url.pathname.endsWith("/save"))).toHaveLength(0);
    });

    it("retains a submitted request when credentials change during delivery and recovers without another POST", async () => {
        const { api, journal, hooks, calls, rows } = setup();
        const entered = deferred<void>(), release = deferred<void>();
        hooks.beforePostReply = async () => { entered.resolve(); await release.promise; };
        const session = await api.openNativeFileSaveSession("home:a", journal);
        const pending = session.begin("chat", "note.txt", "base-cut", "draft");
        const refused = expect(pending).rejects.toThrow("session changed");
        await entered.promise;
        const original = [...rows.values()][0];
        api.setBearer("bob-session");
        release.resolve();
        await refused;
        expect([...rows.values()]).toEqual([original]);
        api.setBearer("opaque-account-session");
        const reopened = await api.openNativeFileSaveSession("home:b", journal);
        expect((await reopened.recover("chat", "note.txt"))?.row).toEqual(original);
        expect((await reopened.begin("chat", "note.txt", "different-base", "different draft")).kind).toBe("retained");
        expect(calls.filter(({ url }) => url.pathname.endsWith("/save"))).toHaveLength(1);
        expect(session.current()).toBe(false); // returning to the same token cannot revive it
    });

    it("does not transmit after a credential change during the submitted journal transaction", async () => {
        const { api, journal, calls, rows } = setup();
        const originalMark = journal.markSubmitted;
        journal.markSubmitted = async (row) => {
            const result = await originalMark(row);
            api.setBearer("bob-session");
            return result;
        };
        const session = await api.openNativeFileSaveSession("home:a", journal);
        await expect(session.begin("chat", "note.txt", "base-cut", "draft")).rejects.toThrow("session changed");
        expect([...rows.values()][0].phase).toBe("submitted");
        expect(calls.filter(({ url }) => url.pathname.endsWith("/save"))).toHaveLength(0);
    });

    it("closing refuses late saved bytes and preserves the shared journal", async () => {
        const { api, journal, hooks, rows } = setup();
        const session = await api.openNativeFileSaveSession("home:a", journal);
        const started = await session.begin("chat", "note.txt", "base-cut", "draft");
        const entered = deferred<void>(), release = deferred<void>();
        hooks.beforeContent = async () => { entered.resolve(); await release.promise; };
        const pending = session.savedContent(started.row, "saved-cut");
        const refused = expect(pending).rejects.toThrow("session changed");
        await entered.promise;
        session.close();
        release.resolve();
        await refused;
        await expect(session.acknowledgeSaved(started.row, "saved-cut")).rejects.toThrow("session changed");
        expect(journal.close).not.toHaveBeenCalled();
        expect(journal.forgetSaved).not.toHaveBeenCalled();
        expect(rows.size).toBe(1);
    });

    it("another verified actor cannot acknowledge or discard the original owner's row", async () => {
        const { api, journal, hooks, rows } = setup();
        const alice = await api.openNativeFileSaveSession("home:a", journal);
        const started = await alice.begin("chat", "note.txt", "base-cut", "draft");
        hooks.actor = "verified-bob";
        const bob = await api.openNativeFileSaveSession("home:a", journal);
        expect(await bob.recover("chat", "note.txt")).toBeNull();
        await expect(bob.acknowledgeSaved(started.row, "saved-cut")).rejects.toThrow("another actor");
        await expect(bob.discardPrepared(started.row)).rejects.toThrow("another actor");
        expect(rows.size).toBe(1);
        expect(journal.forgetSaved).not.toHaveBeenCalled();
        expect(journal.discardPrepared).not.toHaveBeenCalled();
    });

    it("uses an exact registered original Home when no project route exists, never the selected Home", async () => {
        const { api, journal, hooks, calls } = setup();
        hooks.routes = false;
        hooks.registered = true;
        const session = await api.openNativeFileSaveSession("home:a", journal);
        await session.begin("chat", "note.txt", "base-cut", "draft");
        expect(calls.filter(({ url }) => url.pathname === "/home/admissions")).toHaveLength(1);
        expect(calls.some(({ url }) => url.hostname === "z.example")).toBe(false);
    });

    it("refuses an unreachable original Home and an admission identity mismatch", async () => {
        const missing = setup();
        missing.hooks.routes = false;
        await expect(missing.api.openNativeFileSaveSession("home:a", missing.journal)).rejects.toThrow("original Home");
        expect(missing.calls.some(({ url }) => url.hostname === "z.example")).toBe(false);
        const wrong = setup();
        wrong.hooks.wrongHome = true;
        await expect(wrong.api.openNativeFileSaveSession("home:a", wrong.journal)).rejects.toThrow("identity mismatch");
        expect(wrong.calls.some(({ url }) => url.pathname.includes("file-actions"))).toBe(false);
    });
});
