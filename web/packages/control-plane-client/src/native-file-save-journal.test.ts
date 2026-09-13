import { describe, expect, it, vi } from "vitest";
import { nativeSaveRequests, type NativeSaveJournal, type RetainedNativeSave } from "./native-file-save-journal";

const slot = { owner: "account-one", chat: "chat-one", path: "note.txt" };
const identity = { home: "home-original", issuer: "issuer", scope: "original-scope", request_id: "save-one" };
const row: RetainedNativeSave = { schema: "gaugedesk.native-save-journal.v1", slot, identity,
    dispatch_request_id: "dispatch-one", phase: "prepared" };
function store(initial: RetainedNativeSave | null = null) {
    let current = initial;
    const same = (value: RetainedNativeSave) => current?.identity.request_id === value.identity.request_id;
    const journal: NativeSaveJournal = {
        load: vi.fn(async () => current),
        reserve: vi.fn(async (value) => { if (current) return { row: current, created: false }; current = value; return { row: value, created: true }; }),
        markSubmitted: vi.fn(async (value) => { if (!same(value) || current?.phase !== "prepared") return false; current = { ...current, phase: "submitted" }; return true; }),
        discardPrepared: vi.fn(async (value) => { if (!same(value) || current?.phase !== "prepared") return false; current = null; return true; }),
        forgetSaved: vi.fn(async (value) => { if (!same(value) || current?.phase !== "submitted") return false; current = null; return true; }),
        close: async () => {},
    };
    return { journal, current: () => current };
}
function setup(journal: NativeSaveJournal) {
    const json = vi.fn(async (method: string, path: string, body?: unknown): Promise<unknown> => {
        if (method === "GET" && path.includes("/file-actions/request?")) return identity;
        if (method === "POST") return { identity, actor: slot.owner, admission: "admitted", replayed: false,
            dispatch_request_id: (body as { dispatch_request_id: string }).dispatch_request_id,
            dispatch: { state: "authorized", grant_ref: "grant", replayed: false } };
        const view = new URL(path, "https://example.invalid").pathname.split("/").at(-1);
        if (view === "execution") throw new Error("runtime erased");
        return { identity, view, observer: slot.owner, restrictions: {}, evidence: view === "saved" ? [] : {} };
    });
    const connect = vi.fn(async (home: string) => ({ home, transport: { base: "", json } }));
    const keys = vi.fn().mockReturnValueOnce(identity.request_id).mockReturnValueOnce("dispatch-one");
    return { json, connect, keys, controller: nativeSaveRequests(journal, connect, keys) };
}

describe("retained native save lifecycle", () => {
    it("reads accepted content for the retained owner without persisting bytes or acknowledging Saved", async () => {
        const submitted = { ...row, phase: "submitted" as const };
        const { journal, current } = store(submitted);
        const { controller, json, connect } = setup(journal);
        const accepted = { identity, cut: "saved-cut", content: "accepted bytes", content_hash: "hash",
            merged: true, observer: slot.owner, restrictions: {} };
        json.mockResolvedValue(accepted);
        expect(await controller.savedContent(submitted, "saved-cut")).toEqual(accepted);
        expect(connect).toHaveBeenCalledWith(identity.home);
        expect(current()).toEqual(submitted);
        expect(JSON.stringify(current())).not.toContain("accepted bytes");
        expect(journal.forgetSaved).not.toHaveBeenCalled();
        json.mockResolvedValue({ ...accepted, observer: "another-owner" });
        await expect(controller.savedContent(submitted, "saved-cut")).rejects.toThrow("another actor");
        await expect(controller.savedContent({ ...submitted, identity: { ...identity, request_id: "stale" } }, "saved-cut"))
            .rejects.toThrow("original submitted save");
        expect(current()).toEqual(submitted);
    });
    it("persists submitted intent before the single transport call", async () => {
        const { journal, current } = store();
        const { controller, json } = setup(journal);
        const original = json.getMockImplementation()!;
        json.mockImplementation(async (...args) => {
            if (args[0] === "POST") {
                expect(current()?.phase).toBe("submitted");
                expect(args[2]).toHaveProperty("expected_actor", slot.owner);
            }
            return original(...args);
        });
        const result = await controller.begin(slot, identity.home, "cut", "private draft");
        expect(result.kind).toBe("admitted");
        expect(json.mock.calls.filter(([method]) => method === "POST")).toHaveLength(1);
        expect(JSON.stringify(current())).not.toContain("private draft");
        expect(current()).toEqual({ ...row, phase: "submitted" });
    });

    it("refuses transmission when reservation or submitted persistence fails", async () => {
        for (const method of ["reserve", "markSubmitted"] as const) {
            const { journal } = store();
            journal[method] = vi.fn().mockRejectedValue(new Error("transaction aborted"));
            const { controller, json } = setup(journal);
            await expect(controller.begin(slot, identity.home, "cut", "draft")).rejects.toThrow("aborted");
            expect(json.mock.calls.some(([method]) => method === "POST")).toBe(false);
        }
    });

    it("uses an existing request after reload or Home movement without allocating or submitting", async () => {
        for (const phase of ["prepared", "submitted"] as const) {
            const { journal } = store({ ...row, phase });
            const { controller, json, connect, keys } = setup(journal);
            expect((await controller.begin(slot, "home-new", "new-cut", "different draft")).kind).toBe("retained");
            expect(connect).not.toHaveBeenCalled(); expect(keys).not.toHaveBeenCalled();
            const recovered = await controller.recover(slot);
            expect(connect).toHaveBeenCalledWith(identity.home);
            expect(recovered?.execution.kind).toBe("unavailable");
            expect(recovered?.saved.kind).toBe("observed");
            expect(json.mock.calls.map(([method]) => method)).toEqual(["GET", "GET", "GET"]);
            expect(journal.forgetSaved).not.toHaveBeenCalled();
        }
    });

    it("keeps uncertain submission and never retries after a lost response", async () => {
        const { journal, current } = store();
        const first = setup(journal); const original = first.json.getMockImplementation()!;
        first.json.mockImplementation(async (...args) => { if (args[0] === "POST") throw new Error("response lost"); return original(...args); });
        expect((await first.controller.begin(slot, identity.home, "cut", "draft")).kind).toBe("uncertain");
        expect(current()?.phase).toBe("submitted");
        const reopened = setup(journal);
        expect((await reopened.controller.begin(slot, identity.home, "cut", "draft")).kind).toBe("retained");
        expect(reopened.json).not.toHaveBeenCalled();
        expect(await journal.discardPrepared(row)).toBe(false);
    });

    it("requires a fresh matching Saved fact before forgetting and refuses stale acknowledgments", async () => {
        const submitted = { ...row, phase: "submitted" as const };
        const { journal, current } = store(submitted);
        const { controller, json } = setup(journal);
        expect(await controller.acknowledgeSaved(submitted, "saved-cut")).toBe(false);
        expect(current()).toEqual(submitted);
        json.mockResolvedValue({ identity, view: "saved", observer: slot.owner, restrictions: {}, evidence: [{
            effect_id: "effect", run_id: "attempt", result: { protocol: "gaugedesk.native-editor-saved-result.v1",
                cut_id: "saved-cut", product_command_id: "command", content_hash: "hash" },
        }] });
        expect(await controller.acknowledgeSaved(submitted, "wrong-cut")).toBe(false);
        expect(await controller.acknowledgeSaved({ ...submitted, identity: { ...identity, request_id: "older" } }, "saved-cut")).toBe(false);
        expect(await controller.acknowledgeSaved(submitted, "saved-cut")).toBe(true);
        expect(current()).toBeNull();
    });

    it("refuses a substituted Home transport before preparing or publishing intent", async () => {
        const { journal } = store(); const json = vi.fn();
        const controller = nativeSaveRequests(journal, async () => ({ home: "substituted", transport: { base: "", json } }));
        await expect(controller.begin(slot, identity.home, "cut", "draft")).rejects.toThrow("another Home");
        expect(json).not.toHaveBeenCalled(); expect(journal.reserve).not.toHaveBeenCalled();
    });

    it("refuses another authorized reader's response without clearing the owner's submitted request", async () => {
        const submitted = { ...row, phase: "submitted" as const };
        const { journal, current } = store(submitted);
        const { controller, json } = setup(journal);
        json.mockImplementation(async (_method, path) => {
            const view = new URL(path, "https://example.invalid").pathname.split("/").at(-1);
            return { identity, view, observer: "other-account", restrictions: {},
                evidence: view === "saved" ? [{ effect_id: "effect", run_id: "run", result: {
                    protocol: "gaugedesk.native-editor-saved-result.v1", cut_id: "saved-cut",
                    product_command_id: "command", content_hash: "hash" } }]
                    : view === "execution" ? { command: {}, runtime: null } : {} };
        });
        const observed = await controller.recover(slot);
        expect([observed?.command.kind, observed?.execution.kind, observed?.saved.kind])
            .toEqual(["unavailable", "unavailable", "unavailable"]);
        await expect(controller.acknowledgeSaved(submitted, "saved-cut")).rejects.toThrow("another actor");
        expect(journal.forgetSaved).not.toHaveBeenCalled();
        expect(current()).toEqual(submitted);
    });
});
