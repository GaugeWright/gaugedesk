import { describe, expect, it, vi } from "vitest";
import type { WorkbenchTransport } from "./control-plane-workbench";
import { observeNativeFileActor, observeNativeFileRequest, parseNativeFileRequestIdentity, prepareNativeFileSaveRequest, readNativeFileSavedContent, submitNativeFileSave } from "./native-file-actions";

it("reads verified actor metadata from the exact Home without accepting credentials or a substituted Home", async () => {
    const json = vi.fn().mockResolvedValue({ home: "home-one", actor: "alice" });
    expect(await observeNativeFileActor({ base: "", json }, "home-one")).toEqual({ home: "home-one", actor: "alice" });
    expect(json.mock.calls).toEqual([["GET", "/file-actions/actor"]]);
    for (const value of [{ home: "other", actor: "alice" }, { home: "home-one", actor: "" },
        { home: "home-one", actor: "alice", bearer: "must-not-be-returned" }]) {
        json.mockResolvedValue(value);
        await expect(observeNativeFileActor({ base: "", json }, "home-one")).rejects.toThrow("unavailable");
    }
});

const identity = { home: "home-one", issuer: "issuer-one", scope: '["original project","chat"]', request_id: "save & 1" };

describe("exact native saved content", () => {
    const result = { identity, cut: "saved & cut", content: "accepted merged text", content_hash: "hash",
        merged: true, observer: "reader", restrictions: { reader: ["private"], writer: [] } };
    it("reads exact retained coordinates and preserves the accepted bytes and restrictions", async () => {
        const json = vi.fn().mockResolvedValue(result);
        expect(await readNativeFileSavedContent({ base: "", json }, identity, result.cut)).toEqual(result);
        const [method, path] = json.mock.calls[0];
        expect(method).toBe("GET");
        const url = new URL(path, "https://example.invalid");
        expect(url.pathname).toBe("/file-actions/saved-content");
        expect(Object.fromEntries(url.searchParams)).toEqual({ ...identity, cut: result.cut });
        expect(json).toHaveBeenCalledTimes(1);
    });
    it("refuses another request or cut instead of falling back to the working copy", async () => {
        const json = vi.fn();
        for (const field of ["home", "issuer", "scope", "request_id"] as const) {
            json.mockResolvedValue({ ...result, identity: { ...identity, [field]: "different" } });
            await expect(readNativeFileSavedContent({ base: "", json }, identity, result.cut)).rejects.toThrow("another request");
        }
        json.mockResolvedValue({ ...result, cut: "newer-head" });
        await expect(readNativeFileSavedContent({ base: "", json }, identity, result.cut)).rejects.toThrow("unavailable");
        expect(json.mock.calls.every(([method, path]) => method === "GET" && path.startsWith("/file-actions/saved-content?"))).toBe(true);
    });
    it("keeps missing content unavailable and never requests an effect or a replacement cut", async () => {
        const json = vi.fn().mockRejectedValue(new Error("content erased"));
        await expect(readNativeFileSavedContent({ base: "", json }, identity, "")).rejects.toThrow("required");
        expect(json).not.toHaveBeenCalled();
        await expect(readNativeFileSavedContent({ base: "", json }, identity, result.cut)).rejects.toThrow("erased");
        expect(json).toHaveBeenCalledTimes(1);
    });
});
const response = (view: string, evidence: unknown) => ({ identity, view, observer: "reader", restrictions: { reader: ["private"] }, evidence });

describe("native file request transport", () => {
    it("preserves the caller's key and original Home before submission", async () => {
        const json = vi.fn().mockResolvedValue(identity);
        const transport = { base: "", json } as WorkbenchTransport;
        const prepared = await prepareNativeFileSaveRequest(transport, identity.home, "chat / one", "note & one.txt", identity.request_id);
        expect(prepared).toEqual(identity);
        expect(Object.isFrozen(prepared)).toBe(true);
        expect(json.mock.calls).toEqual([["GET", "/chats/chat%20%2F%20one/file-actions/request?path=note+%26+one.txt&request_id=save+%26+1"]]);
        await expect(prepareNativeFileSaveRequest(transport, "other-home", "chat", "note.txt", identity.request_id)).rejects.toThrow("selected Home");
        await expect(prepareNativeFileSaveRequest(transport, identity.home, "chat", "note.txt", "new-key")).rejects.toThrow("selected Home");
    });

    it("reuses persisted coordinates and keeps execution gaps separate from Saved facts", async () => {
        const persisted = parseNativeFileRequestIdentity(JSON.parse(JSON.stringify(identity)));
        const json = vi.fn().mockResolvedValueOnce(response("execution", { command: { request_id: identity.request_id }, runtime: null }))
            .mockResolvedValueOnce(response("saved", []));
        const transport = { base: "original-home", json } as WorkbenchTransport;
        expect((await observeNativeFileRequest(transport, persisted, "execution")).evidence).toEqual({ command: { request_id: identity.request_id }, runtime: null });
        expect((await observeNativeFileRequest(transport, persisted, "saved")).evidence).toEqual([]);
        for (const call of json.mock.calls) {
            expect(call[0]).toBe("GET");
            const query = new URL(String(call[1]), "https://example.invalid").searchParams;
            expect(Object.fromEntries(query)).toEqual(identity);
        }
        expect(json).toHaveBeenCalledTimes(2);
    });

    it("refuses substituted identity or view and never turns an unavailable read into success", async () => {
        for (const field of ["home", "issuer", "scope", "request_id"] as const) {
            const json = vi.fn().mockResolvedValue({ ...response("command", {}), identity: { ...identity, [field]: "substituted" } });
            await expect(observeNativeFileRequest({ base: "", json }, identity, "command")).rejects.toThrow("another request");
            expect(json).toHaveBeenCalledTimes(1);
        }
        for (const value of [null, {}, response("saved", []), response("command", null)]) {
            const json = vi.fn().mockResolvedValue(value);
            await expect(observeNativeFileRequest({ base: "", json }, identity, "command")).rejects.toThrow("unavailable");
        }
        const json = vi.fn().mockRejectedValue(new Error("read refused"));
        await expect(observeNativeFileRequest({ base: "", json }, identity, "saved")).rejects.toThrow("read refused");
        expect(json).toHaveBeenCalledTimes(1);
    });

    it("refuses incomplete or extended identity records without normalizing them", () => {
        for (const value of [null, {}, { ...identity, scope: "" }, { ...identity, home: 42 }, { ...identity, current_project: "new" }]) {
            expect(() => parseNativeFileRequestIdentity(value)).toThrow("unavailable");
        }
        expect(parseNativeFileRequestIdentity({ ...identity, scope: ` ${identity.scope}` }).scope).toBe(` ${identity.scope}`);
    });
});

describe("native file save submission", () => {
    const intent = { expected_actor: "alice", chat: "chat / one", path: "note.txt", base_cut: "original-cut",
        content: "private draft", dispatch_request_id: "dispatch-original" };
    const receipt = { identity, actor: "alice", admission: "admitted", replayed: false,
        dispatch_request_id: intent.dispatch_request_id,
        dispatch: { state: "authorized", grant_ref: "grant-one", replayed: false } };

    it("requires an expected actor and refuses a receipt from another actor", async () => {
        const json = vi.fn().mockResolvedValue({ ...receipt, actor: "bob" });
        await expect(submitNativeFileSave({ base: "", json }, identity,
            { ...intent, expected_actor: "" })).rejects.toThrow("required");
        expect(json).not.toHaveBeenCalled();
        await expect(submitNativeFileSave({ base: "", json }, identity, intent)).rejects.toThrow("unavailable");
        expect(json).toHaveBeenCalledTimes(1);
    });

    it("sends the retained request keys and exact intent once without claiming Saved", async () => {
        const json = vi.fn().mockResolvedValue(receipt);
        const result = await submitNativeFileSave({ base: "", json }, JSON.parse(JSON.stringify(identity)), intent);
        expect(json.mock.calls).toEqual([["POST", "/chats/chat%20%2F%20one/file-actions/save",
            { identity, expected_actor: "alice", path: intent.path, base_cut: intent.base_cut, content: intent.content,
                dispatch_request_id: intent.dispatch_request_id }, { idempotencyKey: identity.request_id }]]);
        expect(result).toEqual(receipt);
        expect(result).not.toHaveProperty("saved");
        expect(Object.isFrozen(result)).toBe(true);
    });

    it("preserves admission when dispatch is unavailable and never resubmits a lost response", async () => {
        const json = vi.fn().mockResolvedValue({ ...receipt, dispatch: { state: "unavailable" } });
        expect((await submitNativeFileSave({ base: "", json }, identity, intent)).dispatch).toEqual({ state: "unavailable" });
        expect(json).toHaveBeenCalledTimes(1);
        json.mockReset().mockRejectedValue(new Error("connection lost"));
        await expect(submitNativeFileSave({ base: "", json }, identity, intent)).rejects.toThrow("connection lost");
        expect(json).toHaveBeenCalledTimes(1);
    });

    it("rejects substituted identities and unsupported outcomes without inventing keys", async () => {
        for (const field of ["home", "issuer", "scope", "request_id"] as const) {
            const json = vi.fn().mockResolvedValue({ ...receipt, identity: { ...identity, [field]: "other" } });
            await expect(submitNativeFileSave({ base: "", json }, identity, intent)).rejects.toThrow("another request");
        }
        for (const value of [{ ...receipt, dispatch_request_id: "new-grant" },
            { ...receipt, admission: "saved" }, { ...receipt, dispatch: { state: "authorized" } },
            { ...receipt, dispatch: { state: "saved" } }]) {
            const json = vi.fn().mockResolvedValue(value);
            await expect(submitNativeFileSave({ base: "", json }, identity, intent)).rejects.toThrow("unavailable");
            expect(json).toHaveBeenCalledTimes(1);
        }
        const json = vi.fn();
        await expect(submitNativeFileSave({ base: "", json }, identity, { ...intent, dispatch_request_id: "" })).rejects.toThrow("required");
        expect(json).not.toHaveBeenCalled();
    });
});
