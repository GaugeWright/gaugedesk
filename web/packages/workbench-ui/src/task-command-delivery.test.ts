import { createRoot, createSignal } from "solid-js";
import { describe, expect, it, vi } from "vitest";
import { Rejected, TurnStopped } from "@gaugewright/control-plane-client";
import { createMemoryOutboxStore } from "./composer-outbox";
import { attachTaskCommandAttempt, createTaskCommandLedger, createSessionComposerController,
    BASIC_COMPOSER_CAPABILITIES, UNIVERSAL_COMPOSER_CAPABILITIES, sameTaskAddress, taskCommandAddress, type TaskCommandScope, type SessionComposerControllerOptions, type TaskCommandAttempt } from "./session-composer-controller";
const flush = async () => { for (let n = 0; n < 40; n++) await Promise.resolve(); };
const addressed = { home: {}, chat: "chat-one", authority: { home_id: "home-one", actor_id: "alice" } };
function harness(mode: "unknown" | "accepted" | "refused" | "error" | "undefined" | "primitive" = "unknown",
    store = createMemoryOutboxStore(), recovery?: SessionComposerControllerOptions["recoverTask"], current = addressed as TaskCommandScope,
    capabilities = UNIVERSAL_COMPOSER_CAPABILITIES) {
    const [busy, setBusy] = createSignal(false);
    let attempt!: TaskCommandAttempt;
    let ledger!: ReturnType<typeof createTaskCommandLedger>;
    let dispose!: () => void;
    const effects = vi.fn();
    const send = vi.fn(async (text: string, _images: unknown, id: string,
        bindTask?: (attempt: TaskCommandAttempt) => Promise<void>) => {
        attempt = ledger.begin(addressed, id, text, 0);
        if (bindTask) await bindTask(attempt);
        effects();
        if (mode === "accepted" || mode === "refused") ledger.observe(addressed, { correlation: {
            client_request_id: id, chat_id: addressed.chat, ...addressed.authority, outcome: mode,
        } });
        if (mode === "error") throw attachTaskCommandAttempt(Object.freeze(new Error("transport dropped")), attempt);
        if (mode === "primitive") throw attachTaskCommandAttempt("transport dropped", attempt);
        if (mode === "undefined") return undefined;
        return attempt;
    });
    const controller = createRoot((cleanup) => {
        dispose = cleanup;
        ledger = createTaskCommandLedger();
        return createSessionComposerController({ scope: () => "chat-one", busy,
            capabilities: () => capabilities, send, outbox: store,
            taskCommands: ledger, taskScope: () => current, recoverTask: recovery, appliesComposedIdOnce: () => true });
    });
    return { controller, ledger: () => ledger, send, effects, store, setBusy, dispose, attempt: () => attempt };
}
describe("correlated durable task delivery", () => {
    it.each(["unknown", "undefined", "error", "primitive"] as const)("holds %s with the same dispatched identity across busy-free and reload", async (mode) => {
        const h = harness(mode);
        await flush(); h.controller.setDraft("hello"); h.controller.submit(); await flush();
        const retained = await h.store.load("chat-one");
        expect(retained).toMatchObject([{ id: h.attempt().id, text: "hello", held: true, dispatched: true }]);
        h.setBusy(true); h.setBusy(false); await flush();
        expect(h.send).toHaveBeenCalledTimes(1);
        h.dispose();
        const reloaded = harness("unknown", h.store);
        await flush(); reloaded.setBusy(true); reloaded.setBusy(false); await flush();
        expect(reloaded.send).not.toHaveBeenCalled();
        expect(await h.store.load("chat-one")).toEqual(retained);
        reloaded.dispose();
    });
    it("retains synchronous target acceptance until delivery registration and removes the row once", async () => {
        const h = harness("accepted"); await flush();
        h.controller.setDraft("hello"); h.controller.submit(); await flush();
        expect(h.attempt().outcome()).toBe("accepted");
        expect(await h.store.load("chat-one")).toEqual([]);
        expect(h.send).toHaveBeenCalledTimes(1); h.dispose();
    });
    it("retains explicit refusal for user-controlled same-ID retry", async () => {
        const h = harness("refused"); await flush();
        h.controller.setDraft("hello"); h.controller.submit(); await flush();
        expect(await h.store.load("chat-one")).toMatchObject([{ id: h.attempt().id, held: true, dispatched: false }]);
        h.setBusy(true); h.setBusy(false); await flush();
        expect(h.send).toHaveBeenCalledTimes(1); h.dispose();
    });
    it("retires held uncertainty only from a later exact author observation", async () => {
        const h = harness(); await flush(); h.controller.setDraft("hello"); h.controller.submit(); await flush();
        const event = { type: "taskcorrelation", client_request_id: h.attempt().id, chat_id: addressed.chat,
            ...addressed.authority, outcome: "settled" };
        h.ledger().observe(addressed, { ...event, actor_id: "bob" });
        h.ledger().observe(addressed, { status: 200 });
        expect((await h.store.load("chat-one"))).toHaveLength(1);
        h.ledger().observe(addressed, event); await flush();
        expect(await h.store.load("chat-one")).toEqual([]);
        h.ledger().observe(addressed, event); await flush();
        expect(await h.store.load("chat-one")).toEqual([]); h.dispose();
    });
    it("disposal leaves held persistence even when the old attempt later receives acceptance", async () => {
        const h = harness(); await flush(); h.controller.setDraft("hello"); h.controller.submit(); await flush();
        const retained = await h.store.load("chat-one"); h.dispose();
        h.ledger().observe(addressed, { type: "user", text: "hello", client_request_id: h.attempt().id,
            chat_id: addressed.chat, ...addressed.authority }); await flush();
        expect(await h.store.load("chat-one")).toEqual(retained);
    });
});

// Identity doors here are controlled callbacks; runtime authority is qualified
// separately. These execute the real controller/store handshake and load path.
describe("original-address task recovery", () => {
    it("refuses actual submission if saving the original address fails", async () => {
        const backing = createMemoryOutboxStore();
        const store = { ...backing, put: async (row: Parameters<typeof backing.put>[0]) => {
            if (row.task_address) throw new Error("disk refused original address");
            await backing.put(row);
        } };
        const h = harness("unknown", store); await flush();
        h.controller.setDraft("hello"); h.controller.submit(); await flush();
        expect(h.effects).not.toHaveBeenCalled();
        expect(await store.load("chat-one")).toMatchObject([{ held: true, dispatched: true, task_correlated: true }]);
        h.dispose();
    });
    it("records the verified original address before the submission boundary", async () => {
        const h = harness(); await flush(); h.controller.setDraft("hello"); h.controller.submit(); await flush();
        const rows = await h.store.load("chat-one");
        expect(rows).toMatchObject([{ id: h.attempt().id, task_correlated: true,
            task_address: { home_id: "home-one", actor_id: "alice", project_id: null, chat_id: "chat-one" } }]);
        expect(h.effects).toHaveBeenCalledTimes(1); h.dispose();
    });
    it("rebuilds confirmation from exact-author durable snapshot without resending", async () => {
        const h = harness(); await flush(); h.controller.setDraft("hello"); h.controller.submit(); await flush();
        const id = h.attempt().id; h.dispose();
        const read = vi.fn(async () => [{ type: "user", text: "hello", client_request_id: id,
            chat_id: addressed.chat, ...addressed.authority }]);
        const restored = harness("unknown", h.store, async (address) => {
            if (!sameTaskAddress(address, taskCommandAddress(addressed))) return undefined;
            return { scope: addressed, events: await read() };
        }); await flush();
        expect(read).toHaveBeenCalledTimes(1);
        expect(restored.effects).not.toHaveBeenCalled();
        expect(await h.store.load("chat-one")).toEqual([]); restored.dispose();
    });
    it.each(["home", "actor", "project"] as const)("never adopts the same-chat row under a changed %s", async (changed) => {
        const h = harness(); await flush(); h.controller.setDraft("hello"); h.controller.submit(); await flush();
        const retained = await h.store.load("chat-one"); h.dispose();
        const current = { ...addressed, project: changed === "project" ? "other-project" : null,
            authority: { home_id: changed === "home" ? "other-home" : "home-one",
                actor_id: changed === "actor" ? "bob" : "alice" } };
        const read = vi.fn(async () => []);
        const restored = harness("unknown", h.store, async (address) => {
            if (!sameTaskAddress(address, taskCommandAddress(current))) return undefined;
            return { scope: current, events: await read() };
        }, current); await flush(); restored.setBusy(true); restored.setBusy(false); await flush();
        expect(read).not.toHaveBeenCalled();
        expect(restored.effects).not.toHaveBeenCalled();
        expect(restored.controller.queue()).toEqual([]);
        expect(await h.store.load("chat-one")).toEqual(retained); restored.dispose();
    });
    it("holds legacy dispatched rows without inventing an original address or retry", async () => {
        const store = createMemoryOutboxStore();
        await store.put({ id: "old", scope: "chat-one", text: "legacy", images: [], held: false,
            dispatched: true, seq: 1, at: Date.now() });
        const recover = vi.fn(async () => undefined);
        const restored = harness("unknown", store, recover); await flush();
        expect(recover).not.toHaveBeenCalled();
        expect(restored.effects).not.toHaveBeenCalled();
        expect(await store.load("chat-one")).toMatchObject([{ id: "old", held: true, dispatched: true }]);
        expect((await store.load("chat-one"))[0]?.task_address).toBeUndefined(); restored.dispose();
    });
});

describe("pre-effect durability ordering", () => {
    it("waits for the original-address commit before invoking the task transport", async () => {
        const backing = createMemoryOutboxStore();
        let release!: () => void;
        const blocked = new Promise<void>((resolve) => { release = resolve; });
        const store = { ...backing, put: async (row: Parameters<typeof backing.put>[0]) => {
            if (row.task_address) await blocked;
            await backing.put(row);
        } };
        const h = harness("unknown", store); await flush();
        h.controller.setDraft("hello"); h.controller.submit(); await flush();
        expect(h.effects).not.toHaveBeenCalled();
        expect((await store.load("chat-one"))[0]?.task_address).toBeUndefined();
        release(); await flush();
        expect(h.effects).toHaveBeenCalledTimes(1);
        expect(await store.load("chat-one")).toMatchObject([{ task_address: {
            home_id: "home-one", actor_id: "alice", project_id: null, chat_id: "chat-one",
        } }]); h.dispose();
    });
});

describe("recovery lifetime", () => {
    it("does not retire retained intent from an asynchronous read after disposal", async () => {
        const h = harness(); await flush(); h.controller.setDraft("hello"); h.controller.submit(); await flush();
        const retained = await h.store.load("chat-one"); const id = h.attempt().id; h.dispose();
        let complete!: (value: { scope: typeof addressed; events: unknown[] }) => void;
        const recovery = new Promise<{ scope: typeof addressed; events: unknown[] }>((resolve) => { complete = resolve; });
        const restored = harness("unknown", h.store, async () => recovery); await flush(); restored.dispose();
        complete({ scope: addressed, events: [{ type: "user", text: "hello", client_request_id: id,
            chat_id: addressed.chat, ...addressed.authority }] }); await flush();
        expect(await h.store.load("chat-one")).toEqual(retained);
        expect(restored.effects).not.toHaveBeenCalled();
    });
});

// A surface that shows no queue (the phone) cannot show a held row, so the two
// outcomes a held row stands for must be recoverable some other way there.
describe("task delivery where no queue is shown", () => {
    const noQueue = BASIC_COMPOSER_CAPABILITIES;
    it("returns an exactly refused message to the box rather than hiding it", async () => {
        const h = harness("refused", undefined, undefined, undefined, noQueue); await flush();
        h.controller.setDraft("hello"); h.controller.submit(); await flush();
        expect(h.controller.draft()).toBe("hello");
        expect(await h.store.load("chat-one")).toEqual([]);
        expect(h.controller.error()).toMatch(/did not accept/);
        expect(h.send).toHaveBeenCalledTimes(1); h.dispose();
    });
    it("returns a refused row saved earlier to the box when the chat is opened again", async () => {
        const store = createMemoryOutboxStore();
        await store.put({ id: "refused", scope: "chat-one", text: "typed with thumbs", images: [], held: true,
            dispatched: false, task_correlated: true, seq: 1, at: Date.now() });
        const h = harness("unknown", store, undefined, undefined, noQueue); await flush();
        expect(h.controller.draft()).toBe("typed with thumbs");
        expect(await store.load("chat-one")).toEqual([]);
        expect(h.send).not.toHaveBeenCalled(); h.dispose();
    });
    it("keeps an unconfirmed message held, says so, and never resends it", async () => {
        const h = harness("unknown", undefined, undefined, undefined, noQueue); await flush();
        h.controller.setDraft("hello"); h.controller.submit(); await flush();
        expect(await h.store.load("chat-one")).toMatchObject([{ id: h.attempt().id, held: true, dispatched: true }]);
        expect(h.controller.draft()).toBe("");
        expect(h.controller.error()).toMatch(/could not be confirmed/);
        h.setBusy(true); h.setBusy(false); await flush();
        expect(h.send).toHaveBeenCalledTimes(1);
        h.ledger().observe(addressed, { type: "taskcorrelation", client_request_id: h.attempt().id,
            chat_id: addressed.chat, ...addressed.authority, outcome: "settled" }); await flush();
        expect(await h.store.load("chat-one")).toEqual([]);
        expect(h.controller.error()).toBe(""); h.dispose();
    });
    it("announces an unconfirmed row found on reload without resending it", async () => {
        const store = createMemoryOutboxStore();
        await store.put({ id: "old", scope: "chat-one", text: "legacy", images: [], held: false,
            dispatched: true, seq: 1, at: Date.now() });
        const h = harness("unknown", store, undefined, undefined, noQueue); await flush();
        expect(h.controller.error()).toMatch(/could not be confirmed/);
        expect(h.controller.draft()).toBe("");
        expect(h.send).not.toHaveBeenCalled(); h.dispose();
    });
});

// Signed-out local work: the Home admits the request as its local account and
// names no verified requester, so no observation will ever confirm the command.
// Waiting for one held every message that had run, and kept its echo beside the
// admitted line, for good (WS-871).
describe("task delivery nothing can confirm (WS-871)", () => {
    const unbound: TaskCommandScope = { home: {}, chat: "chat-one" };
    function signedOut(ending: "ran" | "stopped" | "failed" | "applied", store = createMemoryOutboxStore()) {
        const [busy, setBusy] = createSignal(false);
        let ledger!: ReturnType<typeof createTaskCommandLedger>;
        let dispose!: () => void;
        const send = vi.fn(async (text: string, _images: unknown, id: string,
            bindTask?: (attempt: TaskCommandAttempt) => Promise<void>) => {
            const attempt = ledger.begin(unbound, id, text, 0);
            if (bindTask) await bindTask(attempt);
            if (ending === "stopped") throw attachTaskCommandAttempt(new TurnStopped(), attempt);
            if (ending === "failed") throw attachTaskCommandAttempt(new Error("the model refused"), attempt);
            if (ending === "applied") throw attachTaskCommandAttempt(new Rejected("already applied", "applied"), attempt);
            return attempt;
        });
        const controller = createRoot((cleanup) => {
            dispose = cleanup;
            ledger = createTaskCommandLedger();
            return createSessionComposerController({ scope: () => "chat-one", busy,
                capabilities: () => UNIVERSAL_COMPOSER_CAPABILITIES, send, outbox: store,
                taskCommands: ledger, taskScope: () => unbound, appliesComposedIdOnce: () => true });
        });
        return { controller, send, store, setBusy, dispose, ledger: () => ledger };
    }
    it("marks an attempt in a scope with no verified requester as one nothing can confirm", () => createRoot((dispose) => {
        const ledger = createTaskCommandLedger();
        expect(ledger.begin(unbound, "signed-out", "hello", 0).confirmable).toBe(false);
        expect(ledger.begin(addressed, "addressed", "hello", 0).confirmable).toBe(true);
        expect(ledger.begin({ home: {}, chat: "chat-one", publicSession: true }, "visitor", "hello", 0).confirmable).toBe(true);
        dispose();
    }));
    it("retires a message whose turn ran, binding no address to it", async () => {
        const h = signedOut("ran"); await flush();
        h.controller.setDraft("hello"); h.controller.submit(); await flush();
        expect(await h.store.load("chat-one")).toEqual([]);
        expect(h.controller.queue()).toEqual([]);
        expect(h.controller.error()).toBe("");
        h.setBusy(true); h.setBusy(false); await flush();
        expect(h.send).toHaveBeenCalledTimes(1); h.dispose();
    });
    it("lets the next queued message run once the one in front of it has", async () => {
        const h = signedOut("ran"); await flush();
        h.setBusy(true);
        h.controller.setDraft("first"); h.controller.submit();
        h.controller.setDraft("second"); h.controller.submit(); await flush();
        expect(h.controller.queue().map((item) => item.text)).toEqual(["first", "second"]);
        h.setBusy(false); await flush();
        expect(h.send.mock.calls.map((call) => call[0])).toEqual(["first", "second"]);
        expect(h.controller.queue()).toEqual([]);
        expect(await h.store.load("chat-one")).toEqual([]); h.dispose();
    });
    it.each(["stopped", "applied"] as const)("retires a message whose turn was %s, and reports nothing", async (ending) => {
        const h = signedOut(ending); await flush();
        h.controller.setDraft("hello"); h.controller.submit(); await flush();
        expect(await h.store.load("chat-one")).toEqual([]);
        expect(h.controller.error()).toBe(""); h.dispose();
    });
    it("sets a failed message aside for the reader to release", async () => {
        const h = signedOut("failed"); await flush();
        h.controller.setDraft("hello"); h.controller.submit(); await flush();
        expect(await h.store.load("chat-one")).toMatchObject([{ text: "hello", held: true, dispatched: false }]);
        expect(h.controller.error()).toMatch(/the model refused/);
        h.setBusy(true); h.setBusy(false); await flush();
        expect(h.send).toHaveBeenCalledTimes(1); h.dispose();
    });
    it("releases only an echo nothing can confirm", () => createRoot((dispose) => {
        const ledger = createTaskCommandLedger();
        ledger.begin(unbound, "signed-out", "one", 0);
        ledger.begin(addressed, "addressed", "two", 0);
        ledger.release(unbound, "signed-out");
        ledger.release(addressed, "addressed");
        expect(ledger.pending().map((command) => command.id)).toEqual(["addressed"]);
        dispose();
    }));
});
