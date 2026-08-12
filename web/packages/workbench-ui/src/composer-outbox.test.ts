import { createRoot, createSignal } from "solid-js";
import { describe, expect, it, vi, type Mock } from "vitest";
import { Rejected } from "@gaugewright/control-plane-client";
import type { ImageRef } from "./attachments";
import {
    createMemoryOutboxStore,
    newOutboxId,
    type OutboxRow,
    type OutboxStore,
} from "./composer-outbox";
import {
    UNIVERSAL_COMPOSER_CAPABILITIES,
    createSessionComposerController,
} from "./session-composer-controller";

// A dispatch now waits for its row to be durable, so the chain from `submit()`
// to a settled send runs a few links longer than it used to.
const flush = async () => {
    for (let i = 0; i < 12; i++) await Promise.resolve();
};

/** A store that outlives the controller, which is the only way to observe that
 *  a message is durable rather than merely remembered. */
function sharedStore(seed: readonly OutboxRow[] = []): OutboxStore & { rows: () => OutboxRow[] } {
    const inner = createMemoryOutboxStore();
    for (const row of seed) void inner.put(row);
    const all: OutboxRow[] = [...seed];
    return {
        load: inner.load,
        put: async (row) => {
            await inner.put(row);
            const at = all.findIndex((existing) => existing.id === row.id);
            if (at >= 0) all[at] = row;
            else all.push(row);
        },
        remove: async (id) => {
            await inner.remove(id);
            const at = all.findIndex((existing) => existing.id === id);
            if (at >= 0) all.splice(at, 1);
        },
        rows: () => all,
    };
}

/** The controller's send, spelled out so a mock standing in for it is checked
 *  against the real signature rather than against `any`. */
type ComposerSend = (
    text: string,
    images: readonly ImageRef[],
    composedId: string,
) => Promise<void>;

function harness(options: {
    store?: OutboxStore;
    send?: Mock<ComposerSend>;
    scope?: string;
    appliesComposedIdOnce?: boolean;
} = {}) {
    const send: Mock<ComposerSend> = options.send ?? vi.fn(async () => undefined);
    const [scope, setScope] = createSignal(options.scope ?? "chat-1");
    const [busy, setBusy] = createSignal(false);
    const [canCommand, setCanCommand] = createSignal(true);
    let dispose!: () => void;
    const controller = createRoot((rootDispose) => {
        dispose = rootDispose;
        return createSessionComposerController({
            scope,
            busy,
            canCommand,
            capabilities: () => UNIVERSAL_COMPOSER_CAPABILITIES,
            send,
            stop: vi.fn(async () => undefined),
            outbox: options.store,
            appliesComposedIdOnce: () => options.appliesComposedIdOnce === true,
        });
    });
    return { controller, send, setBusy, setScope, setCanCommand, dispose };
}

describe("the composer outbox", () => {
    it("keeps a stashed message across a controller's whole life", async () => {
        const store = sharedStore();
        const first = harness({ store });
        await flush();
        first.controller.setDraft("check the invoice wording");
        first.controller.stash();
        await flush();
        expect(store.rows().map((row) => [row.text, row.held])).toEqual([
            ["check the invoice wording", true],
        ]);
        first.dispose();

        // A new controller over the same store is what a reload looks like.
        const second = harness({ store });
        await flush();
        expect(second.controller.queue().map(({ text, held }) => [text, held])).toEqual([
            ["check the invoice wording", true],
        ]);
        expect(second.send).not.toHaveBeenCalled();
        second.dispose();
    });

    it("reloads per chat, and does not leak one chat's messages into another", async () => {
        const store = sharedStore();
        const h = harness({ store });
        await flush();
        h.controller.setDraft("for chat one");
        h.controller.stash();
        await flush();

        h.setScope("chat-2");
        await flush();
        expect(h.controller.queue()).toHaveLength(0);

        // Leaving does not delete: coming back finds it exactly as it was, which
        // is the promise the queue caption makes.
        h.setScope("chat-1");
        await flush();
        expect(h.controller.queue().map(({ text }) => text)).toEqual(["for chat one"]);
        h.dispose();
    });

    it("takes a message while the transport is down and sends it on recovery", async () => {
        const store = sharedStore();
        const h = harness({ store });
        await flush();
        h.setCanCommand(false);

        h.controller.setDraft("written on the train");
        h.controller.submit();
        await flush();
        expect(h.send).not.toHaveBeenCalled();
        expect(store.rows().map((row) => row.text)).toEqual(["written on the train"]);

        h.setCanCommand(true);
        await flush();
        expect(h.send).toHaveBeenCalledWith("written on the train", [], expect.any(String));
        // Cleared on acknowledgement — the store is for what has *not* been sent.
        expect(store.rows()).toHaveLength(0);
        h.dispose();
    });

    it("sets a failed message aside instead of losing it or retrying forever", async () => {
        const send = vi.fn(async () => {
            throw new Error("provider unavailable");
        });
        const store = sharedStore();
        const h = harness({ store, send });
        await flush();
        h.controller.setDraft("this one will fail");
        h.controller.submit();
        await flush();

        expect(h.controller.error()).toBe("provider unavailable");
        // Kept, so the work is recoverable...
        expect(h.controller.queue().map(({ text, held }) => [text, held])).toEqual([
            ["this one will fail", true],
        ]);
        // ...and held, so the drain does not offer the same failing row forever.
        expect(send).toHaveBeenCalledTimes(1);
        h.dispose();
    });

    it("drops a message from the queue the moment it is dispatched", async () => {
        let settle!: () => void;
        const send = vi.fn(() => new Promise<void>((resolve) => { settle = resolve; }));
        const store = sharedStore();
        const h = harness({ store, send });
        await flush();
        h.controller.setDraft("running now");
        h.controller.submit();
        await flush();

        // A message that is running is the turn, not something waiting behind it.
        expect(h.controller.queue()).toHaveLength(0);
        // But it is still in the store until the host has acknowledged it.
        expect(store.rows().map((row) => row.text)).toEqual(["running now"]);

        settle();
        await flush();
        expect(store.rows()).toHaveLength(0);
        h.dispose();
    });

    it("survives a store that cannot write, and says so", async () => {
        const store: OutboxStore = {
            load: async () => [],
            put: async () => {
                throw new Error("quota exceeded");
            },
            remove: async () => undefined,
        };
        const h = harness({ store });
        await flush();
        h.controller.setDraft("still has to work");
        h.controller.stash();
        await flush();

        // The row is live in the session even though it is not durable, and the
        // composer says which of the two it got.
        expect(h.controller.queue().map(({ text }) => text)).toEqual(["still has to work"]);
        expect(h.controller.error()).toMatch(/could not be saved/i);
        h.dispose();
    });

    /** A row left marked `dispatched` is one the client handed to the transport
     *  and never heard back about — the host may have run it. What to do with it
     *  depends entirely on whether the host can be asked. */
    const inFlight = (): OutboxRow => ({
        id: "in-flight",
        scope: "chat-1",
        text: "did this go?",
        images: [],
        held: false,
        seq: 1,
        at: Date.now(),
        dispatched: true,
    });

    it("sets aside a message of unknown fate when the host cannot be asked", async () => {
        const store = sharedStore([inFlight()]);
        const h = harness({ store });
        await flush();

        // Against a host with no apply-once guarantee, resending is the one
        // outcome that can run a turn twice. So it does not happen; the message is
        // visible and held, for a person to judge.
        expect(h.send).not.toHaveBeenCalled();
        expect(h.controller.queue().map(({ text, held }) => [text, held])).toEqual([
            ["did this go?", true],
        ]);
        expect(store.rows()[0]?.dispatched).toBe(false);
        h.dispose();
    });

    it("resends a message of unknown fate when the host applies its id once", async () => {
        // ADR 0137 §3: with the composed id carried through to a receipt, the
        // recovery is to *ask*. Resending is safe because the host answers rather
        // than re-runs, so the message recovers itself instead of waiting.
        const store = sharedStore([inFlight()]);
        const h = harness({ store, appliesComposedIdOnce: true });
        await flush();

        expect(h.send).toHaveBeenCalledWith("did this go?", [], "in-flight");
        expect(h.controller.queue()).toHaveLength(0);
        expect(store.rows()).toHaveLength(0);
        h.dispose();
    });

    it("sends under the id the message was composed with, so a resend is the same command", async () => {
        // Held in flight, because a settled send drops the row and there would be
        // nothing left to compare the id against.
        let settle!: () => void;
        const send: Mock<ComposerSend> = vi.fn(
            () => new Promise<void>((resolve) => { settle = resolve; }),
        );
        const store = sharedStore();
        const h = harness({ store, send });
        await flush();
        h.controller.setDraft("book the room");
        h.controller.submit();
        await flush();

        const stored = store.rows()[0];
        expect(stored?.dispatched).toBe(true);
        // The id is the row's own, not one minted for this attempt. That is the
        // whole point: two attempts at one message are one command.
        expect(send.mock.calls[0]?.[2]).toBe(stored?.id);
        settle();
        h.dispose();
    });

    it("treats an already-applied refusal as the answer it went to get, not a failure", async () => {
        // The host refusing because it already ran this composed id is the resend
        // succeeding. Setting the row aside and reporting an error would teach the
        // reader to distrust a mechanism that just worked.
        const send = vi.fn(async () => {
            throw new Rejected("command already applied; refresh its projection", "applied");
        });
        const store = sharedStore([inFlight()]);
        const h = harness({ store, send, appliesComposedIdOnce: true });
        await flush();

        expect(h.send).toHaveBeenCalledTimes(1);
        expect(h.controller.queue()).toHaveLength(0);
        expect(store.rows()).toHaveLength(0);
        expect(h.controller.error()).toBe("");
        h.dispose();
    });

    it("still sets aside a refusal whose outcome is genuinely open", async () => {
        // `processing` is the honest residue: the host claimed the command and
        // never settled it, so nobody knows whether the turn ran. That is exactly
        // the case a person has to judge.
        const send = vi.fn(async () => {
            throw new Rejected("command already processing; refresh its projection", "processing");
        });
        const store = sharedStore([inFlight()]);
        const h = harness({ store, send, appliesComposedIdOnce: true });
        await flush();

        expect(h.controller.queue().map(({ text, held }) => [text, held])).toEqual([
            ["did this go?", true],
        ]);
        expect(h.controller.error()).toMatch(/processing/i);
        h.dispose();
    });

    it("reorders the row you dragged, not the one at that index in the store", async () => {
        // The queue hides rows that are in flight, so a displayed index is not an
        // index into the stored rows. Resolving by id is what keeps a drag from
        // moving the running message instead of the one under the pointer.
        let settle!: () => void;
        const send = vi.fn(() => new Promise<void>((resolve) => { settle = resolve; }));
        const store = sharedStore();
        const h = harness({ store, send });
        await flush();

        h.controller.setDraft("running");
        h.controller.submit();
        await flush();
        h.setBusy(true);
        h.controller.setDraft("two");
        h.controller.submit();
        h.controller.setDraft("three");
        h.controller.submit();
        await flush();
        expect(h.controller.queue().map(({ text }) => text)).toEqual(["two", "three"]);

        // Drag "three" above "two" — displayed indices 1 → 0.
        h.controller.reorderQueue(1, 0);
        await flush();
        expect(h.controller.queue().map(({ text }) => text)).toEqual(["three", "two"]);
        // The in-flight message was never a candidate and is untouched.
        expect(store.rows().some((row) => row.text === "running")).toBe(true);

        settle();
        h.dispose();
    });

    it("makes a message durable before it hands it to the transport", async () => {
        // The draft is cleared the moment the row is composed, so a row given to
        // `send` before its write lands is recoverable from nowhere if the tab
        // dies mid-request: the loss the outbox exists to prevent.
        let land!: () => void;
        const written = new Promise<void>((resolve) => { land = resolve; });
        const inner = sharedStore();
        const store: OutboxStore = {
            ...inner,
            put: async (row) => {
                await written;
                await inner.put(row);
            },
        };
        const h = harness({ store });
        await flush();
        h.controller.setDraft("must survive the crash");
        h.controller.submit();
        await flush();
        expect(h.send).not.toHaveBeenCalled();

        land();
        await flush();
        expect(h.send).toHaveBeenCalledWith("must survive the crash", [], expect.any(String));
        h.dispose();
    });

    it("refuses to send a message it could not store, and holds it instead", async () => {
        const store: OutboxStore = {
            load: async () => [],
            put: async () => {
                throw new Error("quota exceeded");
            },
            remove: async () => undefined,
        };
        const h = harness({ store });
        await flush();
        h.controller.setDraft("nothing would be left of this");
        h.controller.submit();
        await flush();

        // Sending it would put a message in flight that nothing could recover.
        expect(h.send).not.toHaveBeenCalled();
        expect(h.controller.queue().map(({ text, held }) => [text, held])).toEqual([
            ["nothing would be left of this", true],
        ]);
        expect(h.controller.error()).toMatch(/not sent/i);
        h.dispose();
    });

    it("waits for a chat's stored messages before sending one composed just now", async () => {
        // Hydration is asynchronous. Sending the new row while the older ones are
        // still loading would reverse the creation order the outbox promises
        // (ADR 0137 §4).
        let arrive!: () => void;
        const loading = new Promise<void>((resolve) => { arrive = resolve; });
        const older: OutboxRow = {
            id: "older",
            scope: "chat-1",
            text: "written yesterday",
            images: [],
            held: false,
            seq: 1,
            at: Date.now(),
        };
        const inner = sharedStore([older]);
        const store: OutboxStore = {
            ...inner,
            load: async (scope) => {
                await loading;
                return inner.load(scope);
            },
        };
        const sent: string[] = [];
        const send: Mock<ComposerSend> = vi.fn(async (text) => {
            sent.push(text);
        });
        const h = harness({ store, send });
        await flush();

        h.controller.setDraft("written just now");
        h.controller.submit();
        await flush();
        expect(send).not.toHaveBeenCalled();

        arrive();
        await flush();
        await flush();
        expect(sent).toEqual(["written yesterday", "written just now"]);
        h.dispose();
    });

    it("mints ids that do not collide", () => {
        const ids = new Set(Array.from({ length: 500 }, () => newOutboxId()));
        expect(ids.size).toBe(500);
    });
});
