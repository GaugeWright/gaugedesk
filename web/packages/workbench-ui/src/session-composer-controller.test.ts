import { createRoot, createSignal } from "solid-js";
import { describe, expect, it, vi } from "vitest";
import {
    UNIVERSAL_COMPOSER_CAPABILITIES,
    createSessionComposerController,
} from "./session-composer-controller";

// Long enough to settle the store writes the controller now waits on: a row is
// durable before it is dispatched, so every send is a few links further down the
// microtask chain than the call that asked for it.
const flush = async () => {
    for (let i = 0; i < 20; i++) await Promise.resolve();
};

function harness(send = vi.fn(async () => undefined)) {
    const [scope, setScope] = createSignal("chat-1");
    const [busy, setBusy] = createSignal(false);
    const [canCommand, setCanCommand] = createSignal(true);
    const stop = vi.fn(async () => undefined);
    let dispose!: () => void;
    const controller = createRoot((rootDispose) => {
        dispose = rootDispose;
        return createSessionComposerController({
            scope,
            busy,
            capabilities: () => UNIVERSAL_COMPOSER_CAPABILITIES,
            canCommand,
            send,
            stop,
        });
    });
    return { controller, send, stop, setBusy, setScope, setCanCommand, dispose };
}

describe("createSessionComposerController", () => {
    it("queues while an authoritative turn is busy and drains after settlement", async () => {
        const h = harness();
        // Stored rows arrive before anything is sent, so every test that expects
        // a dispatch waits for the chat to finish hydrating first.
        await flush();
        h.setBusy(true);
        h.controller.setDraft("follow up");
        h.controller.submit();
        expect(h.controller.queue()).toMatchObject([{ text: "follow up" }]);
        expect(h.send).not.toHaveBeenCalled();

        h.setBusy(false);
        await flush();
        expect(h.send).toHaveBeenCalledWith("follow up", [], expect.any(String));
        expect(h.controller.queue()).toHaveLength(0);
        h.dispose();
    });

    it("steers by stopping the active turn and running the steering message next", async () => {
        let finishFirst!: () => void;
        const send = vi.fn()
            .mockImplementationOnce(() => new Promise<void>((resolve) => { finishFirst = resolve; }))
            .mockResolvedValueOnce(undefined);
        const h = harness(send);
        await flush();

        h.controller.setDraft("original");
        h.controller.submit();
        await flush();
        h.controller.setDraft("redirect");
        h.controller.steer();
        expect(h.stop).toHaveBeenCalledTimes(1);
        expect(h.controller.queue()).toMatchObject([{ text: "redirect" }]);

        finishFirst();
        await flush();
        await flush();
        expect(send).toHaveBeenNthCalledWith(2, "redirect", [], expect.any(String));
        h.dispose();
    });

    it("uses runtime-owned follow-up and steering commands when the Session supplies them", async () => {
        const [busy] = createSignal(true);
        const [queue, setQueue] = createSignal<{ id: string; text: string }[]>([]);
        const followUp = vi.fn(async (text: string) => {
            setQueue([{ id: "follow-1", text }]);
        });
        const steer = vi.fn(async () => undefined);
        const stop = vi.fn(async () => undefined);
        let dispose!: () => void;
        const controller = createRoot((rootDispose) => {
            dispose = rootDispose;
            return createSessionComposerController({
                scope: () => "chat-1",
                busy,
                capabilities: () => UNIVERSAL_COMPOSER_CAPABILITIES,
                send: async () => undefined,
                stop,
                runtime: {
                    queue,
                    followUp,
                    steer,
                    edit: async () => undefined,
                    remove: async () => undefined,
                    reorder: async () => undefined,
                    promote: async () => undefined,
                },
            });
        });

        await flush();

        controller.setDraft("remember this");
        controller.submit();
        await flush();
        expect(followUp).toHaveBeenCalledWith("remember this", []);
        // The host's projection is text-only, so its rows cannot be withdrawn
        // into the outbox without losing whatever was attached to them.
        expect(controller.queue()).toEqual([
            { id: "follow-1", text: "remember this", held: false, canHold: false },
        ]);

        controller.setDraft("change direction");
        controller.steer();
        await flush();
        expect(steer).toHaveBeenCalledWith("change direction", []);
        expect(stop).not.toHaveBeenCalled();
        dispose();
    });

    it("stashes, edits, reorders, removes, and releases held messages", async () => {
        const h = harness();
        await flush();
        h.controller.setDraft("one");
        h.controller.stash();
        h.controller.setDraft("two");
        h.controller.stash();
        expect(h.controller.queue().map(({ text }) => text)).toEqual(["one", "two"]);
        // Nothing ran: a stash that dispatched would not be a stash.
        expect(h.send).not.toHaveBeenCalled();

        h.controller.reorderQueue(1, 0);
        const first = h.controller.queue()[0]!;
        h.controller.editQueued(first.id, "two edited");
        h.controller.removeQueued(h.controller.queue()[1]!.id);
        expect(h.controller.queue().map(({ text }) => text)).toEqual(["two edited"]);

        h.controller.holdQueued(h.controller.queue()[0]!.id, false);
        await flush();
        expect(h.send).toHaveBeenCalledWith("two edited", [], expect.any(String));
        h.dispose();
    });

    it("steps over held rows and runs the next ready one", async () => {
        const h = harness();
        await flush();
        h.setBusy(true);
        h.controller.setDraft("jotted");
        h.controller.stash();
        h.controller.setDraft("meant to run");
        h.controller.submit();
        expect(h.controller.queue().map(({ text, held }) => [text, held === true])).toEqual([
            ["jotted", true],
            ["meant to run", false],
        ]);

        h.setBusy(false);
        await flush();
        // The held row is stepped over, not blocking — and it is still there.
        expect(h.send).toHaveBeenCalledTimes(1);
        expect(h.send).toHaveBeenCalledWith("meant to run", [], expect.any(String));
        expect(h.controller.queue().map(({ text }) => text)).toEqual(["jotted"]);
        h.dispose();
    });

    it("refuses to stash or hold where the Environment does not declare it", () => {
        const [scope] = createSignal("chat-1");
        const [busy] = createSignal(false);
        let dispose!: () => void;
        const controller = createRoot((rootDispose) => {
            dispose = rootDispose;
            return createSessionComposerController({
                scope,
                busy,
                capabilities: () => ({ ...UNIVERSAL_COMPOSER_CAPABILITIES, hold: false }),
                send: vi.fn(async () => undefined),
            });
        });
        expect(controller.canHold()).toBe(false);
        controller.setDraft("jot this");
        controller.stash();
        // Refused whole: the draft is still there rather than swallowed into a
        // queue the Environment could never release it from.
        expect(controller.queue()).toHaveLength(0);
        expect(controller.draft()).toBe("jot this");
        dispose();
    });

    it("withdraws a host-owned row into the outbox instead of holding it there", async () => {
        const remove = vi.fn(async () => undefined);
        const image = { name: "screenshot.png", mimeType: "image/png", data: "AAAA" };
        // The projection carries the attachments, so the whole message can be
        // reconstructed here, which is what licenses the withdrawal at all.
        const [queue, setQueue] = createSignal([
            { id: "srv-1", text: "on the host", images: [image] },
        ]);
        let dispose!: () => void;
        const controller = createRoot((rootDispose) => {
            dispose = rootDispose;
            return createSessionComposerController({
                scope: () => "chat-1",
                busy: () => false,
                capabilities: () => UNIVERSAL_COMPOSER_CAPABILITIES,
                send: vi.fn(async () => undefined),
                runtime: {
                    queue,
                    followUp: async () => undefined,
                    steer: async () => undefined,
                    edit: async () => undefined,
                    remove,
                    reorder: async () => undefined,
                    promote: async () => undefined,
                },
            });
        });
        await flush();

        // There is no host-side held state to set (ADR 0137 §5): the row comes out
        // of the host's queue and reappears in the outbox, held.
        controller.holdQueued("srv-1", true);
        await flush();
        expect(remove).toHaveBeenCalledWith("srv-1");
        setQueue([]);
        await flush();
        expect(controller.queue().map(({ text, held }) => [text, held])).toEqual([
            ["on the host", true],
        ]);
        // Withdrawn whole: the attachment came back with the words, so releasing
        // it runs the message that was queued rather than a text-only shadow.
        expect(controller.queue()).toHaveLength(1);
        dispose();
    });

    it("refuses to withdraw a host row whose attachments the queue does not carry", async () => {
        const remove = vi.fn(async () => undefined);
        // A text-only projection cannot say whether this row had images, and
        // withdrawing it would delete the host's copy and keep only the words.
        const [queue] = createSignal([{ id: "srv-1", text: "with a screenshot" }]);
        let dispose!: () => void;
        const controller = createRoot((rootDispose) => {
            dispose = rootDispose;
            return createSessionComposerController({
                scope: () => "chat-1",
                busy: () => false,
                capabilities: () => UNIVERSAL_COMPOSER_CAPABILITIES,
                send: vi.fn(async () => undefined),
                runtime: {
                    queue,
                    followUp: async () => undefined,
                    steer: async () => undefined,
                    edit: async () => undefined,
                    remove,
                    reorder: async () => undefined,
                    promote: async () => undefined,
                },
            });
        });
        await flush();

        // The control is withheld for that row rather than offered and lossy...
        expect(controller.queue().map(({ canHold }) => canHold)).toEqual([false]);
        controller.holdQueued("srv-1", true);
        await flush();
        // ...and asking anyway changes nothing on the host.
        expect(remove).not.toHaveBeenCalled();
        expect(controller.error()).toMatch(/attached/i);
        dispose();
    });

    it("hands the composed message to a host that will deliver it elsewhere", () => {
        const h = harness();
        h.controller.setDraft("try this on a new branch");
        const composed = h.controller.takeComposed()!;
        expect(composed.text).toBe("try this on a new branch");
        // Taken means taken: the box is empty, exactly as any other destination
        // would leave it.
        expect(h.controller.draft()).toBe("");
        expect(h.send).not.toHaveBeenCalled();

        // ...but a delivery that fails puts it back rather than eating it.
        composed.restore();
        expect(h.controller.draft()).toBe("try this on a new branch");
        h.dispose();
    });

    it("keeps the mode per chat and falls back to the host default", () => {
        const h = harness();
        expect(h.controller.mode()).toBe("steer");
        h.controller.setMode("stash");
        h.setScope("chat-2");
        // A stashing spell in one conversation must not redirect the next one.
        expect(h.controller.mode()).toBe("steer");
        h.setScope("chat-1");
        expect(h.controller.mode()).toBe("stash");
        h.dispose();
    });

    it("surfaces a failed turn and continues draining the queue", async () => {
        let rejectFirst!: (reason: unknown) => void;
        const send = vi.fn()
            .mockImplementationOnce(() => new Promise<void>((_, reject) => { rejectFirst = reject; }))
            .mockResolvedValueOnce(undefined);
        const h = harness(send);
        await flush();
        h.controller.setDraft("first");
        h.controller.submit();
        h.controller.setDraft("second");
        h.controller.submit();
        await flush();

        rejectFirst(new Error("provider unavailable"));
        await flush();
        await flush();
        expect(h.controller.error()).toBe("provider unavailable");
        expect(send).toHaveBeenNthCalledWith(2, "second", [], expect.any(String));
        h.dispose();
    });

    it("retires client-only state when the Session scope changes", async () => {
        const h = harness();
        h.setBusy(true);
        h.controller.setDraft("draft");
        h.controller.submit();
        h.controller.setDraft("not carried");
        h.setScope("chat-2");
        h.controller.setDraft("new chat draft");
        await flush();
        expect(h.controller.queue()).toHaveLength(0);
        expect(h.controller.draft()).toBe("new chat draft");
        h.dispose();
    });

    it("tracks in-flight dispatch per Session so another chat can run concurrently", async () => {
        let finishFirst!: () => void;
        let finishSecond!: () => void;
        const send = vi.fn()
            .mockImplementationOnce(() => new Promise<void>((resolve) => { finishFirst = resolve; }))
            .mockImplementationOnce(() => new Promise<void>((resolve) => { finishSecond = resolve; }));
        const h = harness(send);
        await flush();

        h.controller.setDraft("alpha");
        h.controller.submit();
        expect(h.controller.busy()).toBe(true);

        h.setScope("chat-2");
        await flush();
        expect(h.controller.busy()).toBe(false);
        h.controller.setDraft("beta");
        h.controller.submit();
        expect(h.controller.busy()).toBe(true);
        await flush();
        expect(send).toHaveBeenCalledTimes(2);

        finishFirst();
        await flush();
        expect(h.controller.busy()).toBe(true);
        finishSecond();
        await flush();
        expect(h.controller.busy()).toBe(false);
        h.dispose();
    });

    it("can preserve a host-owned draft across an overlapping Session handoff", () => {
        const [scope, setScope] = createSignal("chat-1");
        const [draft, setDraft] = createSignal("");
        let dispose!: () => void;
        const controller = createRoot((rootDispose) => {
            dispose = rootDispose;
            return createSessionComposerController({
                scope,
                busy: () => false,
                capabilities: () => UNIVERSAL_COMPOSER_CAPABILITIES,
                send: async () => undefined,
                draft: { value: draft, set: setDraft },
                retainDraftOnScopeChange: true,
            });
        });
        controller.setDraft("typed during navigation");
        setScope("chat-2");
        expect(controller.draft()).toBe("typed during navigation");
        dispose();
    });

    describe("a transport that cannot carry a standing command", () => {
        it("takes the message into the outbox rather than refusing it", async () => {
            const h = harness();
            await flush();
            h.setCanCommand(false);
            h.controller.setDraft("written while offline");
            h.controller.submit();
            await flush();
            expect(h.controller.blocked()).toBe(true);
            // Nothing is sent, and nothing is lost: composing offline is the point
            // of the outbox (ADR 0137), so the message waits durably instead of
            // the draft being held hostage in the box.
            expect(h.send).not.toHaveBeenCalled();
            expect(h.controller.queue().map(({ text }) => text)).toEqual(["written while offline"]);
            expect(h.controller.draft()).toBe("");
            h.dispose();
        });

        it("still permits drafting, which is the point of composing offline", () => {
            const h = harness();
            h.setCanCommand(false);
            h.controller.setDraft("a long message composed on the train");
            expect(h.controller.draft()).toBe("a long message composed on the train");
            expect(h.controller.canSubmit()).toBe(true);
            h.dispose();
        });

        it("refuses stop, which is a standing command a dead transport cannot deliver", () => {
            const h = harness();
            h.setBusy(true);
            h.setCanCommand(false);
            h.controller.stop();
            expect(h.stop).not.toHaveBeenCalled();
            h.dispose();
        });

        it("drains what was staged during the outage once the transport returns", async () => {
            const h = harness();
            await flush();
            // Staged while able, held by a turn already running.
            h.setBusy(true);
            h.controller.setDraft("queued before the drop");
            h.controller.submit();
            expect(h.controller.queue()).toHaveLength(1);

            // The transport drops, then the turn settles: the queue must not
            // dispatch into a connection that cannot carry it.
            h.setCanCommand(false);
            h.setBusy(false);
            await flush();
            expect(h.send).not.toHaveBeenCalled();
            expect(h.controller.queue()).toHaveLength(1);

            // Recovery drains it without further input. Anything less reads as
            // silently swallowed.
            h.setCanCommand(true);
            await flush();
            expect(h.send).toHaveBeenCalledWith("queued before the drop", [], expect.any(String));
            expect(h.controller.queue()).toHaveLength(0);
            h.dispose();
        });

        it("is always able when the host declares no momentary admission", () => {
            const [scope] = createSignal("chat-1");
            const [busy] = createSignal(false);
            let dispose!: () => void;
            const controller = createRoot((rootDispose) => {
                dispose = rootDispose;
                return createSessionComposerController({
                    scope,
                    busy,
                    capabilities: () => UNIVERSAL_COMPOSER_CAPABILITIES,
                    send: async () => undefined,
                });
            });
            expect(controller.blocked()).toBe(false);
            dispose();
        });
    });
});
