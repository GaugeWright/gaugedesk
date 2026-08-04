import { createRoot, createSignal } from "solid-js";
import { describe, expect, it, vi } from "vitest";
import {
    UNIVERSAL_COMPOSER_CAPABILITIES,
    createSessionComposerController,
} from "./session-composer-controller";

const flush = async () => {
    await Promise.resolve();
    await Promise.resolve();
};

function harness(send = vi.fn(async () => undefined)) {
    const [scope, setScope] = createSignal("chat-1");
    const [busy, setBusy] = createSignal(false);
    const stop = vi.fn(async () => undefined);
    let dispose!: () => void;
    const controller = createRoot((rootDispose) => {
        dispose = rootDispose;
        return createSessionComposerController({
            scope,
            busy,
            capabilities: () => UNIVERSAL_COMPOSER_CAPABILITIES,
            send,
            stop,
        });
    });
    return { controller, send, stop, setBusy, setScope, dispose };
}

describe("createSessionComposerController", () => {
    it("queues while an authoritative turn is busy and drains after settlement", async () => {
        const h = harness();
        h.setBusy(true);
        h.controller.setDraft("follow up");
        h.controller.submit();
        expect(h.controller.queue()).toMatchObject([{ text: "follow up" }]);
        expect(h.send).not.toHaveBeenCalled();

        h.setBusy(false);
        await flush();
        expect(h.send).toHaveBeenCalledWith("follow up", [], { review: false });
        expect(h.controller.queue()).toHaveLength(0);
        h.dispose();
    });

    it("steers by stopping the active turn and running the steering message next", async () => {
        let finishFirst!: () => void;
        const send = vi.fn()
            .mockImplementationOnce(() => new Promise<void>((resolve) => { finishFirst = resolve; }))
            .mockResolvedValueOnce(undefined);
        const h = harness(send);

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
        expect(send).toHaveBeenNthCalledWith(2, "redirect", [], { review: false });
        h.dispose();
    });

    it("stages, edits, reorders, removes, and releases queued messages", async () => {
        const h = harness();
        h.controller.toggleGate();
        h.controller.setDraft("one");
        h.controller.submit();
        h.controller.setDraft("two");
        h.controller.submit();
        expect(h.controller.queue().map(({ text }) => text)).toEqual(["one", "two"]);

        h.controller.reorderQueue(1, 0);
        const first = h.controller.queue()[0]!;
        h.controller.editQueued(first.id, "two edited");
        h.controller.removeQueued(h.controller.queue()[1]!.id);
        expect(h.controller.queue().map(({ text }) => text)).toEqual(["two edited"]);

        h.controller.toggleGate();
        await flush();
        expect(h.send).toHaveBeenCalledWith("two edited", [], { review: false });
        h.dispose();
    });

    it("surfaces a failed turn and continues draining the queue", async () => {
        let rejectFirst!: (reason: unknown) => void;
        const send = vi.fn()
            .mockImplementationOnce(() => new Promise<void>((_, reject) => { rejectFirst = reject; }))
            .mockResolvedValueOnce(undefined);
        const h = harness(send);
        h.controller.setDraft("first");
        h.controller.submit();
        h.controller.setDraft("second");
        h.controller.submit();

        rejectFirst(new Error("provider unavailable"));
        await flush();
        await flush();
        expect(h.controller.error()).toBe("provider unavailable");
        expect(send).toHaveBeenNthCalledWith(2, "second", [], { review: false });
        h.dispose();
    });

    it("retires client-only state when the Session scope changes", async () => {
        const h = harness();
        h.controller.toggleGate();
        h.controller.setDraft("draft");
        h.controller.submit();
        h.controller.setDraft("not carried");
        h.setScope("chat-2");
        h.controller.setDraft("new chat draft");
        await flush();
        expect(h.controller.queue()).toHaveLength(0);
        expect(h.controller.draft()).toBe("new chat draft");
        expect(h.controller.gated()).toBe(false);
        h.dispose();
    });

    it("tracks in-flight dispatch per Session so another chat can run concurrently", async () => {
        let finishFirst!: () => void;
        let finishSecond!: () => void;
        const send = vi.fn()
            .mockImplementationOnce(() => new Promise<void>((resolve) => { finishFirst = resolve; }))
            .mockImplementationOnce(() => new Promise<void>((resolve) => { finishSecond = resolve; }));
        const h = harness(send);

        h.controller.setDraft("alpha");
        h.controller.submit();
        expect(h.controller.busy()).toBe(true);

        h.setScope("chat-2");
        await flush();
        expect(h.controller.busy()).toBe(false);
        h.controller.setDraft("beta");
        h.controller.submit();
        expect(send).toHaveBeenCalledTimes(2);
        expect(h.controller.busy()).toBe(true);

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
});
