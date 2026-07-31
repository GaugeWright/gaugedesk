import { describe, expect, it, vi } from "vitest";
import { createRoot } from "solid-js";
import { createRemoteSession } from "./remote-session";
import type { EngagementId, MergeState, StreamEvent } from "@gaugewright/control-plane-client";
import type { EmbedSessionApi } from "./session-api";

const idleMerge: MergeState = {
    phase: "Idle",
    thread_state: "",
    git_outcome: "Unknown",
    review_requested: false,
};

/** Minimal fake edge API that captures live events and records commands. */
function fakeApi() {
    const calls = {
        onEvent: undefined as ((ev: StreamEvent) => void) | undefined,
        closed: false,
        runTask: vi.fn(async () => undefined),
        runEmbedTurn: vi.fn<() => Promise<void>>(async () => undefined),
        mergeCommand: vi.fn(async () => idleMerge),
        recordFirstTextRendered: vi.fn(),
    };
    const api: EmbedSessionApi = {
        getTranscript: async () => [] as StreamEvent[],
        subscribe: (_id: EngagementId, onEvent: (ev: StreamEvent) => void) => {
            calls.onEvent = onEvent;
            return () => {
                calls.closed = true;
            };
        },
        engagementDiff: async () => "",
        getMerge: async () => idleMerge,
        runTask: calls.runTask,
        runEmbedTurn: calls.runEmbedTurn,
        mergeCommand: calls.mergeCommand,
        getFile: async () => "",
        putFile: async () => undefined,
        getTree: async () => [],
        embedMyChats: async () => [],
        embedGetConfig: async () => ({ white_label: false }),
        recordFirstTextRendered: calls.recordFirstTextRendered,
    };
    return { api, calls };
}

const ENG = "eng-1" as EngagementId;

describe("createRemoteSession", () => {
    it("binds to its fixed engagement", () => {
        createRoot((dispose) => {
            const { session } = createRemoteSession({ api: fakeApi().api, engagementId: ENG });
            expect(session.engagementId()).toBe(ENG);
            dispose();
        });
    });

    it("reduces live stream events into the transcript projection", () => {
        createRoot((dispose) => {
            const f = fakeApi();
            const { session } = createRemoteSession({ api: f.api, engagementId: ENG });
            expect(session.transcript().lines).toHaveLength(0);
            f.calls.onEvent?.({ type: "user", text: "hello" });
            const lines = session.transcript().lines;
            expect(lines).toHaveLength(1);
            expect(lines[0]?.text).toBe("hello");
            dispose();
        });
    });

    it("records first text after the reactive render boundary", async () => {
        const f = fakeApi();
        let disposeRoot!: () => void;
        createRoot((dispose) => {
            disposeRoot = dispose;
            createRemoteSession({ api: f.api, engagementId: ENG });
        });

        f.calls.onEvent?.({ type: "text", delta: "visible" });
        expect(f.calls.recordFirstTextRendered).not.toHaveBeenCalled();
        await vi.waitFor(() =>
            expect(f.calls.recordFirstTextRendered).toHaveBeenCalledTimes(1),
        );
        disposeRoot();
    });

    it("send() echoes the user line optimistically and starts a turn", () => {
        createRoot((dispose) => {
            const f = fakeApi();
            const { session } = createRemoteSession({ api: f.api, engagementId: ENG });
            session.send("do the thing");
            expect(session.transcript().lines.at(-1)?.text).toBe("do the thing");
            expect(f.calls.runEmbedTurn).toHaveBeenCalledWith(ENG, "do the thing");
            dispose();
        });
    });

    it("send() ignores blank input", () => {
        createRoot((dispose) => {
            const f = fakeApi();
            const { session } = createRemoteSession({ api: f.api, engagementId: ENG });
            session.send("   ");
            expect(f.calls.runEmbedTurn).not.toHaveBeenCalled();
            expect(session.transcript().lines).toHaveLength(0);
            dispose();
        });
    });

    it("projects one in-flight turn so the shared composer shows working and refuses duplicates", async () => {
        const f = fakeApi();
        let finish!: () => void;
        f.calls.runEmbedTurn.mockImplementation(
            () => new Promise<void>((resolve) => {
                finish = resolve;
            }),
        );
        let disposeRoot!: () => void;
        const { session } = createRoot((dispose) => {
            disposeRoot = dispose;
            return createRemoteSession({
                api: f.api,
                engagementId: ENG,
            });
        });

        session.send("first");
        expect(session.busy?.()).toBe(true);
        session.send("duplicate");
        expect(f.calls.runEmbedTurn).toHaveBeenCalledTimes(1);

        finish();
        await vi.waitFor(() => expect(session.busy?.()).toBe(false));
        disposeRoot();
    });

    it("tracks cross-panel file selection", () => {
        createRoot((dispose) => {
            const f = fakeApi();
            const { session } = createRemoteSession({ api: f.api, engagementId: ENG });
            expect(session.selectedFile()).toBeNull();
            session.selectFile("src/index.ts");
            expect(session.selectedFile()).toBe("src/index.ts");
            dispose();
        });
    });

    it("merge() drives the merge command for the engagement", () => {
        createRoot((dispose) => {
            const f = fakeApi();
            const { session } = createRemoteSession({ api: f.api, engagementId: ENG });
            session.merge("admit");
            expect(f.calls.mergeCommand).toHaveBeenCalledWith(ENG, "admit");
            dispose();
        });
    });

    it("dispose closes the live stream", () => {
        const f = fakeApi();
        createRoot((dispose) => {
            const { dispose: closeStream } = createRemoteSession({ api: f.api, engagementId: ENG });
            closeStream();
            dispose();
        });
        expect(f.calls.closed).toBe(true);
    });
});
