import { createRoot, createSignal } from "solid-js";
import { describe, expect, it, vi } from "vitest";
import { type EngagementId } from "@gaugewright/control-plane-client";
import { empty as emptyTranscript, reduce } from "@gaugewright/workbench-ui/transcript";
import { type ConnectionStatus } from "@gaugewright/workbench-ui/connection";
import { createMobileSession, MOBILE_COMPOSER_CAPABILITIES } from "./mobile-session";

const CHAT = "chat-1" as EngagementId;

function harness(overrides: { runTask?: () => Promise<unknown> } = {}) {
    const api = {
        runTask: vi.fn(overrides.runTask ?? (async () => undefined)),
        stopTurn: vi.fn(async () => ({ stopped: true })),
        getTree: vi.fn(async () => []),
        getFile: vi.fn(async () => ""),
    };
    const [engagementId, setEngagement] = createSignal<EngagementId | null>(CHAT);
    const [transcript, setTranscript] = createSignal(emptyTranscript);
    const [connection, setConnection] = createSignal<ConnectionStatus>("active");
    const onSettled = vi.fn();
    const onSendFailed = vi.fn();
    let dispose!: () => void;
    const session = createRoot((rootDispose) => {
        dispose = rootDispose;
        return createMobileSession({
            api,
            engagementId,
            transcript,
            connection,
            selectedFile: () => null,
            selectFile: () => undefined,
            worktreeRev: () => 0,
            onSettled,
            onSendFailed,
            onStatus: () => undefined,
        });
    });
    return { session, api, setEngagement, setTranscript, setConnection, onSettled, onSendFailed, dispose };
}

describe("createMobileSession", () => {
    it("declares only what the mobile control plane can actually serve", () => {
        // A capability the transport has no route for is how a control becomes
        // silently dead, so neither shared default is usable here.
        expect(MOBILE_COMPOSER_CAPABILITIES).toEqual({
            queue: false,
            steer: false,
            stop: true,
            hold: false,
            fork: false,
            attachments: [],
        });
    });

    it("reads command admission off the same predicate the banner reads", () => {
        const h = harness();
        expect(h.session.canCommand()).toBe(true);
        h.setConnection("offline");
        expect(h.session.canCommand()).toBe(false);
        h.setConnection("revoked");
        expect(h.session.canCommand()).toBe(false);
        h.dispose();
    });

    it("settles the sibling projections a turn may have changed", async () => {
        const h = harness();
        await h.session.send("go", []);
        expect(h.onSettled).toHaveBeenCalledTimes(1);
        h.dispose();
    });

    it("gives a failed send's text back rather than dropping it", async () => {
        const h = harness({ runTask: async () => { throw new Error("relay dropped"); } });
        await expect(h.session.send("typed with thumbs", [])).rejects.toThrow("relay dropped");
        expect(h.onSendFailed).toHaveBeenCalledWith("typed with thumbs");
        // And the Session settles: a failure must not leave the composer busy.
        expect(h.session.busy()).toBe(false);
        h.dispose();
    });

    it("reports live-turn activity from the transcript it already reduces", async () => {
        const h = harness({ runTask: () => new Promise(() => {}) });
        expect(h.session.turnActivity()).toEqual({ state: "idle" });

        void h.session.send("what changed?", []);
        expect(h.session.busy()).toBe(true);
        // Dispatched, nothing streamed back yet.
        expect(h.session.turnActivity()).toEqual({ state: "awaiting_model" });

        // A tool that started and has not reported back is a tool running, and
        // the name is the whole reason the caption is worth showing.
        h.setTranscript((t) =>
            reduce(t, { type: "tool", tool: "grep", mediated: false, call_id: "c1" }),
        );
        expect(h.session.turnActivity()).toEqual({ state: "running_tool", tool: "grep" });

        h.setTranscript((t) => reduce(t, { type: "text", delta: "found it" }));
        expect(h.session.turnActivity()).toEqual({ state: "streaming_output" });
        h.dispose();
    });

    it("refuses a send with no chat open instead of inventing one", async () => {
        const h = harness();
        h.setEngagement(null);
        await expect(h.session.send("into the void", [])).rejects.toThrow(/Open a chat/);
        expect(h.api.runTask).not.toHaveBeenCalled();
        h.dispose();
    });

    it("refuses a file write explicitly, since the phone has no route for one", async () => {
        const h = harness();
        await expect(h.session.api.putFile(CHAT, "a.txt", "x")).rejects.toThrow(/cannot write files/);
        h.dispose();
    });
});
