import { describe, expect, it } from "vitest";
import { createSignal } from "solid-js";
import { localTurnActivity, TURN_ACTIVITIES, type TurnObservation } from "./session-context";
import { empty, reduce, type Transcript } from "./transcript";

/** Feed the shared reduction so the fixture ages exactly as a real transcript
 *  does — `openText` is the signal under test, and hand-built literals would
 *  let this pass while the reduction that produces it changed underneath. */
function transcriptOf(...events: Parameters<typeof reduce>[1][]): Transcript {
    return events.reduce<Transcript>((current, event) => reduce(current, event), empty);
}

describe("live turn observation vocabulary (ADR 0133)", () => {
    it("matches the runtime vocabulary exactly", () => {
        // This list is the contract with WhippleScript's `PublicTurnActivity`
        // (spec/agent-harness.md). A state the runtime publishes but this list
        // omits is a frame the transport silently drops.
        expect([...TURN_ACTIVITIES]).toEqual([
            "idle",
            "awaiting_model",
            "streaming_output",
            "running_tool",
            "compacting",
            "retrying",
            "settling",
            "stopping",
        ]);
    });
});

describe("localTurnActivity (Environments without runtime activity frames)", () => {
    it("reads idle whenever no turn is running", () => {
        const [busy] = createSignal(false);
        const [transcript] = createSignal(transcriptOf({ type: "text", delta: "partial" }));
        // Even with an open text line, a settled session is idle: busy is what
        // says a turn exists, and a stale open line must not pin the composer.
        expect(localTurnActivity(busy, transcript)()).toEqual({ state: "idle" });
    });

    it("reads thinking while a turn runs before any answer text arrives", () => {
        const [busy] = createSignal(true);
        const [transcript] = createSignal(transcriptOf({ type: "user", text: "hello" }));
        expect(localTurnActivity(busy, transcript)()).toEqual({ state: "awaiting_model" });
    });

    it("reads streaming while deltas arrive, then names the tool that starts", () => {
        const [busy] = createSignal(true);
        const [transcript, setTranscript] = createSignal(
            transcriptOf({ type: "user", text: "hello" }, { type: "text", delta: "the ans" }),
        );
        const activity = localTurnActivity(busy, transcript);
        expect(activity()).toEqual({ state: "streaming_output" });

        // A tool line with no result yet IS a running tool, and it carries the
        // name — the local runtime publishes no activity frames, but the
        // transcript already records everything needed to say this.
        setTranscript((current) =>
            reduce(current, { type: "tool", tool: "bash", mediated: false, call_id: "c1" }),
        );
        expect(activity()).toEqual({ state: "running_tool", tool: "bash" });

        // Once the tool reports back, the turn is waiting on the model again.
        setTranscript((current) =>
            reduce(current, { type: "toolresult", call_id: "c1", ok: true, result: "done" }),
        );
        expect(activity()).toEqual({ state: "awaiting_model" });
    });

    it("only ever reports states in the shared vocabulary", () => {
        const [busy, setBusy] = createSignal(false);
        const [transcript, setTranscript] = createSignal(empty);
        const activity = localTurnActivity(busy, transcript);
        const seen: TurnObservation[] = [activity()];
        setBusy(true);
        seen.push(activity());
        setTranscript((current) => reduce(current, { type: "text", delta: "x" }));
        seen.push(activity());
        for (const observation of seen) expect(TURN_ACTIVITIES).toContain(observation.state);
    });
});
