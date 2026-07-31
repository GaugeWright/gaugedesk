import { describe, expect, it } from "vitest";
import { empty, fromSnapshot, pendingUserAfterSnapshot, reduce, type StreamEvent } from "./transcript";

describe("transcript reduction", () => {
    it("coalesces streamed text deltas into one operational line", () => {
        let t = empty;
        t = reduce(t, { type: "text", delta: "Hello " });
        t = reduce(t, { type: "text", delta: "world" });
        expect(t.lines).toHaveLength(1);
        expect(t.lines[0]).toMatchObject({ tier: "operational", text: "Hello world" });
    });

    it("keeps operational and admitted tiers distinct", () => {
        let t = empty;
        t = reduce(t, { type: "text", delta: "thinking..." });
        t = reduce(t, { type: "admitted", kind: "run", text: "run → Completed" });
        expect(t.lines.map((l) => l.tier)).toEqual(["operational", "admitted"]);
    });

    it("marks a blocked tool as such (the membrane's veto is visible)", () => {
        const t = reduce(empty, { type: "blocked", tool: "bash", reason: "policy" });
        expect(t.lines[0].kind).toBe("blocked");
        expect(t.lines[0].text).toContain("bash");
    });

    it("builds a tool line with a clickable target and fills in ✓/✗ on result", () => {
        let t = empty;
        t = reduce(t, { type: "tool", tool: "read", mediated: true, call_id: "t1", target: "auth.ts", args: '{"path":"auth.ts"}' });
        expect(t.lines[0]).toMatchObject({ kind: "tool", text: "▸ read auth.ts" });
        expect(t.lines[0].tool).toMatchObject({ name: "read", target: "auth.ts", callId: "t1" });
        expect(t.lines[0].tool?.ok).toBeUndefined();
        // the result correlates by call_id and fills in success + output
        t = reduce(t, { type: "toolresult", call_id: "t1", ok: true, result: "file contents" });
        expect(t.lines[0].tool).toMatchObject({ ok: true, result: "file contents" });
    });

    it("correlates a result to the most recent matching tool line only", () => {
        let t = empty;
        t = reduce(t, { type: "tool", tool: "read", mediated: true, call_id: "t1", target: "a.ts" });
        t = reduce(t, { type: "tool", tool: "read", mediated: true, call_id: "t2", target: "b.ts" });
        t = reduce(t, { type: "toolresult", call_id: "t2", ok: false });
        expect(t.lines[0].tool?.ok).toBeUndefined();
        expect(t.lines[1].tool?.ok).toBe(false);
    });

    it("surfaces a failed turn's reason as an admitted-tier error line", () => {
        const t = reduce(empty, { type: "error", reason: "model does not support image input" });
        expect(t.lines[0]).toMatchObject({
            tier: "admitted",
            kind: "error",
            text: "model does not support image input",
        });
        expect(t.lines[0].code).toBeUndefined();
    });

    it("carries an error's machine-readable code onto the line (LLM-1 credential refusal)", () => {
        const t = reduce(empty, {
            type: "error",
            reason: "No model sign-in found. Link a key in Account settings.",
            code: "no_credential",
        });
        expect(t.lines[0]).toMatchObject({ kind: "error", code: "no_credential" });
    });

    it("preserves durable point-fork coordinates on user and assistant lines", () => {
        const user = reduce(empty, {
            type: "user",
            text: "revise it",
            entry_id: 41,
            forkable: true,
        });
        const assistant = reduce(user, {
            type: "assistant",
            text: "done",
            entry_id: 52,
            forkable: true,
        });
        expect(assistant.lines[0]).toMatchObject({ entryId: 41, forkable: true });
        expect(assistant.lines[1]).toMatchObject({ entryId: 52, forkable: true });
    });

    it("is repairable: replaying a snapshot from empty yields the same transcript", () => {
        const events: StreamEvent[] = [
            { type: "text", delta: "a" },
            { type: "tool", tool: "read", mediated: true },
            { type: "text", delta: "b" },
            { type: "admitted", kind: "run", text: "run → Running" },
        ];
        const live = events.reduce(reduce, empty);
        const repaired = fromSnapshot(events);
        expect(repaired).toEqual(live);
    });

    it("keeps a pending user line across a lagging snapshot repair without duplicating admission", () => {
        const before = fromSnapshot([{ type: "user", text: "same words" }]);

        expect(pendingUserAfterSnapshot(before, "same words", before.lines.length).lines)
            .toMatchObject([{ kind: "user", text: "same words" }]);

        const admitted = fromSnapshot([
            { type: "user", text: "same words" },
            { type: "user", text: "same words" },
        ]);
        expect(pendingUserAfterSnapshot(admitted, "same words", before.lines.length)).toEqual(empty);
    });
});
