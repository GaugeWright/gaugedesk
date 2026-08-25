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

    it("admits no line for an assistant record with no prose, but closes the open text", () => {
        let t = empty;
        t = reduce(t, { type: "text", delta: "partial" });
        expect(t.openText).not.toBeNull();
        t = reduce(t, { type: "assistant", text: "", entry_id: 7, forkable: true });
        expect(t.openText).toBeNull();
        expect(t.lines.filter((l) => l.kind === "assistant")).toHaveLength(0);
        // whitespace-only prose is the same absence
        const ws = reduce(empty, { type: "assistant", text: "  \n" });
        expect(ws.lines).toHaveLength(0);
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

    it("carries an inherited line's origin on every durable kind, not only messages (ADR 0141)", () => {
        // A fork's inherited prefix includes tool and lifecycle lines. If any of
        // them drops `origin`, the fork-point seam renders at every kind change
        // inside the inherited history instead of once at the real seam.
        const parent = "chat-parent";
        const events: StreamEvent[] = [
            { type: "user", text: "do it", origin: parent },
            { type: "tool", tool: "write", mediated: true, call_id: "c1", origin: parent },
            { type: "toolresult", call_id: "c1", ok: true, origin: parent },
            { type: "blocked", tool: "curl", reason: "no egress", origin: parent },
            { type: "error", reason: "transport died", origin: parent },
            { type: "assistant", text: "done", origin: parent },
            { type: "admitted", kind: "run", text: "run → Completed", origin: parent },
            { type: "user", text: "my own line" },
        ];
        const lines = fromSnapshot(events).lines;
        expect(lines.slice(0, -1).every((line) => line.origin === parent)).toBe(true);
        expect(lines[lines.length - 1].origin).toBeUndefined();
    });

    it("admits the streamed reply in place — one line flips tier, no duplicate below it", () => {
        let t = empty;
        t = reduce(t, { type: "user", text: "go" });
        t = reduce(t, { type: "text", delta: "work" });
        t = reduce(t, { type: "text", delta: "ing" });
        t = reduce(t, { type: "assistant", text: "working", entry_id: 7, forkable: true });
        expect(t.lines).toHaveLength(2);
        expect(t.lines[1]).toMatchObject({
            seq: 1, tier: "admitted", kind: "assistant", text: "working", entryId: 7,
        });
        expect(t.openText).toBeNull();
    });

    it("still appends the admitted reply when no streamed line is open", () => {
        let t = reduce(empty, { type: "text", delta: "first thoughts" });
        t = reduce(t, { type: "tool", tool: "read", mediated: true, call_id: "c1" });
        t = reduce(t, { type: "assistant", text: "done" });
        // the tool call closed the streamed line, so the admitted reply appends
        expect(t.lines.map((l) => l.kind)).toEqual(["text", "tool", "assistant"]);
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
