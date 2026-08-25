import { describe, expect, it } from "vitest";
import {
    fromSnapshot,
    groupTurns,
    reconcileLines,
    reconcileSegments,
    type StreamEvent,
} from "./transcript";

/** Build a transcript's lines from a flat event list, the way the client does. */
const lines = (evs: StreamEvent[]) => fromSnapshot(evs).lines;

describe("groupTurns — fold agent prose + its tool calls into one turn", () => {
    it("brackets a run of agent lines (text/tool/blocked) into a single turn", () => {
        const segs = groupTurns(
            lines([
                { type: "user", text: "do it" },
                { type: "assistant", text: "Let me check" },
                { type: "tool", tool: "read", mediated: false, call_id: "c1", target: "a.txt" },
                { type: "assistant", text: "Done" },
            ]),
        );
        expect(segs.map((s) => s.type)).toEqual(["line", "turn"]);
        const turn = segs[1];
        if (turn.type !== "turn") throw new Error("expected a turn");
        expect(turn.lines).toHaveLength(3);
        // The turn id is the seq of its first line — stable as the turn streams.
        expect(turn.id).toBe(turn.lines[0].seq);
    });

    it("your messages, lifecycle notes and errors stand alone, splitting turns", () => {
        const segs = groupTurns(
            lines([
                { type: "user", text: "one" },
                { type: "assistant", text: "first" },
                { type: "admitted", kind: "run", text: "run → Completed" },
                { type: "user", text: "two" },
                { type: "assistant", text: "second" },
            ]),
        );
        // user · turn · run · user · turn
        expect(segs.map((s) => s.type)).toEqual(["line", "turn", "line", "line", "turn"]);
    });

    it("is empty for an empty transcript and order-preserving", () => {
        expect(groupTurns([])).toEqual([]);
        const segs = groupTurns(lines([{ type: "user", text: "hi" }]));
        expect(segs).toHaveLength(1);
        expect(segs[0].type).toBe("line");
    });
});

describe("reconcile — identity survives a rebuild so unchanged rows keep their DOM", () => {
    const events: StreamEvent[] = [
        { type: "user", text: "go" },
        { type: "text", delta: "working" },
        { type: "tool", tool: "read", mediated: true, call_id: "c1", target: "a.ts" },
    ];

    it("keeps the previous line object wherever nothing changed", () => {
        const prev = lines(events);
        const next = lines(events); // fresh objects, same content
        const out = reconcileLines(prev, next);
        expect(out).toBe(prev); // nothing changed at all → the previous array itself
    });

    it("replaces only the lines that actually changed", () => {
        const prev = lines(events);
        const next = lines([...events, { type: "toolresult", call_id: "c1", ok: true }]);
        const out = reconcileLines(prev, next);
        expect(out[0]).toBe(prev[0]);
        expect(out[1]).toBe(prev[1]);
        expect(out[2]).not.toBe(prev[2]); // ✓ filled in
        expect(out[2].tool?.ok).toBe(true);
    });

    it("keeps a segment's wrapper object while its line objects are unchanged", () => {
        const stable = lines(events);
        const prevSegs = groupTurns(stable);
        const nextSegs = reconcileSegments(prevSegs, groupTurns(stable));
        expect(nextSegs[0]).toBe(prevSegs[0]); // the user line
        expect(nextSegs[1]).toBe(prevSegs[1]); // the whole turn
    });

    it("rebuilds only the segment whose lines changed — the settle-swap case", () => {
        const live = lines(events);
        const settled = reconcileLines(
            live,
            lines([
                { type: "user", text: "go" },
                { type: "assistant", text: "working", entry_id: 3 },
                { type: "tool", tool: "read", mediated: true, call_id: "c1", target: "a.ts" },
            ]),
        );
        const prevSegs = groupTurns(live);
        const nextSegs = reconcileSegments(prevSegs, groupTurns(settled));
        expect(nextSegs[0]).toBe(prevSegs[0]); // untouched user line keeps identity
        expect(nextSegs[1]).not.toBe(prevSegs[1]); // the settling turn is the one that rebuilds
    });
});
