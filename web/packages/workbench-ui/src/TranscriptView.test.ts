import { describe, expect, it } from "vitest";
import { reduce, empty, type StreamEvent } from "./transcript";
import {
    displayAgentName,
    lineRendersMarkdown,
    settledLabel,
    turnForkPoint,
    turnProse,
    turnSettledAt,
} from "./TranscriptView";

describe("transcript Markdown routing", () => {
    it("renders user and agent prose while leaving operational rows literal", () => {
        expect(lineRendersMarkdown("user")).toBe(true);
        expect(lineRendersMarkdown("assistant")).toBe(true);
        expect(lineRendersMarkdown("text")).toBe(true);
        expect(lineRendersMarkdown("tool")).toBe(false);
        expect(lineRendersMarkdown("error")).toBe(false);
        expect(lineRendersMarkdown("run")).toBe(false);
    });
});

describe("assistant display name", () => {
    it("keeps the generic label unless the host supplies a real name", () => {
        expect(displayAgentName()).toBe("Agent");
        expect(displayAgentName("   ")).toBe("Agent");
        expect(displayAgentName("  Theo  ")).toBe("Theo");
    });
});

describe("a settled turn's foot", () => {
    const settled = Date.UTC(2026, 8, 30, 14, 5);
    const turn = (events: StreamEvent[]) => events.reduce(reduce, empty).lines;
    const lines = turn([
        { type: "assistant", text: "Looking at the file.", entry_id: 4, settled_at_unix_ms: settled },
        { type: "tool", tool: "read", mediated: true, call_id: "c1", target: "notes.md" },
        { type: "assistant", text: "  It says **hello**.\n", entry_id: 6, forkable: true, settled_at_unix_ms: settled },
    ]);

    it("copies the turn's prose as written, without its tool lines", () => {
        expect(turnProse(lines)).toBe("Looking at the file.\n\nIt says **hello**.");
    });

    it("forks at the turn's forkable reply", () => {
        expect(turnForkPoint(lines)?.entryId).toBe(6);
        expect(turnForkPoint(lines.slice(0, 2))).toBeUndefined();
    });

    it("says when the turn settled, and nothing for a reply recorded before that was kept", () => {
        expect(turnSettledAt(lines)).toBe(settled);
        expect(turnSettledAt(turn([{ type: "assistant", text: "older", entry_id: 2 }]))).toBeUndefined();
    });

    it("gives the clock time today and the date otherwise", () => {
        const at = new Date(2026, 8, 30, 14, 5).getTime();
        const today = settledLabel(at, new Date(2026, 8, 30, 18, 0));
        const earlier = settledLabel(at, new Date(2026, 9, 2, 9, 0));
        const lastYear = settledLabel(at, new Date(2027, 0, 3, 9, 0));
        expect(today).toMatch(/2:05|14:05/);
        expect(today).not.toMatch(/Sep/);
        expect(earlier).toMatch(/Sep/);
        expect(earlier).not.toMatch(/2026/);
        expect(lastYear).toMatch(/2026/);
    });
});
