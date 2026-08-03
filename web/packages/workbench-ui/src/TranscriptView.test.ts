import { describe, expect, it } from "vitest";
import { lineRendersMarkdown } from "./TranscriptView";

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
