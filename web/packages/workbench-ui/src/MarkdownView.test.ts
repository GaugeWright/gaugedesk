/**
 * The View tab's markdown rendering: agent-written files are untrusted, so
 * these pin the safety posture (embedded HTML is escaped, dangerous link
 * protocols are refused) alongside the feature itself (headings, GFM tables).
 */

import { describe, expect, it } from "vitest";
import { isMarkdownPath, renderMarkdown } from "./MarkdownView";

describe("isMarkdownPath", () => {
    it("matches .md and .markdown, case-insensitively", () => {
        expect(isMarkdownPath("poem.md")).toBe(true);
        expect(isMarkdownPath("notes/README.MD")).toBe(true);
        expect(isMarkdownPath("doc.markdown")).toBe(true);
        expect(isMarkdownPath("main.rs")).toBe(false);
        expect(isMarkdownPath("md")).toBe(false);
        expect(isMarkdownPath("archive.md.bak")).toBe(false);
    });
});

describe("renderMarkdown", () => {
    it("renders headings, emphasis, and GFM tables", () => {
        const html = renderMarkdown("# Title\n\nSome **bold** text.\n\n| a | b |\n| - | - |\n| 1 | 2 |\n");
        expect(html).toContain("<h1>Title</h1>");
        expect(html).toContain("<strong>bold</strong>");
        expect(html).toContain("<table>");
    });

    it("escapes embedded HTML instead of executing it", () => {
        const html = renderMarkdown('hello <script>alert(1)</script> <img src=x onerror="alert(1)">');
        expect(html).not.toContain("<script>");
        expect(html).not.toContain("<img");
        expect(html).toContain("&lt;script&gt;");
    });

    it("refuses dangerous link protocols", () => {
        const html = renderMarkdown("[click](javascript:alert(1))");
        expect(html).not.toContain('href="javascript:');
    });

    it("keeps safe links and autolinks", () => {
        const html = renderMarkdown("see https://example.com and [docs](https://docs.rs)");
        expect(html).toContain('href="https://example.com"');
        expect(html).toContain('href="https://docs.rs"');
        expect(html.match(/target="_blank"/g)).toHaveLength(2);
        expect(html.match(/rel="noopener noreferrer"/g)).toHaveLength(2);
    });
});
