import { describe, it, expect } from "vitest";
import { isBoilerplateResult, partitionedToolTarget, toolDetail, toolHeaderTarget } from "./tool-detail";

describe("toolDetail — additive-only disclosure (no redundant restatement)", () => {
    it("reveals a bash call's full command, not a {command:…} blob", () => {
        expect(toolDetail("bash", '{"command":"echo hi"}').summary).toBe("Ran: echo hi");
    });

    it("emits no summary for a search tool — the pattern is in the collapsed header", () => {
        expect(toolDetail("grep", '{"pattern":"todo"}').summary).toBeNull();
        expect(toolDetail("find", '{"pattern":"*.ts"}').summary).toBeNull();
    });

    it("emits NO summary for file tools — the header (verb + file) already says it", () => {
        // The collapsed line is "Wrote agent-note.txt ✓"; "Saved the file …" would be
        // pure redundancy, the waste this strips.
        expect(toolDetail("write", '{"path":"agent-note.txt"}').summary).toBeNull();
        expect(toolDetail("edit", '{"file":"a.txt"}').summary).toBeNull();
        expect(toolDetail("read", '{"path":"b.md"}').summary).toBeNull();
        expect(toolDetail("rm", '{"path":"c"}').summary).toBeNull();
    });

    it("emits no summary for an unknown tool (header carries the verb + target)", () => {
        expect(toolDetail("mystery", '{"path":"z.txt"}').summary).toBeNull();
    });

    it("returns null for empty / {} / unparseable / non-object args", () => {
        expect(toolDetail("bash", undefined).summary).toBeNull();
        expect(toolDetail("bash", "{}").summary).toBeNull();
        expect(toolDetail("bash", "{ not json").summary).toBeNull();
        expect(toolDetail("bash", "[1,2,3]").summary).toBeNull();
    });

    it("never returns the raw args string as the summary", () => {
        const raw = '{"command":"ls","extra":{"nested":true}}';
        expect(toolDetail("bash", raw).summary).not.toBe(raw);
    });
});

describe("toolHeaderTarget — the collapsed line's target", () => {
    it("shows a search tool's pattern, not the directory the server picked", () => {
        // grep emits {pattern, path}; the server's target extraction picks `path`
        // first (".") — recover the pattern so the line reads "Searched todo", not ".".
        expect(toolHeaderTarget("grep", '{"pattern":"todo","path":"."}', ".")).toBe("todo");
        expect(toolHeaderTarget("find", '{"pattern":"*.ts","path":"src"}', "src")).toBe("*.ts");
    });

    it("falls back to the server target when a search carries no pattern", () => {
        expect(toolHeaderTarget("grep", "{}", "src")).toBe("src");
        expect(toolHeaderTarget("grep", undefined, "src")).toBe("src");
    });

    it("keeps the server target for non-search tools (file path, command)", () => {
        expect(toolHeaderTarget("write", '{"path":"a.txt"}', "a.txt")).toBe("a.txt");
        expect(toolHeaderTarget("bash", '{"command":"echo hi"}', "echo hi")).toBe("echo hi");
    });

    it("is undefined when there is no target at all", () => {
        expect(toolHeaderTarget("write", undefined, undefined)).toBeUndefined();
        expect(toolHeaderTarget("write", undefined, "")).toBeUndefined();
    });
});

describe("partitionedToolTarget", () => {
    it("keeps the stable target partition explicit while presenting the relative path", () => {
        expect(partitionedToolTarget("targets/t-mfrgg/src/app.ts")).toEqual({
            targetRoot: "t-mfrgg",
            relativePath: "src/app.ts",
        });
    });
});

describe("isBoilerplateResult — strip confirmations the ✓ already conveys", () => {
    it("treats the canonical write confirmations as boilerplate", () => {
        for (const t of [
            "wrote 1 file",
            "wrote 3 files",
            "1 file written",
            "File written successfully",
            "Successfully created agent-note.txt",
            "The file has been updated",
            "Applied 2 edits",
            "ok",
            "Done.",
            "no changes",
            "",
            "   ",
        ]) {
            expect(isBoilerplateResult(t)).toBe(true);
        }
    });

    it("keeps real output (command stdout, file contents, search matches)", () => {
        for (const t of [
            "hello world",
            "total 8\ndrwxr-xr-x  3 user  staff",
            "export const x = 1;",
            "src/app.ts:42: const todo = true;",
        ]) {
            expect(isBoilerplateResult(t)).toBe(false);
        }
    });
});
