import { describe, expect, it } from "vitest";
import { friendlyToolVerb, toolGroup, toolId } from "./tool-verb";

describe("toolId — normalize a tool name onto a filter identity", () => {
    it("maps each runtime tool to its own identity", () => {
        expect(toolId("bash")).toBe("bash");
        expect(toolId("write")).toBe("write");
        expect(toolId("edit")).toBe("edit");
        expect(toolId("read")).toBe("read");
        expect(toolId("ls")).toBe("ls");
        expect(toolId("grep")).toBe("grep");
        expect(toolId("find")).toBe("find");
    });

    it("folds aliases onto the same identity (case-insensitive)", () => {
        expect(toolId("SHELL")).toBe("bash");
        expect(toolId("str_replace")).toBe("edit");
        expect(toolId("cat")).toBe("read");
        expect(toolId("list")).toBe("ls");
        expect(toolId("search")).toBe("grep");
    });

    it("folds any unrecognized (plugin/MCP) tool to 'other'", () => {
        expect(toolId("fetch_url")).toBe("other");
        expect(toolId("rm")).toBe("other");
    });
});

describe("toolGroup — coarse grouping for the menu", () => {
    it("groups the identities", () => {
        expect(toolGroup("bash")).toBe("command");
        expect(toolGroup("write")).toBe("write");
        expect(toolGroup("edit")).toBe("write");
        expect(toolGroup("read")).toBe("read");
        expect(toolGroup("ls")).toBe("read");
        expect(toolGroup("grep")).toBe("read");
        expect(toolGroup("find")).toBe("read");
        expect(toolGroup("other")).toBe("other");
    });
});

describe("friendlyToolVerb — plain-language verb (unchanged contract)", () => {
    it("reads the common tools in plain words", () => {
        expect(friendlyToolVerb("write")).toBe("Wrote");
        expect(friendlyToolVerb("bash")).toBe("Ran a command");
        expect(friendlyToolVerb("grep")).toBe("Searched");
        expect(friendlyToolVerb("offer_download")).toBe("Offered a download");
    });
});
