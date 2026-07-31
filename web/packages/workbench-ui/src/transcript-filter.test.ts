import { describe, expect, it } from "vitest";
import {
    defaultPrefs,
    isFiltering,
    lineToolGroup,
    lineVisible,
    loadPrefs,
    messageCategoryOf,
    savePrefs,
    toolExpanded,
    type FilterPrefs,
} from "./transcript-filter";
import { type TranscriptLine } from "./transcript";

const line = (kind: string, toolName?: string): TranscriptLine => ({
    seq: 0,
    tier: "operational",
    kind,
    text: "",
    tool: toolName ? { name: toolName } : undefined,
});

describe("messageCategoryOf — non-tool lines", () => {
    it("maps the conversation kinds and folds lifecycle/unknown into system", () => {
        expect(messageCategoryOf("user")).toBe("user");
        expect(messageCategoryOf("assistant")).toBe("agent");
        expect(messageCategoryOf("text")).toBe("agent");
        expect(messageCategoryOf("blocked")).toBe("blocked");
        expect(messageCategoryOf("error")).toBe("error");
        for (const k of ["run", "merge", "sync", "clean", "revert", "whatever"]) {
            expect(messageCategoryOf(k)).toBe("system");
        }
    });
});

describe("lineVisible — per-tool and per-message visibility", () => {
    it("hides an individual tool without touching its siblings", () => {
        const prefs: FilterPrefs = {
            ...defaultPrefs,
            tools: { ...defaultPrefs.tools, grep: { visible: false, expanded: false } },
        };
        expect(lineVisible(line("tool", "grep"), prefs)).toBe(false);
        // alias normalizes — "search" is the same identity as grep
        expect(lineVisible(line("tool", "search"), prefs)).toBe(false);
        expect(lineVisible(line("tool", "ls"), prefs)).toBe(true);
        expect(lineVisible(line("tool", "read"), prefs)).toBe(true);
    });

    it("hides a message category independently of tools", () => {
        const prefs: FilterPrefs = { ...defaultPrefs, messages: { ...defaultPrefs.messages, agent: false } };
        expect(lineVisible(line("assistant"), prefs)).toBe(false);
        expect(lineVisible(line("tool", "bash"), prefs)).toBe(true);
    });

    it("an unknown tool falls under the 'other' identity", () => {
        const prefs: FilterPrefs = {
            ...defaultPrefs,
            tools: { ...defaultPrefs.tools, other: { visible: false, expanded: false } },
        };
        expect(lineVisible(line("tool", "fetch_url"), prefs)).toBe(false);
    });
});

describe("toolExpanded / lineToolGroup", () => {
    it("opens a tool by default only when its pref says so", () => {
        const prefs: FilterPrefs = {
            ...defaultPrefs,
            tools: { ...defaultPrefs.tools, read: { visible: true, expanded: true } },
        };
        expect(toolExpanded(line("tool", "read"), prefs)).toBe(true);
        expect(toolExpanded(line("tool", "bash"), prefs)).toBe(false);
        expect(toolExpanded(line("assistant"), prefs)).toBe(false);
    });

    it("tags a tool line with its coarse group, null for non-tools", () => {
        expect(lineToolGroup(line("tool", "write"))).toBe("write");
        expect(lineToolGroup(line("tool", "grep"))).toBe("read");
        expect(lineToolGroup(line("tool", "bash"))).toBe("command");
        expect(lineToolGroup(line("assistant"))).toBeNull();
    });
});

describe("isFiltering — funnel 'on' state", () => {
    it("is neutral at defaults and active when additional content is hidden", () => {
        expect(isFiltering(defaultPrefs)).toBe(false);
        expect(isFiltering({ ...defaultPrefs, messages: { ...defaultPrefs.messages, system: true } })).toBe(false);
        expect(isFiltering({ ...defaultPrefs, messages: { ...defaultPrefs.messages, agent: false } })).toBe(true);
        expect(
            isFiltering({ ...defaultPrefs, tools: { ...defaultPrefs.tools, ls: { visible: false, expanded: false } } }),
        ).toBe(true);
    });
});

const store = (v: string | null): Pick<Storage, "getItem"> => ({ getItem: () => v });

describe("loadPrefs — seed from storage, merged over defaults", () => {
    it("returns defaults with no / empty / malformed storage", () => {
        expect(loadPrefs(null)).toEqual(defaultPrefs);
        expect(loadPrefs(store(null))).toEqual(defaultPrefs);
        expect(loadPrefs(store("{not json"))).toEqual(defaultPrefs);
        expect(defaultPrefs.messages.system).toBe(false);
    });

    it("migrates legacy saves to the hidden-system-note baseline", () => {
        const saved = JSON.stringify({
            messages: { agent: false, system: true },
            tools: { grep: { visible: false } },
        });
        const prefs = loadPrefs(store(saved));
        expect(prefs.messages.system).toBe(false);
        expect(prefs.messages.agent).toBe(false);
        expect(prefs.tools.grep.visible).toBe(false);
        expect(prefs.tools.grep.expanded).toBe(false);
        expect(prefs.tools.read).toEqual(defaultPrefs.tools.read);
    });

    it("honors an explicit system-note choice saved under the current schema", () => {
        const saved = JSON.stringify({ version: 2, messages: { system: true } });
        expect(loadPrefs(store(saved)).messages.system).toBe(true);
    });
});

describe("savePrefs — versioned persistence", () => {
    it("marks saves so an explicit system-note choice survives reload", () => {
        let raw = "";
        savePrefs({ setItem: (_key, value) => (raw = value) }, {
            ...defaultPrefs,
            messages: { ...defaultPrefs.messages, system: true },
        });
        expect(JSON.parse(raw)).toMatchObject({ version: 2, messages: { system: true } });
        expect(loadPrefs(store(raw)).messages.system).toBe(true);
    });
});
