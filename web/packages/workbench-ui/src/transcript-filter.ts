/**
 * View preferences for the transcript: which event types are shown, and whether a
 * tool call opens expanded by default. This is **pure view state**, not domain
 * truth (the transcript is the server's reduction — `transcript.ts`); these prefs
 * only decide how a reader paints it. Persisted to localStorage so a reader's
 * filter choices survive a reload.
 *
 * Two axes:
 *  - **message categories** — your messages, agent messages, blocked effects,
 *    system notes, errors — each shown or hidden.
 *  - **tools** — each tool ({@link ToolId}) shown/hidden individually and given
 *    its own expand-by-default, organized in the menu under coarse groups.
 */

import { type TranscriptLine } from "./transcript";
import { toolGroup, toolId, type ToolGroup, type ToolId } from "./tool-verb";

/** A non-tool line's filter category. Lifecycle kinds (run/merge/sync/clean/
 *  revert) and any other admitted kind fold into "system". */
export type MessageCategory = "user" | "agent" | "blocked" | "system" | "error";

export function messageCategoryOf(kind: string): MessageCategory {
    switch (kind) {
        case "user":
            return "user";
        case "assistant":
        case "text":
            return "agent";
        case "blocked":
            return "blocked";
        case "error":
            return "error";
        default:
            return "system";
    }
}

export interface ToolPref {
    /** Hidden tools are filtered out of the rendered transcript. */
    readonly visible: boolean;
    /** Render this tool's calls open by default (only some carry detail). */
    readonly expanded: boolean;
}

export interface FilterPrefs {
    readonly messages: Record<MessageCategory, boolean>;
    readonly tools: Record<ToolId, ToolPref>;
}

/** The message rows shown above the tools in the menu, in order. */
export const MESSAGE_LEAD: readonly { id: MessageCategory; label: string }[] = [
    { id: "user", label: "Your messages" },
    { id: "agent", label: "Agent messages" },
];

/** The message rows shown below the tools in the menu, in order. */
export const MESSAGE_TAIL: readonly { id: MessageCategory; label: string }[] = [
    { id: "blocked", label: "Blocked effects" },
    { id: "system", label: "System notes" },
    { id: "error", label: "Errors" },
];

/** The tool menu, grouped. Each group is a toggle over its tools; each tool is an
 *  individually filterable row. `expandable` flags a tool whose calls can reveal
 *  detail (so the "open by default" control is offered). */
export const TOOL_GROUPS: readonly {
    group: ToolGroup;
    label: string;
    tools: readonly { id: ToolId; label: string; expandable: boolean }[];
}[] = [
    { group: "command", label: "Commands", tools: [{ id: "bash", label: "Run command", expandable: true }] },
    {
        group: "write",
        label: "File writes",
        tools: [
            { id: "write", label: "Write file", expandable: false },
            { id: "edit", label: "Edit file", expandable: false },
        ],
    },
    {
        group: "read",
        label: "File reads",
        tools: [
            { id: "read", label: "Read file", expandable: true },
            { id: "ls", label: "List files", expandable: false },
            { id: "grep", label: "Search (grep)", expandable: true },
            { id: "find", label: "Find files", expandable: true },
        ],
    },
    { group: "other", label: "Other tools", tools: [{ id: "other", label: "Plugin / MCP tools", expandable: true }] },
];

const MESSAGE_IDS: readonly MessageCategory[] = ["user", "agent", "blocked", "system", "error"];
export const TOOL_IDS: readonly ToolId[] = ["bash", "write", "edit", "read", "ls", "grep", "find", "other"];

export const defaultPrefs: FilterPrefs = {
    messages: { user: true, agent: true, blocked: true, system: false, error: true },
    tools: {
        bash: { visible: true, expanded: false },
        write: { visible: true, expanded: false },
        edit: { visible: true, expanded: false },
        read: { visible: true, expanded: false },
        ls: { visible: true, expanded: false },
        grep: { visible: true, expanded: false },
        find: { visible: true, expanded: false },
        other: { visible: true, expanded: false },
    },
};

/** Is a line visible under the given prefs? Tool lines key on the tool's identity,
 *  every other line on its message category. */
export function lineVisible(line: TranscriptLine, prefs: FilterPrefs): boolean {
    if (line.kind === "tool" && line.tool) return prefs.tools[toolId(line.tool.name)].visible;
    return prefs.messages[messageCategoryOf(line.kind)];
}

/** Should this line render expanded by default? Only tool lines can. */
export function toolExpanded(line: TranscriptLine, prefs: FilterPrefs): boolean {
    return line.kind === "tool" && line.tool ? prefs.tools[toolId(line.tool.name)].expanded : false;
}

/** The coarse group tag for a tool line, for `data-tool-category` / styling. */
export function lineToolGroup(line: TranscriptLine): ToolGroup | null {
    return line.kind === "tool" && line.tool ? toolGroup(toolId(line.tool.name)) : null;
}

/** True when the reader hides anything that is visible in the product defaults.
 *  System notes start hidden, so that baseline alone does not light the funnel. */
export function isFiltering(prefs: FilterPrefs): boolean {
    return (
        MESSAGE_IDS.some((m) => defaultPrefs.messages[m] && !prefs.messages[m]) ||
        TOOL_IDS.some((t) => !prefs.tools[t].visible)
    );
}

const STORAGE_KEY = "ui.transcript-filter";
const STORAGE_VERSION = 2;

/** Load prefs from storage, each field merged over the defaults so a message
 *  category or tool added after the blob was written is always present
 *  (forward-compatible with a partial / older save). Pure given its storage. */
export function loadPrefs(storage: Pick<Storage, "getItem"> | null): FilterPrefs {
    try {
        const raw = storage?.getItem(STORAGE_KEY);
        if (!raw) return defaultPrefs;
        const saved = JSON.parse(raw) as {
            version?: number;
            messages?: Partial<Record<MessageCategory, boolean>>;
            tools?: Partial<Record<ToolId, Partial<ToolPref>>>;
        };
        const messages = { ...defaultPrefs.messages };
        for (const id of MESSAGE_IDS) {
            // Version 1 wrote every checkbox, so it cannot distinguish the old
            // system:true factory value from an intentional choice. Migrate that
            // category to the quieter baseline; subsequent explicit saves are v2.
            if (id === "system" && saved.version !== STORAGE_VERSION) continue;
            if (typeof saved.messages?.[id] === "boolean") messages[id] = saved.messages[id] as boolean;
        }
        const tools = {} as Record<ToolId, ToolPref>;
        for (const id of TOOL_IDS) {
            tools[id] = { ...defaultPrefs.tools[id], ...saved.tools?.[id] };
        }
        return { messages, tools };
    } catch {
        return defaultPrefs;
    }
}

/** Persist prefs. A storage failure (full / unavailable) is swallowed — the prefs
 *  are session-only this run, acceptable for view state. */
export function savePrefs(storage: Pick<Storage, "setItem"> | null, prefs: FilterPrefs): void {
    try {
        storage?.setItem(STORAGE_KEY, JSON.stringify({ version: STORAGE_VERSION, ...prefs }));
    } catch {
        // storage unavailable → prefs are session-only this run
    }
}
