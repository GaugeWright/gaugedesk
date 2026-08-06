/**
 * Translate a raw tool name into a plain verb a layperson can read (#5). The raw
 * name is dev-speak ("bash", "write", "edit"); the UI should say what the agent
 * *did*, not which primitive it called. Unknown tools fall back to a tidy
 * Title-cased label rather than leaking the raw token.
 *
 * Shared between the live transcript (App.tsx) and the plain-language history
 * activity list (audit-activity.ts) so both speak one vocabulary.
 */
/** The distinct tool *identities* the chat log filters on. The seven map onto
 *  the runtime tool set (bash, write, edit, read, ls, grep, find); any other tool
 *  exposed by a package or external capability folds to `other`. Aliases
 *  (str_replace→edit, cat→read, …) normalize so
 *  one filter row governs a tool regardless of which name the runtime emits. */
export type ToolId = "bash" | "write" | "edit" | "read" | "ls" | "grep" | "find" | "other";

/** The coarse group a tool belongs to, used only to organize the filter menu and
 *  tag a line (`data-tool-category`): a shell **command**, a file **write**
 *  (mutation), a file **read** (non-mutating inspection), or **other**. */
export type ToolGroup = "command" | "write" | "read" | "other";

export function toolId(name: string): ToolId {
    const n = name.toLowerCase();
    if (n === "bash" || n === "shell" || n === "exec" || n === "run" || n === "command") return "bash";
    if (n === "write" || n === "create" || n === "writefile") return "write";
    if (n === "edit" || n === "str_replace" || n === "apply_patch") return "edit";
    if (n === "read" || n === "view" || n === "readfile" || n === "cat") return "read";
    if (n === "ls" || n === "list") return "ls";
    if (n === "grep" || n === "search") return "grep";
    if (n === "find") return "find";
    return "other";
}

export function toolGroup(id: ToolId): ToolGroup {
    switch (id) {
        case "bash":
            return "command";
        case "write":
        case "edit":
            return "write";
        case "read":
        case "ls":
        case "grep":
        case "find":
            return "read";
        case "other":
            return "other";
    }
}

export function friendlyToolVerb(name: string): string {
    const n = name.toLowerCase();
    if (n === "write" || n === "create" || n === "writefile") return "Wrote";
    if (n === "edit" || n === "str_replace" || n === "apply_patch") return "Edited";
    if (n === "read" || n === "view" || n === "readfile" || n === "cat") return "Read";
    if (n === "bash" || n === "shell" || n === "exec" || n === "run" || n === "command") return "Ran a command";
    if (n === "search" || n === "grep" || n === "find") return "Searched";
    if (n === "delete" || n === "rm") return "Deleted";
    if (n === "ls" || n === "list") return "Listed files";
    return name.charAt(0).toUpperCase() + name.slice(1);
}

/**
 * The same vocabulary as `friendlyToolVerb`, in the present progressive, for a
 * tool that is running *right now* rather than one already in the transcript.
 * Kept beside its past-tense twin so a tool cannot be phrased one way live and
 * another way in the history.
 */
export function liveToolVerb(name: string): string {
    switch (toolId(name)) {
        case "write":
            return "writing a file";
        case "edit":
            return "editing a file";
        case "read":
            return "reading a file";
        case "bash":
            return "running a command";
        case "grep":
        case "find":
            return "searching";
        case "ls":
            return "listing files";
        case "other":
            return `using ${name}`;
    }
}

/**
 * Whether a tool's `target` is a **file that opens in the content viewer** (so it
 * renders as a clickable link) versus a **command string or query** (which is
 * shown inline as monospace code and is never a link). A shell command is not a
 * navigable target — styling it like one is the bug round-11 #1 fixes.
 */
export function toolTargetOpensViewer(name: string): boolean {
    const n = name.toLowerCase();
    return (
        n === "write" || n === "create" || n === "writefile" ||
        n === "edit" || n === "str_replace" || n === "apply_patch" ||
        n === "read" || n === "view" || n === "readfile" || n === "cat" ||
        n === "delete" || n === "rm" ||
        n === "ls" || n === "list"
    );
}
