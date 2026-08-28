/**
 * Plain-language rendering of an expanded tool-call detail (round-8 #4).
 *
 * The collapsed transcript line already speaks plain language ("Wrote
 * agent-note.txt"), but expanding it (the ▸ disclosure) used to reveal the raw
 * argument blob — `{"path":"agent-note.txt"}` — i.e. the exact serialized-JSON
 * dev-speak (MEMORY #10) earlier rounds scrubbed from the *headers*, just
 * relocated one level down. Progressive disclosure (#8) should reveal more
 * *understanding*, not a machine parameter object.
 *
 * This pure reducer turns a tool name + its raw JSON args into a short, human
 * sentence ("Saved the file agent-note.txt", "Ran: echo hi"). It is deliberately
 * conservative: if it can't confidently parse the args into something friendlier,
 * it returns `null` and the caller shows nothing rather than leaking raw JSON.
 */

export interface ToolDetail {
    /** A plain sentence describing what the call did, or null if not parseable. */
    readonly summary: string | null;
}

/** Pull the most relevant string field out of a parsed args object. */
function firstString(obj: Record<string, unknown>, keys: readonly string[]): string | null {
    for (const k of keys) {
        const v = obj[k];
        if (typeof v === "string" && v.trim()) return v.trim();
    }
    return null;
}

/** Parse a tool call's raw JSON args into a plain object, or null when it is
 *  absent / empty / not a JSON object. Never throws. */
function parseArgs(rawArgs: string | undefined): Record<string, unknown> | null {
    const raw = (rawArgs ?? "").trim();
    if (!raw || raw === "{}") return null;
    let parsed: unknown;
    try {
        parsed = JSON.parse(raw);
    } catch {
        return null;
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    return parsed as Record<string, unknown>;
}

const COMMAND_TOOLS = ["bash", "shell", "exec", "run", "command"] as const;
const SEARCH_TOOLS = ["grep", "find", "search"] as const;

/**
 * Translate `(toolName, rawArgsJson)` into a plain sentence. Never throws.
 * Returns `{ summary: null }` when there is nothing *additive* to show — the
 * collapsed line (verb + target) already names the file / search pattern, so the
 * only tool that gains an expanded sentence is a command, whose full text the
 * header truncates to a one-line chip.
 */
export function toolDetail(name: string, rawArgs: string | undefined): ToolDetail {
    const n = (name ?? "").toLowerCase();
    const obj = parseArgs(rawArgs);
    if (!obj) return { summary: null };

    if ((COMMAND_TOOLS as readonly string[]).includes(n)) {
        const cmd = firstString(obj, ["command", "cmd", "script", "input"]);
        return { summary: cmd ? `Ran: ${cmd}` : null };
    }

    // Every other tool (file writes/reads/deletes, listings, searches, unknowns):
    // the collapsed header already says it — no additive sentence to show.
    return { summary: null };
}

/**
 * The string shown after the verb in the **collapsed** tool line. For a search
 * tool (`grep`/`find`) the reader wants the **pattern**, not the directory the
 * search ran in — but the server's target extraction picks `path` before
 * `pattern`, so it hands us the directory. Recover the pattern from the args
 * here. Every other tool keeps the server-provided target (a file path, a
 * command); falls back to it when the args carry no pattern.
 */
export function toolHeaderTarget(
    name: string,
    rawArgs: string | undefined,
    serverTarget: string | undefined,
): string | undefined {
    const n = (name ?? "").toLowerCase();
    if ((SEARCH_TOOLS as readonly string[]).includes(n)) {
        const obj = parseArgs(rawArgs);
        const pattern = obj && firstString(obj, ["pattern", "query", "q", "search"]);
        if (pattern) return pattern;
    }
    return serverTarget || undefined;
}

export function partitionedToolTarget(target: string): { targetRoot: string | null; relativePath: string } {
    const match = target.match(/^targets\/([^/]+)\/(.+)$/);
    return match
        ? { targetRoot: match[1], relativePath: match[2] }
        : { targetRoot: null, relativePath: target };
}

/** Tool result text that merely confirms the action — "wrote 1 file", "File
 *  created successfully", a bare "ok" — restating what the ✓ and the header
 *  already say. The expanded detail strips these so a disclosure reveals real
 *  output (a command's stdout, a file's contents), not boilerplate. Empty /
 *  whitespace results are boilerplate too (nothing to show). */
const BOILERPLATE_RESULT: readonly RegExp[] = [
    /^wrote\s+\d+\s+files?\b/i,
    /^\d+\s+files?\s+(written|created|updated|changed|saved)\b/i,
    /^(successfully\s+)?(wrote|created|updated|saved|edited|written|deleted|removed|applied)\b/i,
    /^file\s+(was\s+)?(written|created|updated|saved|edited|deleted|removed)\b/i,
    /\bhas\s+been\s+(written|created|updated|saved|edited|deleted|removed)\b/i,
    /^applied\s+\d+\s+(edit|change|diff|hunk)s?\b/i,
    /^(ok|okay|done|success|succeeded|completed?|no\s+changes?|no\s+output)\.?$/i,
];

export function isBoilerplateResult(result: string | undefined): boolean {
    const t = (result ?? "").trim();
    if (!t) return true;
    return BOILERPLATE_RESULT.some((re) => re.test(t));
}
