/**
 * The live transcript is a **client reduction of the server event stream**
 * (`app-stack.md`), not client-owned truth. It is repairable from a snapshot:
 * replaying the same events from empty yields the same transcript, so a dropped
 * connection recovers by re-fetching and re-reducing.
 *
 * Two tiers (the B4 run/chat doctrine):
 *  - **operational** lines stream live (tokens, tool calls) for liveness;
 *  - **admitted** lines are run truth the server's lifecycle has admitted.
 * The UI must not show operational lines as admitted truth.
 */

import type { StreamEvent } from "@gaugewright/control-plane-client";

export type { StreamEvent } from "@gaugewright/control-plane-client";

export type Tier = "operational" | "admitted";

export interface TranscriptLine {
    readonly seq: number;
    readonly tier: Tier;
    readonly kind: string;
    readonly text: string;
    /** Machine-readable failure code (e.g. `"no_credential"`) on a `kind: "error"`
     *  line, so the view can render an action (link into settings) rather than text. */
    readonly code?: string;
    /** Stable durable-store entry backing a reproducible user/assistant fork. */
    readonly entryId?: number;
    readonly forkable?: boolean;
    /** The authoring chat of an inherited line (ADR 0141): a fork's transcript
     *  carries its lineage prefix by reference, and entry ids are scoped to
     *  their authoring chat — so a fork at this line targets `origin`. Absent
     *  on the chat's own lines. */
    readonly origin?: string;
    /** Tool-line metadata (B4): target opens the content viewer; args/result expand. */
    readonly tool?: ToolLine;
}

/** The structured tool line behind a `kind: "tool"` entry. */
export interface ToolLine {
    readonly name: string;
    readonly callId?: string;
    readonly target?: string;
    readonly args?: string;
    /** Filled in when the matching `toolresult` arrives. */
    readonly ok?: boolean;
    readonly result?: string;
}

export interface Transcript {
    readonly lines: readonly TranscriptLine[];
    /** Open operational text line being appended to, if any. */
    readonly openText: number | null;
}

export const empty: Transcript = { lines: [], openText: null };

/** Pure reduction: (transcript, event) -> transcript. Order-deterministic. */
export function reduce(t: Transcript, ev: StreamEvent): Transcript {
    const seq = t.lines.length;
    switch (ev.type) {
        case "user": {
            const line: TranscriptLine = {
                seq, tier: "admitted", kind: "user", text: ev.text,
                entryId: ev.entry_id, forkable: ev.forkable, origin: ev.origin,
            };
            return { lines: [...t.lines, line], openText: null };
        }
        case "assistant": {
            // A turn can end with no user-visible prose (the durable Assistant
            // record exists regardless — it anchors the turn boundary). Admit
            // nothing rather than a blank bubble, but still close the open
            // operational line: the turn is over.
            if (ev.text.trim() === "") {
                return { lines: t.lines, openText: null };
            }
            const line: TranscriptLine = {
                seq, tier: "admitted", kind: "assistant", text: ev.text,
                entryId: ev.entry_id, forkable: ev.forkable, origin: ev.origin,
            };
            return { lines: [...t.lines, line], openText: null };
        }
        case "text": {
            // Coalesce streamed deltas into the currently-open operational line.
            if (t.openText !== null) {
                const lines = t.lines.map((l) =>
                    l.seq === t.openText ? { ...l, text: l.text + ev.delta } : l,
                );
                return { lines, openText: t.openText };
            }
            const line: TranscriptLine = { seq, tier: "operational", kind: "text", text: ev.delta };
            return { lines: [...t.lines, line], openText: seq };
        }
        case "tool": {
            // The collapsed B4 tool line: `▸ {tool} {target}` (✓/✗ fills in on result).
            const tool: ToolLine = {
                name: ev.tool,
                callId: ev.call_id,
                target: ev.target,
                args: ev.args,
            };
            const text = `▸ ${ev.tool}${ev.target ? ` ${ev.target}` : ""}`;
            const line: TranscriptLine = {
                seq, tier: "operational", kind: "tool", text, tool, origin: ev.origin,
            };
            return { lines: [...t.lines, line], openText: null };
        }
        case "toolresult": {
            // Correlate to the most recent matching tool line; fill in ✓/✗ + output.
            let matched = false;
            const lines = t.lines
                .slice()
                .reverse()
                .map((l) => {
                    if (!matched && l.kind === "tool" && l.tool?.callId === ev.call_id) {
                        matched = true;
                        return { ...l, tool: { ...l.tool!, ok: ev.ok, result: ev.result } };
                    }
                    return l;
                })
                .reverse();
            return { lines, openText: t.openText };
        }
        case "blocked": {
            const line: TranscriptLine = {
                seq,
                tier: "operational",
                kind: "blocked",
                text: `⨯ ${ev.tool}${ev.reason ? `: ${ev.reason}` : ""}`,
                origin: ev.origin,
            };
            return { lines: [...t.lines, line], openText: null };
        }
        case "error": {
            // A failed turn's reason, shown as an admitted-tier line so it survives a
            // reload and reads as durable truth (run-chat.md "Message attachments").
            const line: TranscriptLine = {
                seq, tier: "admitted", kind: "error", text: ev.reason, code: ev.code, origin: ev.origin,
            };
            return { lines: [...t.lines, line], openText: null };
        }
        case "admitted": {
            const line: TranscriptLine = {
                seq, tier: "admitted", kind: ev.kind, text: ev.text, origin: ev.origin,
            };
            return { lines: [...t.lines, line], openText: null };
        }
    }
}

/** Rebuild a transcript from a snapshot of events (connection repair). */
export function fromSnapshot(events: readonly StreamEvent[]): Transcript {
    return events.reduce(reduce, empty);
}

/** Rebuild the live optimistic tier after snapshot repair while a user command is
 * still pending. A just-settled run can return before its admitted user event is
 * visible through the transcript projection; clearing `live` in that window makes
 * the message disappear even though the command is running. `baselineLines` is the
 * durable snapshot length when the command began, so an identical older message
 * cannot be mistaken for this command's admission. */
export function pendingUserAfterSnapshot(
    repaired: Transcript,
    text: string,
    baselineLines: number,
): Transcript {
    const admitted = repaired.lines
        .slice(Math.max(0, baselineLines))
        .some((line) => line.kind === "user" && line.text === text);
    return admitted ? empty : reduce(empty, { type: "user", text });
}

/** A presentation segment: a run of agent-produced lines folded into one
 *  collapsible **turn**, or a single standalone line (your message, a lifecycle
 *  note, an error). A turn's `id` is the seq of its first line — stable as the
 *  turn streams, so a collapsed turn stays collapsed while more lines arrive. */
export type TranscriptSegment =
    | { readonly type: "turn"; readonly id: number; readonly lines: readonly TranscriptLine[] }
    | { readonly type: "line"; readonly line: TranscriptLine };

/** The line kinds that belong to one agent turn — the agent's prose plus the
 *  tool calls / blocked effects it made answering the last message. Everything
 *  else (`user`, the run/merge/sync lifecycle notes, an `error`) stands alone. */
const AGENT_TURN_KINDS: ReadonlySet<string> = new Set(["assistant", "text", "tool", "blocked"]);

/** Presentation-only fold of the flat line list into turn segments. Pure and
 *  order-preserving: a maximal run of consecutive agent lines becomes one turn,
 *  every other line passes through standalone. (The transcript itself stays the
 *  flat server reduction — this is a view of it, owned by no one.) */
export function groupTurns(lines: readonly TranscriptLine[]): TranscriptSegment[] {
    const segments: TranscriptSegment[] = [];
    let turn: TranscriptLine[] | null = null;
    const flush = () => {
        if (turn && turn.length > 0) segments.push({ type: "turn", id: turn[0].seq, lines: turn });
        turn = null;
    };
    for (const line of lines) {
        if (AGENT_TURN_KINDS.has(line.kind)) {
            (turn ??= []).push(line);
        } else {
            flush();
            segments.push({ type: "line", line });
        }
    }
    flush();
    return segments;
}
