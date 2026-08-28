/**
 * The shared **transcript renderer**: the `you / agent` lines and the collapsed
 * tool lines (`▸ {verb} {target} {✓/✗}`) that both the desktop chat pane and the
 * mobile chat carousel-stop show. It is a thin projection of a folded
 * {@link Transcript} (`transcript.ts`) — it owns no truth, it only paints
 * the reduced lines and routes a "open this target" click back to the host.
 *
 * Extracted from the desktop `App.tsx` so the mobile shell (MOB-F2) renders the
 * *same* transcript — same friendly-language mapping, same tool-line expansion —
 * rather than a second, drifting copy.
 */

import { createMemo, createSignal, For, lazy, onMount, Show, Suspense, type JSX } from "solid-js";
import {
    groupTurns,
    reconcileLines,
    reconcileSegments,
    type TranscriptLine,
    type TranscriptSegment,
} from "./transcript";
import {
    defaultPrefs,
    lineToolGroup,
    lineVisible,
    toolExpanded,
    type FilterPrefs,
} from "./transcript-filter";
import { friendlyToolVerb, toolTargetOpensViewer } from "./tool-verb";
import { isBoilerplateResult, partitionedToolTarget, toolDetail, toolHeaderTarget } from "./tool-detail";

// Markdown and its GFM parser load only when conversational prose is present;
// the empty panel and tool/status-only transcripts keep the initial bundle lean.
const MarkdownBody = lazy(() =>
    import("./MarkdownView").then((module) => ({ default: module.MarkdownBody })),
);

/** User and agent prose is Markdown. Operational and lifecycle rows remain
 * literal text so punctuation in commands, errors, and status is never restyled. */
export function lineRendersMarkdown(kind: string): boolean {
    return kind === "user" || kind === "assistant" || kind === "text";
}

/** The public panel may name its assistant; blank or absent values retain the
 * workbench's generic label for existing hosts. */
export function displayAgentName(value?: string): string {
    return value?.trim() || "Agent";
}

/** Translate a lifecycle status line ("run → Completed", "merge → Advanced") into
 *  plain language. These leak the internal state-machine vocabulary; a layperson
 *  should read what happened, not the phase token. The raw text is kept on
 *  `data-line-text` for tests; unknown lines pass through untouched. */
export function friendlyLine(kind: string, text: string): string {
    const phase = (s: string) => s.split("→").pop()?.trim() ?? s;
    if (kind === "run") {
        const p = phase(text).toLowerCase();
        if (p === "completed") return "Finished this turn";
        if (p === "running") return "Working…";
        if (p === "failed") return "This turn didn't finish";
        if (p === "stopped" || p === "aborted") return "Stopped";
        return text;
    }
    if (kind === "merge") {
        const p = phase(text).toLowerCase();
        if (p === "advanced" || p === "integrated") return "Kept into the shared copy";
        if (p === "clean") return "Ready to review";
        if (p === "rejected") return "Discarded";
        return text;
    }
    // Auto-sync lifecycle lines speak plain language and never leak ref vocabulary
    // ("synced from main", "main", "engagement"). Match on the line *kind* only — the
    // old `/\bmain\b/i` text catch-all was too greedy and relabeled a `revert`
    // ("reverted to main — engagement work discarded") as "Pulled in the latest"
    // (WS-H).
    if (kind === "sync") {
        const t = text.toLowerCase();
        if (/no(thing)?\b|up.to.date|already/.test(t)) return "Already up to date — nothing new to pull in";
        const n = text.match(/(\d+)/)?.[1];
        return n ? `Pulled in the latest (${n} change${n === "1" ? "" : "s"})` : "Pulled in the latest";
    }
    if (kind === "revert") return "Discarded the draft — restored to the shared copy";
    if (kind === "error") return `Turn failed — ${text}`;
    return text;
}

/** The collapsed tool line `▸ {friendly verb} {target} {✓/✗}`: clicking the
 *  target opens it in the content viewer; clicking the line expands its args +
 *  result. The verb is plain-language — the raw tool name is kept on `data-tool`
 *  for tests/automation, never shown. */
export function ToolLineView(props: {
    line: TranscriptLine;
    onOpen: (path: string) => void;
    /** Render expanded on first paint (the tool category's "expanded by default"
     *  pref). The reader can still collapse it with the caret. */
    defaultOpen?: boolean;
}): JSX.Element {
    const tool = () => props.line.tool!;
    // The expanded detail is the additive part only: the full command / query, and
    // the call's real output — boilerplate confirmations ("wrote 1 file") stripped.
    const summary = () => toolDetail(tool().name, tool().args).summary;
    const output = () => {
        const r = tool().result;
        return r && !isBoilerplateResult(r) ? r : null;
    };
    // No additive detail ⇒ a tight, non-expandable one-liner (a file write is fully
    // said by "Wrote X ✓"; there is nothing worth a disclosure).
    const hasDetail = () => Boolean(summary() || output());
    // The collapsed line's target: for grep/find this is the pattern, not the
    // directory the server's extraction picked (toolHeaderTarget recovers it).
    const headerTarget = () => toolHeaderTarget(tool().name, tool().args, tool().target);
    const partition = () => headerTarget() ? partitionedToolTarget(headerTarget()!) : null;
    const [open, setOpen] = createSignal(Boolean(props.defaultOpen) && hasDetail());
    const toggle = () => hasDetail() && setOpen((v) => !v);
    const mark = () => {
        const ok = tool().ok;
        return ok === undefined ? "" : ok ? "✓" : "✗";
    };
    return (
        <div
            class={`line ${props.line.tier} tool`}
            data-testid="tool-line"
            data-tool={tool().name}
            data-tool-category={lineToolGroup(props.line) ?? undefined}
        >
            <div class="tool-head" classList={{ expandable: hasDetail() }} onClick={toggle}>
                <span class="tool-caret">{!hasDetail() ? "" : open() ? "▾" : "▸"}</span>
                <span class="tool-name">{friendlyToolVerb(tool().name)}</span>
                <Show when={headerTarget()}>
                    {(target) =>
                        toolTargetOpensViewer(tool().name) ? (
                            // A real file target: a link that opens the content viewer.
                            <button
                                class="tool-target"
                                title="open in the content viewer"
                                onClick={(e) => {
                                    e.stopPropagation();
                                    props.onOpen(target());
                                }}
                            >
                                <Show when={partition()?.targetRoot}>
                                    {(root) => <span class="tool-target-root">Target {root()} · </span>}
                                </Show>
                                {partition()?.relativePath ?? target()}
                            </button>
                        ) : (
                            // A command / query is not navigable: show it as inline
                            // monospace code (one line, ellipsised), never a link. The
                            // full command lives in the expanded detail below.
                            <code class="tool-cmd" title={target()}>
                                {target()}
                            </code>
                        )
                    }
                </Show>
                <span class={`tool-mark ${tool().ok === false ? "bad" : "ok"}`}>{mark()}</span>
            </div>
            <Show when={open() && hasDetail()}>
                <div class="tool-detail">
                    {/* Additive detail only: a plain sentence (the full command /
                        query), never the raw `{"path":…}` arg blob — raw args stay on
                        data-tool-args for tests/automation. */}
                    <Show when={summary()}>
                        {(s) => (
                            <div class="tool-detail-line" data-tool-args={tool().args}>
                                {s()}
                            </div>
                        )}
                    </Show>
                    {/* The call's real output (a command's stdout, a file's contents);
                        bare confirmations like "wrote 1 file" are stripped upstream. */}
                    <Show when={output()}>
                        {(r) => <div class="tool-detail-line tool-result-line">{r()}</div>}
                    </Show>
                </div>
            </Show>
        </div>
    );
}

/** One transcript line, routed by kind: a tool line gets the expandable
 *  {@link ToolLineView} (opened by default per its own category's pref —
 *  command / write / read), everything else a friendly-language row. */
function LineView(props: {
    line: TranscriptLine;
    agentName: string;
    onOpen: (path: string) => void;
    prefs: FilterPrefs;
    /** Fired by the action on a `code: "no_credential"` error line — opens settings. */
    onResolveCredential?: () => void;
    onFork?: (entryId: number, origin?: string) => void;
}): JSX.Element {
    // A model-credential refusal (LLM-1) carries a machine-readable code: render the
    // reason *with* an action into settings, so the user can act from the chat log
    // instead of being left with dead text.
    const isCredentialError = () =>
        props.line.kind === "error" && props.line.code === "no_credential" && !!props.onResolveCredential;
    return (
        <Show
            when={props.line.kind === "tool" && props.line.tool}
            fallback={
                <Show
                    when={isCredentialError()}
                    fallback={
                        <div
                            class={`line ${props.line.tier} ${props.line.kind}`}
                            data-line-text={props.line.text}
                            data-agent-label={props.line.kind === "assistant" ? props.agentName : undefined}
                        >
                            <Show
                                when={lineRendersMarkdown(props.line.kind)}
                                fallback={<span>{friendlyLine(props.line.kind, props.line.text)}</span>}
                            >
                                <Suspense fallback={<span>{friendlyLine(props.line.kind, props.line.text)}</span>}>
                                    <MarkdownBody
                                        class="message-markdown"
                                        text={friendlyLine(props.line.kind, props.line.text)}
                                    />
                                </Suspense>
                            </Show>
                            <Show when={props.line.forkable && props.line.entryId !== undefined && props.onFork}>
                                <button
                                    type="button"
                                    class="line-action fork-action"
                                    data-fork-entry={props.line.entryId}
                                    title={props.line.kind === "user" ? "Fork before this message" : "Fork after this message"}
                                    onClick={() => props.onFork?.(props.line.entryId!, props.line.origin)}
                                >
                                    Fork here
                                </button>
                            </Show>
                        </div>
                    }
                >
                    <div
                        class={`line ${props.line.tier} error credential-error`}
                        data-line-text={props.line.text}
                        data-credential-error
                    >
                        <span>{friendlyLine(props.line.kind, props.line.text)}</span>
                        <button
                            type="button"
                            class="line-action"
                            data-open-account-settings
                            onClick={() => props.onResolveCredential?.()}
                        >
                            Open Account settings
                        </button>
                    </div>
                </Show>
            }
        >
            <ToolLineView line={props.line} onOpen={props.onOpen} defaultOpen={toolExpanded(props.line, props.prefs)} />
        </Show>
    );
}

/** A one-line gist of a collapsed turn: the opening prose (trimmed) and a count
 *  of the tool calls it made, so a folded turn still says what happened. */
function turnSummary(lines: readonly TranscriptLine[]): string {
    const tools = lines.filter((l) => l.kind === "tool").length;
    const firstProse = lines.find((l) => (l.kind === "assistant" || l.kind === "text") && l.text.trim());
    const snippet = firstProse ? firstProse.text.trim().replace(/\s+/g, " ").slice(0, 80) : "";
    const toolPart = tools ? `${tools} tool call${tools === 1 ? "" : "s"}` : "";
    return [snippet, toolPart].filter(Boolean).join(" · ") || "agent turn";
}

/** A folded agent turn: the agent's prose plus the tool calls it made, bracketed
 *  by one accent rail and a header that collapses the whole turn to its gist. */
function TurnView(props: {
    lines: readonly TranscriptLine[];
    agentName: string;
    prefs: FilterPrefs;
    onOpen: (path: string) => void;
    onResolveCredential?: () => void;
    onFork?: (entryId: number, origin?: string) => void;
}): JSX.Element {
    const [collapsed, setCollapsed] = createSignal(false);
    return (
        <div class="turn" classList={{ collapsed: collapsed() }} data-testid="turn">
            <div
                class="turn-head"
                onClick={() => setCollapsed((v) => !v)}
                title={collapsed() ? "Expand this turn" : "Collapse this turn"}
            >
                <span class="turn-caret">{collapsed() ? "▸" : "▾"}</span>
                <span class="turn-label">{props.agentName}</span>
                <Show when={collapsed()}>
                    <span class="turn-summary">{turnSummary(props.lines)}</span>
                </Show>
            </div>
            <Show when={!collapsed()}>
                <div class="turn-body">
                    <For each={props.lines}>
                        {(line) => (
                            <LineView
                                line={line}
                                agentName={props.agentName}
                                onOpen={props.onOpen}
                                prefs={props.prefs}
                                onResolveCredential={props.onResolveCredential}
                                onFork={props.onFork}
                            />
                        )}
                    </For>
                </div>
            </Show>
        </div>
    );
}

/** Render a folded transcript: agent prose + its tool calls bracketed into
 *  collapsible {@link TurnView} turns, your messages / lifecycle notes / errors
 *  standalone. `prefs` filters which event categories show and whether tool
 *  calls open by default. `onOpen(path)` fires when a tool target is clicked.
 *  Empty (after filtering) renders the supplied `fallback`. */
export function TranscriptView(props: {
    lines: readonly TranscriptLine[];
    /** Human-readable assistant name. Defaults to the generic "Agent" label. */
    agentName?: string;
    onOpen: (path: string) => void;
    prefs?: FilterPrefs;
    fallback?: JSX.Element;
    /** Fired by the in-log action on a model-credential refusal (LLM-1) — opens settings. */
    onResolveCredential?: () => void;
    /** Owner-only exact point fork. Omit in audience environments. */
    onFork?: (entryId: number, origin?: string) => void;
}): JSX.Element {
    const prefs = () => props.prefs ?? defaultPrefs;
    const agentName = () => displayAgentName(props.agentName);
    // Rows are keyed by object reference (`For`), but every re-reduction and the
    // settle-time snapshot swap rebuild the whole line list as fresh objects.
    // Reconciling against the previous value keeps identity for everything that
    // did not actually change, so a streaming delta re-renders only the open
    // turn and a turn settling leaves every earlier row's DOM untouched —
    // instead of tearing down and rebuilding the entire transcript.
    const lines = createMemo<readonly TranscriptLine[]>(
        (prev) => reconcileLines(prev, props.lines.filter((l) => lineVisible(l, prefs()))),
        [],
    );
    const segments = createMemo<TranscriptSegment[]>(
        (prev) => reconcileSegments(prev, groupTurns(lines())),
        [],
    );
    // Warm the Markdown chunk before the first prose token needs it: the lazy
    // split keeps tool-only transcripts lean, but resolving it mid-stream swaps
    // the raw-text fallback for rendered Markdown under the reader. An idle
    // prefetch keeps both: a lean first paint and no mid-reply swap.
    onMount(() => {
        const warm = () => void import("./MarkdownView");
        if ("requestIdleCallback" in window) requestIdleCallback(warm);
        else setTimeout(warm, 300);
    });
    // The authoring chat of a segment's first line (ADR 0141): inherited lines
    // carry their origin, the chat's own lines none. A change of origin between
    // consecutive segments is a fork point — mark it, so where inherited
    // history ends is legible in the flow of the transcript. A transcript that
    // *ends* inherited (a fresh fork that has run nothing yet) gets a trailing
    // marker instead: new messages continue from there.
    const segmentOrigin = (seg: TranscriptSegment): string | undefined =>
        seg.type === "turn" ? seg.lines[0]?.origin : seg.line.origin;
    // A factory, not a shared element: each seam needs its own node.
    const forkPointMarker = (): JSX.Element => (
        <div
            class="fork-boundary"
            data-fork-boundary
            title="The history above is inherited from the chat this one was forked from."
        >
            ⑂ fork point
        </div>
    );
    return (
        <>
        <For each={segments()} fallback={props.fallback ?? <div class="status">no activity yet</div>}>
            {(seg, index) => (
                <>
                    <Show
                        when={index() > 0 && segmentOrigin(segments()[index() - 1]) !== segmentOrigin(seg)}
                    >
                        {forkPointMarker()}
                    </Show>
                    {seg.type === "turn" ? (
                        <TurnView
                            lines={seg.lines}
                            agentName={agentName()}
                            prefs={prefs()}
                            onOpen={props.onOpen}
                            onResolveCredential={props.onResolveCredential}
                            onFork={props.onFork}
                        />
                    ) : (
                        <LineView
                            line={seg.line}
                            agentName={agentName()}
                            onOpen={props.onOpen}
                            prefs={prefs()}
                            onResolveCredential={props.onResolveCredential}
                            onFork={props.onFork}
                        />
                    )}
                </>
            )}
        </For>
        <Show
            when={
                segments().length > 0 &&
                segmentOrigin(segments()[segments().length - 1]) !== undefined
            }
        >
            {forkPointMarker()}
        </Show>
        </>
    );
}
