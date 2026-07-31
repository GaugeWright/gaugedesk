/**
 * The per-row **status gem** (WS-H): a compact kind glyph that doubles as the row's
 * status light. Chats use a robot glyph while its tooltip says whether it is a
 * **work** or **edit** chat; its colour says the single most important *state* — a sync
 * **conflict** to resolve, the agent **working**, a turn that **errored**, or changes
 * waiting for **review**; and a conflict carries a `!` mark.
 *
 * Idle rows show a quiet, uncoloured glyph — information on demand
 * (`experience/README.md`): the gem only lights when there is something to know.
 *
 * The lights fold two sources: the live client run-tone (`working`/`error`/`review`)
 * and the per-chat projection status (`conflict`/`changes`, WS-H b/c). {@link gemState}
 * resolves them with a fixed precedence and is unit-tested.
 */

import { Show, type JSX } from "solid-js";
import { type ChatRunTone, runDotTitle } from "./chat-run-state";
import { Icon } from "./icons";

/** The kind of row a gem sits on — a chat's kind is its root (ADR 0035). */
export type GemKind = "work" | "edit" | "project";

/** The single state the gem paints, most-urgent first (see {@link gemState}). */
export type GemState = "idle" | "working" | "review" | "error" | "conflict";

const KIND_TITLE: Record<GemKind, string> = {
    work: "work chat — uses the method to do the project's work",
    edit: "edit chat — changes what the method itself does",
    project: "project",
};
const STATE_TITLE: Record<GemState, string | null> = {
    idle: null,
    working: runDotTitle("working"),
    review: "this chat has changes waiting for your review",
    error: runDotTitle("error"),
    conflict: "this chat hit a sync conflict — resolve it in the Changes view",
};

/** Fold the row's signals into the single most important state, most-urgent first:
 *  a **conflict** demands resolution; a live turn (working / error) is the most
 *  current fact; a finished turn or pending changes need **review**; else idle. Pure,
 *  so the precedence is unit-tested without rendering. */
export function gemState(opts: {
    readonly tone?: ChatRunTone;
    readonly conflict?: boolean;
    readonly changes?: boolean;
}): GemState {
    if (opts.conflict) return "conflict";
    if (opts.tone === "working") return "working";
    if (opts.tone === "error") return "error";
    if (opts.changes || opts.tone === "review") return "review";
    return "idle";
}

export function StatusGem(props: {
    readonly kind: GemKind;
    /** The row's live run tone (working / review / error); `undefined` = none. */
    readonly tone?: ChatRunTone;
    /** The chat hit a sync/merge conflict being repaired (projection, WS-H c). */
    readonly conflict?: boolean;
    /** The chat has a finished turn's changes awaiting keep (projection, WS-H b). */
    readonly changes?: boolean;
}): JSX.Element {
    const state = () => gemState(props);
    // When the row has a live state, its hover text names it; idle falls back to the
    // kind, so the glyph is never an unexplained mark.
    const title = () => STATE_TITLE[state()] ?? KIND_TITLE[props.kind];
    return (
        <span
            class="status-gem"
            data-kind={props.kind}
            data-state={state()}
            title={title()}
            aria-label={title()}
        >
            <Show
                when={props.kind !== "project"}
                fallback={<span class="status-gem-glyph" aria-hidden="true">▣</span>}
            >
                <Icon name="robot" class="status-gem-glyph" />
            </Show>
            <Show when={state() === "conflict"}>
                <span class="status-gem-mark" data-gem-conflict aria-hidden="true">!</span>
            </Show>
        </span>
    );
}
