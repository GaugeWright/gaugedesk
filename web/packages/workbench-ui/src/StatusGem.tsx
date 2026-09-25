/**
 * The per-row **status gem** (WS-H): a compact type or structural glyph with a
 * top-right status dot and a bottom-right authoring mark. Colour says the
 * single most important *state* — a sync
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
import { Icon, type IconName } from "./icons";

/** The kind of row a gem sits on — a chat's kind is its root (ADR 0035). */
export type GemKind = "work" | "edit" | "management" | "project";

/** The single state the gem paints, most-urgent first (see {@link gemState}). */
export type GemState = "idle" | "working" | "review" | "error" | "conflict";

const KIND_TITLE: Record<GemKind, string> = {
    work: "work chat — uses an Agent to do the project's work",
    edit: "authoring chat — changes what the Agent does",
    management: "management chat — helps manage this account or organization",
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
 *  current fact; a chat with an open ask needs **review**; else idle. Pure, so the
 *  precedence is unit-tested without rendering.
 *
 *  The run tone is the only source of "review" now. It used to be joined by a
 *  `changes` projection flag reporting a clean candidate held for per-change
 *  review; ADR 0136 retired the hold, so that flag could only ever be false. */
export function gemState(opts: {
    readonly tone?: ChatRunTone;
    readonly conflict?: boolean;
}): GemState {
    if (opts.conflict) return "conflict";
    if (opts.tone === "working") return "working";
    if (opts.tone === "error") return "error";
    if (opts.tone === "review") return "review";
    return "idle";
}

export function StatusGem(props: {
    readonly kind: GemKind;
    /** The type icon in a flat lens, or connector when the Agent parent is visible. */
    readonly base?: Extract<IconName, "chat-bubble" | "panel" | "child-connector">;
    /** The row's live run tone (working / review / error); `undefined` = none. */
    readonly tone?: ChatRunTone;
    /** The chat hit a sync/merge conflict being repaired (projection, WS-H c). */
    readonly conflict?: boolean;
}): JSX.Element {
    const state = () => gemState(props);
    // When the row has a live state, its hover text names it; idle falls back to the
    // kind, so the glyph is never an unexplained mark.
    const title = () => [KIND_TITLE[props.kind], STATE_TITLE[state()]].filter(Boolean).join(" · ");
    return (
        <span
            class="status-gem"
            data-kind={props.kind}
            data-state={state()}
            title={title()}
            aria-label={title()}
        >
            <Icon name={props.base ?? "chat-bubble"} class="status-gem-glyph" />
            <Show when={props.kind === "edit"}>
                <Icon name="page-edit" class="status-gem-corner" />
            </Show>
            <Show when={state() !== "idle"}>
                <span class="status-gem-dot" data-gem-state={state()} aria-hidden="true" />
            </Show>
        </span>
    );
}
