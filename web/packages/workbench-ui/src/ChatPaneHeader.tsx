/**
 * Canonical desktop chat-pane header shared by every workbench Environment.
 *
 * The header answers four questions, left to right, and nothing else:
 *
 *   ◆ what kind of chat is this, and what state is it in   → {@link StatusGem}
 *   ▸ which chat is it                                     → the title
 *   ▸ what context does it belong to                       → project / archetype
 *   ▸ which line is it working on, and can we still reach it → workstream + connection
 *
 * **The gem is the state, and it is the same gem the navigation row paints.** The
 * header used to derive its own status badge from its own inputs with its own
 * precedence, so the two surfaces could disagree — and did: the row had an `error`
 * state the header could not express, and showed a red row beside a calm "Ready".
 * Both now render {@link StatusGem} over the same pure {@link gemState} fold, so
 * agreement is structural rather than maintained.
 *
 * Colour never carries the state alone: the gem marks a conflict with `!`, names
 * the state in its tooltip, and this header repeats the state as text for
 * assistive technology and for the run-phase assertions the browser lane makes.
 */
import { Show, type JSX } from "solid-js";
import { PanelCollapseIcon } from "./PanelCollapseIcon";
import { StatusGem, type GemKind } from "./StatusGem";
import { type ChatRunTone } from "./chat-run-state";
import { type FreshnessStatus } from "./desktop-freshness";
import type { ChatTargetMember } from "@gaugewright/control-plane-client";

export interface ChatPaneHeaderProps {
    /** The shell supplies the persistent CHAT label; this is only a selected-chat title. */
    readonly title?: string;
    /** The chat's kind — the gem's glyph, and the row's own root (ADR 0035). */
    readonly kind?: GemKind;
    /** The live run tone feeding the gem, exactly as the navigation row feeds it. */
    readonly tone?: ChatRunTone;
    /** The chat hit a sync conflict (projection, WS-H c) — gem input, not a second flag. */
    readonly conflict?: boolean;
    /** The state as words, for assistive technology and the run-phase lane. */
    readonly statusLabel?: string;
    /** The raw engine phase, carried through for the browser lane's assertions. */
    readonly statusPhase?: string;
    /**
     * What this chat belongs to: its project (work) or its archetype (edit). The
     * Personal project is the catch-all every chat falls back to, so naming it says
     * nothing a reader did not already know — pass an empty value and the slot
     * disappears rather than spending header width on a constant.
     */
    readonly context?: string;
    /** `work` / `edit`, kept on the context slot for the browser lane. */
    readonly contextKind?: string;
    /** The line this chat's work lands on — its workstream, or the default mainline. */
    readonly workstream?: string;
    /** That line's sync state in words, e.g. `up to date`. */
    readonly workstreamState?: string;
    /** Explicit execution scope, separate from the collaboration line. */
    readonly targets?: readonly ChatTargetMember[];
    /**
     * Whether we can still vouch for what is shown (RF-E4). It paints the workstream
     * label rather than the gem: reachability is a property of the line we sync to,
     * not of the chat's own state, and folding it into the gem would force a
     * precedence between two unrelated axes ("unreachable" vs "in conflict").
     */
    readonly connection?: FreshnessStatus;
    readonly mobile: boolean;
    readonly actions?: JSX.Element;
    readonly onCollapse: () => void;
}

const CONNECTION_TITLE: Record<FreshnessStatus, string> = {
    fresh: "in sync with this line",
    stale: "couldn't refresh — showing the last view we could vouch for",
    stuck: "no current view of this line — retry from the banner above",
};

export function ChatPaneHeader(props: ChatPaneHeaderProps): JSX.Element {
    const workstreamTitle = () => {
        const line = props.workstream;
        if (!line) return undefined;
        const sync = props.workstreamState ? `; ${props.workstreamState}` : "";
        return `this chat's work lands on ${line}${sync} — ${CONNECTION_TITLE[props.connection ?? "fresh"]}`;
    };
    return (
        <h2 class="chat-heading">
            <Show when={!props.mobile}>
                <button
                    class="panel-collapse left"
                    data-collapse="run"
                    type="button"
                    title="Hide Chat"
                    aria-label="Hide Chat"
                    onClick={props.onCollapse}
                >
                    <PanelCollapseIcon direction="left" />
                </button>
            </Show>
            <Show when={props.kind}>
                {(kind) => (
                    <span
                        class="chat-state"
                        data-testid="run-phase"
                        data-run-phase={props.statusPhase}
                        data-status={props.statusLabel}
                    >
                        <StatusGem
                            kind={kind()}
                            tone={props.tone}
                            conflict={props.conflict}
                        />
                        {/* The state in words. Visually redundant with the gem's colour,
                            which is the point: colour is never the only carrier. */}
                        <span class="chat-state-label">{props.statusLabel}</span>
                    </span>
                )}
            </Show>
            <Show when={props.title}>
                <span class="chat-title" data-chat-title>{props.title}</span>
            </Show>
            <Show when={props.context}>
                <span
                    class="chat-lineage"
                    data-chat-lineage
                    data-kind={props.contextKind}
                    title={`what this chat belongs to: ${props.context}`}
                >
                    {props.context}
                </span>
            </Show>
            <Show when={props.workstream}>
                <span
                    class="chat-workstream"
                    data-chat-workstream
                    data-connection={props.connection ?? "fresh"}
                    title={workstreamTitle()}
                >
                    <span class="chat-workstream-name">{props.workstream}</span>
                    <Show when={props.workstreamState}>
                        <span class="chat-workstream-state">{props.workstreamState}</span>
                    </Show>
                </span>
            </Show>
            <Show when={(props.targets?.length ?? 0) > 0}>
                <span
                    class="chat-targets"
                    data-chat-targets={props.targets?.length}
                    title="This chat's selected work targets; each retains its own basis and authority"
                >
                    {(props.targets ?? []).map((target) =>
                        `${target.name}${target.participation === "read-only" ? " (read-only)" : ""}`,
                    ).join(" + ")}
                </span>
            </Show>
            {props.actions}
        </h2>
    );
}
