/**
 * The mobile **Carousel island** (`mobile-client.md`, MOB-014): the four desktop
 * panels — `nav · chat · files · content` — shown one at a time on a phone, with
 * the same left→right *broad → deep* order. It is a thin renderer: it owns *no*
 * navigation truth. The pure swipe-depth reducer (MOB-009) decides every
 * transition, the view-derived helpers (MOB-014 `carousel-view`) decide the
 * toggle / peek / gutter paint, and this component only wires Solid signals and
 * DOM events onto them (`navigation.md`: the client renders projections and
 * submits gestures, never a lifecycle transition).
 *
 *   ┌ top toggle:  nav  [ chat ]  files  content ───────────────┐
 *   │ ‹ gutter │            current pane                │ gutter ›│
 *   └────────────────────────────────────────────────────────────┘
 *
 * Each pane is supplied as a render-prop so the island stays projection-agnostic
 * — `MobileFiles` (MOB-015), `MobileContent` (MOB-016), the chat composer
 * (MOB-020) and the nav facet all slot in here without the island knowing their
 * internals. The toggle is the *canonical, labelled* control; the edge gutters
 * are a discoverable shortcut for the same gestures.
 */

import { createMemo, type JSX } from "solid-js";
import { reduce, select as reselect } from "./carousel";
import {
    PANE_LABEL,
    tapGesture,
    toggleSegments,
    type GutterEdge,
} from "./carousel-view";
import {
    type CarouselGesture,
    type CarouselState,
    type PaneKind,
    type Selection,
} from "./mobile-layout";

/** The island is *controlled*: the host owns the {@link CarouselState} signal and
 *  the panes, so the carousel composes with the rest of the shell (top bar,
 *  deep-link resolver) which also read/write that same state. The island routes
 *  gestures back through `onState`, never mutating truth itself. */
export interface CarouselProps {
    /** Current carousel state (which pane is shown + the selection that gates
     *  reachability). The host holds the signal; the island reads it reactively. */
    readonly state: CarouselState;
    /** Apply a reduced state (the host's setter). Every gesture flows through here. */
    readonly onState: (next: CarouselState) => void;
    /** The pane bodies, keyed by pane. Supplied by the host so the island stays
     *  agnostic of each projection (files/content/chat/nav components). */
    readonly panes: Record<PaneKind, JSX.Element>;
    /** Optional environment-specific subset, preserving broad-to-deep order. */
    readonly paneOrder?: readonly PaneKind[];
    /** Optional: start a new chat. When supplied, the **Chat** toggle is always
     *  actionable — if a chat is open it navigates there as usual, but with none
     *  open yet it starts one (same as the nav's "+ new chat") instead of sitting
     *  greyed and inert. Other panes keep their selection-gated reachability. */
    readonly onNewChat?: () => void;
}

export function Carousel(props: CarouselProps): JSX.Element {
    // Route a gesture through the pure reducer; the host owns the resulting truth.
    const apply = (gesture: CarouselGesture) => props.onState(reduce(props.state, gesture));

    const segments = createMemo(() => {
        const admitted = new Set(props.paneOrder ?? ["nav", "chat", "files", "content"]);
        return toggleSegments(props.state).filter((segment) => admitted.has(segment.pane));
    });
    const peek = createMemo(() => {
        const visible = segments();
        const current = visible.findIndex((segment) => segment.current);
        return {
            broader: current > 0 ? visible[current - 1]!.pane : null,
            deeper: current >= 0 && visible[current + 1]?.reachable
                ? visible[current + 1]!.pane
                : null,
        };
    });

    return (
        <div class="carousel" data-pane={props.state.current}>
            <div class="carousel-toggle" role="tablist" aria-label="panes">
                {segments().map((seg) => {
                    // The Chat tab is always actionable when the host supplies
                    // `onNewChat`: navigate to the open chat if there is one, else
                    // start a new chat — never a greyed dead tab.
                    const startsNewChat =
                        seg.pane === "chat" && !seg.reachable && props.onNewChat !== undefined;
                    const enabled = seg.reachable || startsNewChat;
                    return (
                        <button
                            type="button"
                            class="carousel-seg"
                            role="tab"
                            classList={{ current: seg.current, greyed: !enabled }}
                            aria-selected={seg.current}
                            aria-disabled={!enabled}
                            onClick={() =>
                                startsNewChat ? props.onNewChat!() : apply(tapGesture(seg.pane))
                            }
                        >
                            {seg.label}
                        </button>
                    );
                })}
            </div>

            <div class="carousel-stage">
                <EdgeGutter
                    edge="left"
                    peek={peek().broader}
                    onPull={() => peek().broader && apply(tapGesture(peek().broader!))}
                />
                <div class="carousel-pane">{props.panes[props.state.current]}</div>
                <EdgeGutter
                    edge="right"
                    peek={peek().deeper}
                    onPull={() => peek().deeper && apply(tapGesture(peek().deeper!))}
                />
            </div>
        </div>
    );
}

/** A thin screen-edge gutter: a shortcut for the pane switch the toggle also
 *  offers. It only paints a chevron when a neighbour is actually reachable, so
 *  the rail never advertises a no-op swipe (`mobile-client.md`, "Edge gutter").
 *  Interior horizontal drags are *not* captured here — only the gutter — so wide
 *  diffs in Content never fight the carousel. */
function EdgeGutter(props: {
    readonly edge: GutterEdge;
    readonly peek: PaneKind | null;
    readonly onPull: () => void;
}): JSX.Element {
    const chevron = props.edge === "left" ? "‹" : "›";
    // Name the destination pane ("Go to Files") rather than a bare direction
    // ("deeper"/"back") — the gutter is a shortcut to a specific pane, so the
    // label should say which (MOB-F4). Falls back to the direction when no
    // neighbour is reachable (the gutter is inert/hidden then anyway).
    const label = () =>
        props.peek !== null
            ? `Go to ${PANE_LABEL[props.peek]}`
            : props.edge === "left"
              ? "back"
              : "deeper";
    return (
        <button
            type="button"
            class="carousel-gutter"
            classList={{ [props.edge]: true, inert: props.peek === null }}
            aria-label={label()}
            aria-hidden={props.peek === null}
            tabindex={props.peek === null ? -1 : 0}
        onClick={() => props.peek !== null && props.onPull()}
        >
            {props.peek !== null ? chevron : ""}
        </button>
    );
}

/** Re-export the selection repair so a host that changes the *selection* (a chat
 *  opened, a file picked) lands the carousel on a still-reachable pane without
 *  reaching into the reducer module directly. */
export function applySelection(state: CarouselState, selection: Selection): CarouselState {
    return reselect(state, selection);
}
