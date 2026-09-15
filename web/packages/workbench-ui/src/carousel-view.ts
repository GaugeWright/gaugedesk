/**
 * The carousel island's **view-derived vocabulary** (`mobile-client.md`,
 * MOB-014): the small, pure projections the {@link Carousel} island needs to
 * paint itself — the labelled top toggle, the screen-edge peek neighbours, and
 * the gutter→gesture mapping. None of these are *navigation truth* (that lives
 * in the reducer, MOB-009); they are pure functions of the current
 * {@link CarouselState}, kept here so the island stays a thin renderer and this
 * layer is testable without a DOM (`navigation.md`: the client owns no
 * lifecycle, and here the view owns no navigation either).
 */

import { paneVisibility, isReachable } from "./carousel";
import {
    PANE_ORDER,
    paneDepth,
    type CarouselGesture,
    type CarouselState,
    type PaneKind,
} from "./mobile-layout";

// ----- Top toggle ------------------------------------------------------------

/** One segment of the labelled pane toggle (the *canonical* control —
 *  `mobile-client.md`, "the top toggle is the canonical, labelled control").
 *  `current` boxes the segment on screen; `reachable=false` greys it out for the
 *  current selection (tapping it is a reducer no-op, never a dead-end). */
export interface ToggleSegment {
    readonly pane: PaneKind;
    readonly label: string;
    readonly current: boolean;
    readonly reachable: boolean;
}

/** Human labels for the toggle, in canonical broad→deep order. The desktop
 *  panels read on mobile as `Browse · Chat · Files · Content`. (The `nav` key is
 *  the internal pane token; the user-facing word is **Browse** — the browse pane.) */
export const PANE_LABEL: Record<PaneKind, string> = {
    nav: "Browse",
    chat: "Chat",
    files: "Files",
    content: "Content",
};

/** The pane toggle for a state: every pane in canonical order, each tagged
 *  current/reachable so the island can box the active one and grey the rest. */
export function toggleSegments(
    state: CarouselState,
    labels: Partial<Record<PaneKind, string>> = {},
): ToggleSegment[] {
    const visibility = paneVisibility(state.selection);
    return PANE_ORDER.map((pane) => ({
        pane,
        label: labels[pane] ?? PANE_LABEL[pane],
        current: pane === state.current,
        reachable: visibility[pane],
    }));
}

// ----- Edge peek -------------------------------------------------------------

/** The neighbours that "peek" at the screen edges (`mobile-client.md`, "Peek").
 *  `broader` sits to the right edge (swipe-right target), `deeper` to the left
 *  edge (swipe-left target). A neighbour is shown only when it actually exists
 *  *and is reachable* — we never advertise a swipe that the reducer would no-op,
 *  so the chevron rails never lie. */
export interface PeekNeighbours {
    /** The pane one step broader (swipe-right lands here), or `null` at `nav`. */
    readonly broader: PaneKind | null;
    /** The pane one step deeper (swipe-left lands here), or `null` if the next
     *  pane does not exist or is greyed for the current selection. */
    readonly deeper: PaneKind | null;
}

export function peekNeighbours(state: CarouselState): PeekNeighbours {
    const depth = paneDepth(state.current);
    const broaderPane = PANE_ORDER[depth - 1];
    const deeperPane = PANE_ORDER[depth + 1];
    return {
        broader: broaderPane ?? null,
        deeper:
            deeperPane !== undefined && isReachable(deeperPane, state.selection)
                ? deeperPane
                : null,
    };
}

// ----- Gutter → gesture ------------------------------------------------------

/** Which screen-edge gutter the user pulled. The gutters are a *shortcut* for
 *  the canonical toggle; left-edge goes broader (back), right-edge goes deeper,
 *  matching iOS edge-swipe-back / the Android back button which both pop one
 *  pane rightward (`mobile-client.md`, "Edge gutter"). */
export type GutterEdge = "left" | "right";

/** Map a gutter pull to the carousel gesture it stands for. The left edge is
 *  back/broader (`swipe-right` in depth terms); the right edge is deeper
 *  (`swipe-left`). Reachability is still the reducer's call — an unreachable
 *  swipe is simply a no-op there. */
export function gutterGesture(edge: GutterEdge): CarouselGesture {
    return edge === "left" ? { kind: "swipe-right" } : { kind: "swipe-left" };
}

/** A tap on a toggle segment is a `tap` gesture to that pane (honoured by the
 *  reducer only when the target is reachable). */
export function tapGesture(pane: PaneKind): CarouselGesture {
    return { kind: "tap", target: pane };
}
