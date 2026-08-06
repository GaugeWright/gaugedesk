/**
 * The mobile **Content pane's** view-derived vocabulary (`mobile-client.md`,
 * MOB-016): the small, pure projections the {@link MobileContent} island needs
 * to paint the *payload* of the handle picked in the Files pane (MOB-015). The
 * cardinal rule the Files pane already encodes carries straight through here:
 * **holding a handle is not holding the payload** (`INV-10`, mirrors
 * `gaugedesk_core::resource_access`). The Files pane lists every file by name; this
 * pane renders the *body* — and so it must make every reason a body is *not*
 * shown an **explicit, surfaced state**, never a silent blank.
 *
 * Two orthogonal axes decide what the pane shows:
 *
 *   1. **Access** (`AccessPhase`, reused from `mobile-files`): only a `granted`
 *      handle admits the payload. `init` / `requested` / `revoked` / `denied`
 *      each render their *own* access-denied panel (with the right affordance —
 *      request, wait, re-request, or a terminal explanation) rather than the
 *      content body.
 *   2. **Freshness** (`FreshnessMarker`, from the projection carriage): even a
 *      granted body may be `stale` / `partial` / `redacted` / `indeterminate`,
 *      a caveat that must surface as a banner over the body rather than read as
 *      current truth (mirrors `FreshnessMarker::is_current`, ADR 0037).
 *
 * The island is a thin renderer; every "what may I show, and how do I caption
 * it?" decision lives here as a pure function so it is testable without a DOM
 * (same split as `carousel-view.ts` / `CarouselIsland.tsx`, `mobile-files.ts` /
 * `MobileFiles.tsx`).
 */

import {
    payloadAccessible,
    type AccessPhase,
} from "./mobile-files";
import {
    isCurrent,
    type Freshness,
    type FreshnessMarker,
    type ProjectionCarriage,
} from "@gaugewright/control-plane-client";

// ----- The content the pane may render ----------------------------------------

/** The diff/body payload of a selected handle, as the Content pane consumes it.
 *  The payload is *always* carried inside a {@link ProjectionCarriage} so its
 *  freshness travels with it (a body is never shown as current without a marker,
 *  ADR 0037). The `path` names the handle whose body this is. */
export interface ContentPayload {
    /** The handle whose payload this is (echoed for the header). */
    readonly path: string;
    /** The unified `git diff` text of the engagement-vs-`main` change — the only
     *  truth; there is no client-side diffing (mirrors {@link DiffView}). */
    readonly diff: string;
}

/** What the Content pane is asked to render: the selected handle, its access
 *  phase, and — when access is granted — the carried payload. A `null`
 *  `selection` means nothing is selected yet (the empty pane). */
export interface ContentRequest {
    /** The handle selected in the Files pane, or `null` when none is. */
    readonly selection: SelectedHandle | null;
}

/** The handle the Content pane was asked to show, with its access phase. The
 *  payload carriage is present only when the phase admits it; a non-granted
 *  phase carries `null` (the safe direction is *less* access — the wire never
 *  ships a body the access phase forbids). */
export interface SelectedHandle {
    /** The handle's path/name — always shown, even when the body is withheld. */
    readonly path: string;
    /** The payload-access phase of this handle (mirrors `AccessPhase`). */
    readonly access: AccessPhase;
    /** The carried payload, present only when {@link access} is `granted`. */
    readonly payload: ProjectionCarriage<ContentPayload> | null;
}

// ----- Derived presentation ---------------------------------------------------

/** The kind of panel the Content pane paints. Exactly one is shown at a time. */
export type ContentViewKind =
    /** Nothing selected — invite the user to pick a file. */
    | "empty"
    /** Access is granted: render the diff body (possibly under a freshness caveat). */
    | "body"
    /** Access is withheld: render the matching access-denied panel. */
    | "denied";

/** A fully-derived plan for what the Content pane should render. The island
 *  reads this and paints; it makes no access or freshness decision itself. */
export interface ContentPresentation {
    /** Which panel to paint. */
    readonly kind: ContentViewKind;
    /** The handle's path, or `null` for the empty pane. Always shown when set —
     *  name-visibility survives an access denial (`INV-10`). */
    readonly path: string | null;
    /** The diff body to render, present only for a `body` panel. */
    readonly diff: string | null;
    /** A freshness caveat to surface over a `body` panel, or `null` when the
     *  body is `live` (current) or there is no body. A non-`null` caveat must be
     *  shown — a non-live body is never presented as bare current truth. */
    readonly freshnessCaveat: FreshnessCaveat | null;
    /** The access-denied detail, present only for a `denied` panel. */
    readonly denial: AccessDenial | null;
}

/** A surfaced freshness caveat over a granted body (`stale` / `partial` /
 *  `redacted` / `indeterminate`). `live` bodies carry no caveat. */
export interface FreshnessCaveat {
    readonly marker: FreshnessMarker;
    /** A short, human caption for why the body is not current. */
    readonly label: string;
    /** The affordance describing how to refresh, when the projection offered one. */
    readonly repairHint: string | null;
}

/** The explicit reason a body is withheld, with the affordance that fits. The
 *  whole point of MOB-016: a withheld body is *never* a silent blank — every
 *  non-granted phase has its own captioned panel. */
export interface AccessDenial {
    /** The access phase that withholds the body. */
    readonly phase: AccessPhase;
    /** A short, human caption explaining the denial. */
    readonly label: string;
    /** Whether the user may *request* (or re-request) payload access from here.
     *  True for `init` / `revoked`; false while a request is pending (`requested`)
     *  or after a terminal `denied`. */
    readonly requestable: boolean;
}

/** Human captions for each freshness caveat marker (`live` never captions). */
const FRESHNESS_LABEL: Record<FreshnessMarker, string> = {
    live: "live",
    stale: "showing a stale snapshot — may be behind",
    partial: "partial — material outside scope is omitted",
    redacted: "redacted — some material is hidden by policy",
    indeterminate: "currentness unknown — cannot confirm this is up to date",
};

/** Human captions for each access-denied phase (`granted` is never denied). */
const DENIAL_LABEL: Record<AccessPhase, string> = {
    init: "payload access not requested",
    requested: "access requested — awaiting approval",
    granted: "payload available",
    revoked: "access revoked — request again to view",
    denied: "access denied",
};

/** Derive the freshness caveat for a carried body: `null` when the body is
 *  current (`live`), otherwise the marker, its caption, and any repair hint. */
export function freshnessCaveat(freshness: Freshness): FreshnessCaveat | null {
    if (isCurrent(freshness.marker)) return null;
    return {
        marker: freshness.marker,
        label: FRESHNESS_LABEL[freshness.marker],
        repairHint: freshness.repairHint,
    };
}

/** Derive the access-denial panel for a non-granted phase. `init` and `revoked`
 *  are requestable (you may ask for the payload); a pending `requested` and a
 *  terminal `denied` are not. */
export function accessDenial(phase: AccessPhase): AccessDenial {
    const requestable = phase === "init" || phase === "revoked";
    return { phase, label: DENIAL_LABEL[phase], requestable };
}

/** The whole derivation: from the selected handle (or none) to the panel the
 *  Content pane paints. Access is decided first (a withheld body is never shown
 *  under any freshness); only a granted handle with a carried payload reaches
 *  the body panel, where its freshness caveat (if any) is surfaced. */
export function presentContent(req: ContentRequest): ContentPresentation {
    const sel = req.selection;
    if (sel === null) {
        return { kind: "empty", path: null, diff: null, freshnessCaveat: null, denial: null };
    }

    // Access gates the body. A non-granted phase — or a granted phase whose
    // payload the wire did not carry — yields the matching denied panel, never a
    // silent blank (the safe direction is less access).
    if (!payloadAccessible(sel.access) || sel.payload === null) {
        const phase: AccessPhase = payloadAccessible(sel.access) ? "init" : sel.access;
        return {
            kind: "denied",
            path: sel.path,
            diff: null,
            freshnessCaveat: null,
            denial: accessDenial(phase),
        };
    }

    // Granted and carried: render the body, surfacing any freshness caveat.
    return {
        kind: "body",
        path: sel.path,
        diff: sel.payload.value.diff,
        freshnessCaveat: freshnessCaveat(sel.payload.freshness),
        denial: null,
    };
}
