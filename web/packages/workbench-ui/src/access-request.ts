/**
 * The mobile **access-request flow** (`mobile-client.md`, MOB-030): the pure
 * state machine the {@link AccessRequestPanel} island reduces over when a user
 * asks for the *payload* behind a withheld handle in the Content pane (MOB-016).
 * It is where `INV-10` becomes an *action*: the Files pane shows a handle's name
 * and the Content pane refuses its body until access is granted; this flow is the
 * affordance that turns that refusal into a request the owner can approve.
 *
 * The vocabulary is the one the rest of the mobile client already speaks — the
 * payload-access {@link AccessPhase} (`mobile-files.ts`, mirroring
 * `gaugedesk_core::resource_access::AccessPhase`). A request walks the same arc the
 * core reducer walks server-side: `init` (no ask) → the user submits → `requested`
 * (awaiting the owner's approval) → the owner answers → `granted` (the body is now
 * admitted), `denied` (terminal refusal), or — if a prior grant was withdrawn —
 * `revoked`. The flow never manufactures the granted fact: it is `granted` only
 * once the server's resource-access state says so (mirrors the pairing flow's
 * `paired ⇔ Active` discipline, `pairing.ts`; `principles.md`, `INV-5`).
 *
 * Like the rest of the mobile client (`mobile-content.ts`, `connection.ts`,
 * `pairing.ts`) this is a thin, DOM-free pure layer: every "what may the user do,
 * and what do we show?" decision is a pure function here, and the
 * {@link AccessRequestPanel} island only wires Solid signals and DOM events onto
 * it. The transport (the actual `request payload access` command to the owner) is
 * the host's; this module decides nothing about the network beyond folding the
 * phase it is handed.
 *
 * The optimistic-reconcile correlation id (`ClientRequestId`, MOB-003) travels
 * with a pending ask so the host can retire the optimistic `requested` entry when
 * the resource-access projection that answers it lands.
 */

import { type AccessPhase, payloadAccessible } from "./mobile-files";
import { type ClientRequestId } from "@gaugewright/control-plane-client";

// ----- Flow state -------------------------------------------------------------

/** The access-request flow's state for a single withheld handle. The `phase`
 *  mirrors the server's payload-access phase for this handle (the truth the owner
 *  controls); `requestId` correlates a still-in-flight optimistic ask with the
 *  projection that retires it (MOB-003), and is `null` once no ask is pending. */
export interface AccessRequestState {
    /** The handle the user is asking for the payload of (echoed for the header). */
    readonly path: string;
    /** The server-mirrored payload-access phase of this handle. */
    readonly phase: AccessPhase;
    /** The optimistic correlation id of a request still in flight, else `null`.
     *  Set only while `phase === "requested"` from a local submit; the host clears
     *  it once the answering resource-access projection lands. */
    readonly requestId: ClientRequestId | null;
}

/** A freshly opened flow for a handle at the given phase, with no ask in flight. */
export function initialAccessRequest(path: string, phase: AccessPhase): AccessRequestState {
    return { path, phase, requestId: null };
}

// ----- Derivation (the pure heart) -------------------------------------------

/** What the access-request panel should show and enable for a handle. The island
 *  reads this and paints; it makes no phase decision itself (same split as
 *  `mobile-content`'s `presentContent` and `pairing`'s `presentPairing`). */
export interface AccessRequestPresentation {
    /** The handle this panel is about — always shown (name-visibility survives a
     *  denial, `INV-10`). */
    readonly path: string;
    /** The phase driving the panel — selects which caption/affordance to paint. */
    readonly phase: AccessPhase;
    /** A short, human caption for the current phase. */
    readonly label: string;
    /** Whether the user may *submit* a (re-)request from here. True for `init` and
     *  `revoked` (you may ask, or ask again); false while a request is pending
     *  (`requested`), already `granted`, or terminally `denied`. */
    readonly canRequest: boolean;
    /** Whether the user may *cancel* a pending request (only while `requested`). */
    readonly canCancel: boolean;
    /** Whether the flow is settled — the owner has answered (`granted`/`denied`),
     *  so the panel no longer waits. A settled `granted` hands off to the body. */
    readonly settled: boolean;
    /** Whether the panel is actively waiting on the owner (drives the spinner). */
    readonly waiting: boolean;
    /** Whether the payload is now admitted (`granted`): the host may render the
     *  body and dismiss this panel (mirrors `payloadAccessible`). */
    readonly granted: boolean;
}

/** Human captions for each access-request phase. */
const PHASE_LABEL: Record<AccessPhase, string> = {
    init: "the payload of this handle is withheld — request access to view it",
    requested: "access requested — awaiting the owner's approval",
    granted: "access granted — the payload is available",
    revoked: "access was revoked — request again to view",
    denied: "access denied",
};

/** Derive the panel presentation from the flow state. `init`/`revoked` may
 *  request; only `requested` may cancel; `granted`/`denied` are settled. */
export function presentAccessRequest(state: AccessRequestState): AccessRequestPresentation {
    const phase = state.phase;
    const canRequest = phase === "init" || phase === "revoked";
    const settled = phase === "granted" || phase === "denied";
    return {
        path: state.path,
        phase,
        label: PHASE_LABEL[phase],
        canRequest,
        canCancel: phase === "requested",
        settled,
        waiting: phase === "requested",
        granted: payloadAccessible(phase),
    };
}

// ----- Events -----------------------------------------------------------------

/** The events that move the flow. They mirror the only things that move an
 *  access request: the user submitting an ask (optimistically `requested` under a
 *  correlation id), the user canceling a still-pending ask, and the owner's answer
 *  arriving as the handle's new server-side phase. */
export type AccessRequestEvent =
    /** The user submitted a request for the payload. Carries the optimistic
     *  correlation id so the answering projection can retire it (MOB-003). Only
     *  meaningful when the current phase admits a (re-)request. */
    | { readonly kind: "submit"; readonly requestId: ClientRequestId }
    /** The user withdrew a still-pending request (back to `init`, no ask in flight). */
    | { readonly kind: "cancel" }
    /** The handle's payload-access phase changed server-side (the owner answered,
     *  a grant was revoked, etc.). The authoritative fact; it clears any pending
     *  optimistic correlation id once the phase is no longer `requested`. */
    | { readonly kind: "phase"; readonly phase: AccessPhase };

// ----- The reducer ------------------------------------------------------------

/** Apply an event. Pure — returns the same reference unchanged on a no-op so the
 *  island can cheaply diff. A `submit` from a phase that cannot request is ignored
 *  (the safe direction is to never optimistically claim an ask the server would
 *  reject); a server `phase` is always authoritative and overrides the optimistic
 *  view (it never *narrows* less than the server says — the owner controls access). */
export function reduceAccessRequest(
    state: AccessRequestState,
    event: AccessRequestEvent,
): AccessRequestState {
    switch (event.kind) {
        case "submit": {
            // Only a phase that admits a request may optimistically move to
            // `requested`; from anywhere else the ask is a no-op (never claim an
            // ask the server would refuse).
            if (state.phase !== "init" && state.phase !== "revoked") return state;
            return { ...state, phase: "requested", requestId: event.requestId };
        }
        case "cancel": {
            // Only a pending request can be canceled; back to `init` with no ask.
            if (state.phase !== "requested") return state;
            return { ...state, phase: "init", requestId: null };
        }
        case "phase": {
            // The server's phase is authoritative. Clear the optimistic id once the
            // ask is no longer in flight (any phase but `requested`); preserve it
            // only while the server still reports `requested`.
            const requestId = event.phase === "requested" ? state.requestId : null;
            if (event.phase === state.phase && requestId === state.requestId) return state;
            return { ...state, phase: event.phase, requestId };
        }
    }
}
