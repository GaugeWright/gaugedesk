/**
 * The mobile **inline merge/review approval flow** (`mobile-client.md`, MOB-031):
 * the pure state machine the {@link ChatApprovalCard} island reduces over when a
 * turn surfaces a *result that needs approval* in the chat transcript. On the
 * desktop this is the output catalog (conjunctive consent → clear → release);
 * on a phone the same review lifecycle rides *inline in the chat stop*, as a card
 * threaded between the turns that produced it — the carousel has no second shelf.
 *
 * The vocabulary is the one the rest of the client already speaks — the review
 * {@link ReviewPhase} (`control-plane.ts`, mirroring `gaugedesk_core::review`). A card
 * walks the same arc the core reducer walks server-side: `Init` (nothing to
 * approve) → an agent proposes → `Proposed` (the required parties must each
 * consent) → every required party consents → `Cleared` → the user releases →
 * `Released` (terminal), or the proposal is withdrawn → `Withheld` (terminal). The
 * flow never manufactures a clearance: it is `Cleared` only once *every* required
 * party's consent is in (the conjunctive `INV-7` rule the core reducer enforces),
 * and `Released` only once the server's review state says so (mirrors
 * `access-request.ts`'s `granted ⇔ server phase` discipline; `principles.md`,
 * `INV-5`/`INV-7`).
 *
 * Like the rest of the mobile client (`access-request.ts`, `mobile-composer.ts`,
 * `connection.ts`) this is a thin, DOM-free pure layer: every "what may the user
 * do, and what do we show?" decision is a pure function here, and the
 * {@link ChatApprovalCard} island only wires Solid signals and DOM events onto it.
 * The transport (the actual `consent` / `release` command) is the host's; this
 * module decides nothing about the network beyond folding the phase it is handed.
 *
 * The optimistic-reconcile correlation id (`ClientRequestId`, MOB-003) travels
 * with a pending consent/release so the host can retire the optimistic entry when
 * the review projection that answers it lands.
 */

import { type ReviewPhase } from "@gaugewright/control-plane-client";
import { type ClientRequestId } from "@gaugewright/control-plane-client";

// ----- Flow state -------------------------------------------------------------

/** The approval card's state for a single proposal threaded in the transcript.
 *  The `phase` + `consented`/`required` sets mirror the server's review state (the
 *  truth the parties control); `pendingId` correlates a still-in-flight optimistic
 *  consent/release with the projection that retires it (MOB-003), `null` once no
 *  command is pending. The `party` is *this* device's user — the only consent this
 *  card may optimistically record (you never consent on another party's behalf). */
export interface ChatApprovalState {
    /** The proposal this card is about (echoed for the card header / correlation). */
    readonly proposalId: string;
    /** This device's user — the party whose consent this card may submit. */
    readonly party: string;
    /** The server-mirrored review phase of this proposal. */
    readonly phase: ReviewPhase;
    /** The parties whose consent the proposal requires (conjunctive, `INV-7`). */
    readonly required: readonly string[];
    /** The parties who have consented so far (server-mirrored). */
    readonly consented: readonly string[];
    /** The optimistic correlation id of a consent/release still in flight, else
     *  `null`. The host clears it once the answering review projection lands. */
    readonly pendingId: ClientRequestId | null;
}

/** A freshly threaded card for a proposal at the given phase, no command in flight. */
export function initialChatApproval(
    proposalId: string,
    party: string,
    phase: ReviewPhase,
    required: readonly string[],
    consented: readonly string[],
): ChatApprovalState {
    return { proposalId, party, phase, required, consented, pendingId: null };
}

// ----- Derivation (the pure heart) -------------------------------------------

/** What the approval card should show and enable. The island reads this and
 *  paints; it makes no phase decision itself (same split as
 *  `access-request`'s `presentAccessRequest`). */
export interface ChatApprovalPresentation {
    /** The proposal this card is about. */
    readonly proposalId: string;
    /** The phase driving the card — selects which caption/affordance to paint. */
    readonly phase: ReviewPhase;
    /** A short, human caption for the current phase. */
    readonly label: string;
    /** Whether *this party* may consent from here: only while `Proposed`, the
     *  proposal requires this party, and this party has not already consented
     *  (you consent once, and only to a live proposal). */
    readonly canConsent: boolean;
    /** Whether the user may *release* the cleared result (only while `Cleared`). */
    readonly canRelease: boolean;
    /** Whether the flow is actively waiting on the other required parties (drives
     *  the progress caption): `Proposed` with consent still outstanding. */
    readonly waiting: boolean;
    /** Whether the flow is settled — terminally `Released` or `Withheld`, so the
     *  card offers no further affordance. */
    readonly settled: boolean;
    /** Whether the result was released (the terminal accept). */
    readonly released: boolean;
    /** How many required consents are in / needed (drives the `2 / 3` progress). */
    readonly consentsIn: number;
    readonly consentsNeeded: number;
    /** The required parties still outstanding (consent not yet recorded). */
    readonly outstanding: readonly string[];
}

/** Human captions for each review phase, in chat-card voice. */
const PHASE_LABEL: Record<ReviewPhase, string> = {
    Init: "no result to approve yet",
    Proposed: "review proposed — consent required from all parties",
    Cleared: "all parties consented — release the result",
    Released: "result released",
    Withheld: "proposal withdrawn",
};

/** The parties from `required` that have not yet consented. */
function outstandingParties(state: ChatApprovalState): readonly string[] {
    const seen = new Set(state.consented);
    return state.required.filter((p) => !seen.has(p));
}

/** Derive the card presentation from the flow state. Only a `Proposed` proposal
 *  that requires this party and lacks its consent may consent; only `Cleared` may
 *  release; `Released`/`Withheld` are settled. */
export function presentChatApproval(state: ChatApprovalState): ChatApprovalPresentation {
    const phase = state.phase;
    const outstanding = outstandingParties(state);
    const requires = state.required.includes(state.party);
    const alreadyConsented = state.consented.includes(state.party);
    const consentsIn = state.required.filter((p) => state.consented.includes(p)).length;
    return {
        proposalId: state.proposalId,
        phase,
        label: PHASE_LABEL[phase],
        canConsent: phase === "Proposed" && requires && !alreadyConsented,
        canRelease: phase === "Cleared",
        waiting: phase === "Proposed" && outstanding.length > 0,
        settled: phase === "Released" || phase === "Withheld",
        released: phase === "Released",
        consentsIn,
        consentsNeeded: state.required.length,
        outstanding,
    };
}

// ----- Events -----------------------------------------------------------------

/** The events that move the flow. They mirror the only things that move a review:
 *  this party consenting (optimistically recorded under a correlation id), the user
 *  releasing a cleared result, and the server's review state arriving (the
 *  authoritative phase + consent sets). */
export type ChatApprovalEvent =
    /** This party submitted its consent. Carries the optimistic correlation id so
     *  the answering projection can retire it (MOB-003). Only meaningful while
     *  `Proposed` and this party is required and has not already consented. */
    | { readonly kind: "consent"; readonly requestId: ClientRequestId }
    /** The user released the cleared result (optimistically `Released`). Only
     *  meaningful while `Cleared`. */
    | { readonly kind: "release"; readonly requestId: ClientRequestId }
    /** The review state changed server-side (a party consented, it cleared, it was
     *  withheld). The authoritative fact; it overrides the optimistic view and
     *  clears the pending id once the server has caught up to (or past) the
     *  optimistic step. */
    | {
          readonly kind: "review";
          readonly phase: ReviewPhase;
          readonly required: readonly string[];
          readonly consented: readonly string[];
      };

// ----- The reducer ------------------------------------------------------------

/** Apply an event. Pure — returns the same reference unchanged on a no-op so the
 *  island can cheaply diff. A `consent`/`release` from a phase that cannot do so is
 *  ignored (never optimistically claim a step the server would reject); a server
 *  `review` is always authoritative and overrides the optimistic view (the parties
 *  control the result, never the device). */
export function reduceChatApproval(
    state: ChatApprovalState,
    event: ChatApprovalEvent,
): ChatApprovalState {
    switch (event.kind) {
        case "consent": {
            // Only a live proposal that requires this party (and lacks its consent)
            // may optimistically record it; from anywhere else the consent is a
            // no-op (never claim a consent the server would refuse).
            if (state.phase !== "Proposed") return state;
            if (!state.required.includes(state.party)) return state;
            if (state.consented.includes(state.party)) return state;
            return {
                ...state,
                consented: [...state.consented, state.party],
                pendingId: event.requestId,
            };
        }
        case "release": {
            // Only a cleared proposal may be released; optimistically terminal.
            if (state.phase !== "Cleared") return state;
            return { ...state, phase: "Released", pendingId: event.requestId };
        }
        case "review": {
            // The server's review state is authoritative. Clear the optimistic id
            // once a command is no longer in flight — i.e. once the server has
            // caught up to (or moved past) the optimistic step. We treat the id as
            // retired whenever the server phase is no longer `Proposed`, or this
            // party's consent is now reflected server-side, or the flow has settled.
            const settled = event.phase === "Released" || event.phase === "Withheld";
            const consentReflected = event.consented.includes(state.party);
            const pendingId =
                settled || event.phase === "Cleared" || consentReflected
                    ? null
                    : state.pendingId;
            const unchanged =
                event.phase === state.phase &&
                sameSet(event.required, state.required) &&
                sameSet(event.consented, state.consented) &&
                pendingId === state.pendingId;
            if (unchanged) return state;
            return {
                ...state,
                phase: event.phase,
                required: event.required,
                consented: event.consented,
                pendingId,
            };
        }
    }
}

/** Order-insensitive set equality for the party lists (so an echo that merely
 *  reorders the consent set is a no-op). */
function sameSet(a: readonly string[], b: readonly string[]): boolean {
    if (a.length !== b.length) return false;
    const sb = new Set(b);
    return a.every((x) => sb.has(x));
}
