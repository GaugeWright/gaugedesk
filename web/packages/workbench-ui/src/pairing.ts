/**
 * The client's **pairing flow** (`mobile-client.md`, "Pairing", MOB-026): the
 * pure state machine the {@link PairingFlow} island reduces over while a device
 * binds itself to an environment. A pairing ticket — scanned from a QR code or
 * typed as a short code — is submitted to the owner's `POST /pairing-requests`
 * endpoint, which opens a `DeviceBinding` boundary and returns a `pairing_id`;
 * the client then polls `GET /pairing-status/:id` until the owner accepts and the
 * boundary goes `Active` (`crates/app/src/library_routes.rs`, MOB-027). The end
 * of a successful flow is the grant this device now holds — the connection state
 * machine's `grants-changed` input (`connection.ts`, MOB-018).
 *
 * Like the rest of the mobile client (`mobile-content.ts`, `mobile-composer.ts`,
 * `connection.ts`) this is a thin, DOM-free pure layer: every "what step are we
 * on, and what may the user do?" decision is a pure function here, and the
 * {@link PairingFlow} island only wires Solid signals and DOM events onto it. The
 * transport (the two fetches) is the shell's; this module decides nothing about
 * the network beyond folding the wire status it is handed.
 *
 * The step vocabulary mirrors the boundary phases the server reports verbatim
 * (`gaugewright_core::boundary_lifecycle::BoundaryPhase`): a freshly bound pairing sits
 * at `DeviceBinding` (awaiting the owner's acceptance); the owner accepting moves
 * the boundary to `Active`, which the client reads as `paired` and the flow as
 * done. The flow never manufactures the paired fact — it is `paired` only once the
 * server's status says so (`paired === state.active()`; `principles.md`, `INV-5`).
 */

import { type ScopeId } from "@gaugewright/control-plane-client";
import { type BridgeGrantId, type DeviceId } from "@gaugewright/control-plane-client";

// ----- Ticket entry (QR / code) ----------------------------------------------

/** How the user supplied the pairing ticket — a scanned QR payload or a typed
 *  short code. Both decode to the same {@link PairingTicket}; the distinction is
 *  only which entry affordance the island offers (camera vs text field). */
export type TicketSource = "qr" | "code";

/** A parsed pairing ticket: the environment the device is binding to and the
 *  legacy `(device, bridge_grant)` invitation shape. The browser harness uses
 *  the ticket device verbatim. A native client owns its device identity and
 *  substitutes that identity when opening the request; the owner-generated
 *  device segment remains only until the one-use invitation protocol replaces
 *  this compatibility wire form. */
export interface PairingTicket {
    /** The environment (boundary scope) this device is pairing to. */
    readonly environment: ScopeId;
    /** Browser-harness device handle / legacy native invitation hint. */
    readonly device: DeviceId;
    /** The bridge grant the device pairs under, or `null` to let the owner mint
     *  one (the loopback flow mints both ends). */
    readonly bridgeGrant: BridgeGrantId | null;
}

/** Parse a raw QR/code payload into a {@link PairingTicket}. The wire form mirrors
 *  the deep-link scheme's authority segment (`deep-link.ts`):
 *
 *      gaugewright-pair://<environment>/<device>[/<bridge-grant>]
 *
 *  A malformed payload returns `null` — the island shows "invalid ticket" rather
 *  than submitting garbage to the owner. Parse is the only place the opaque string
 *  becomes typed; everything downstream consumes the branded ticket. */
/** Mint the compatibility wire ticket the owner hands a device (the inverse of
 *  {@link parseTicket}, MOB-F5): `gaugewright-pair://<environment>/<device>`.
 *  Native enrollment treats `device` as an invitation hint and presents its own
 *  keystore-derived id. The v2 ticket must replace this owner-invented segment
 *  with a one-use invitation capability. Round-trips through `parseTicket`. */
export function pairingTicket(environment: string, device: string): string {
    return `gaugewright-pair://${environment}/${device}`;
}

export function parseTicket(raw: string): PairingTicket | null {
    const trimmed = raw.trim();
    const prefix = "gaugewright-pair://";
    if (!trimmed.startsWith(prefix)) return null;
    const segments = trimmed.slice(prefix.length).split("/").filter((s) => s.length > 0);
    if (segments.length < 2 || segments.length > 3) return null;
    const [environment, device, bridgeGrant] = segments;
    return {
        environment: environment as ScopeId,
        device: device as DeviceId,
        bridgeGrant: (bridgeGrant ?? null) as BridgeGrantId | null,
    };
}

// ----- Wire pairing status (mirror `pairing_status_json`) --------------------

/** The boundary phase the pairing status reports, verbatim from the server's
 *  `format!("{:?}", phase)` over `BoundaryPhase`. Only the phases a pairing can
 *  reach are named; an unexpected string is treated as not-yet-paired (the safe
 *  direction — never claim `paired` from an unknown phase). */
export type PairingPhase =
    | "Proposed"
    | "Declared"
    | "DeviceBinding"
    | "Active"
    | "Draining"
    | "TornDown"
    | "Denied";

/** The client-facing pairing status, a structural mirror of `pairing_status_json`
 *  (`crates/app/src/library_routes.rs`): the boundary phase, the typed pair the
 *  `DeviceBinding` phase pinned (or `null` before a bind), and whether the owner
 *  has accepted. `paired ⇔ the boundary is Active`. */
export interface PairingStatus {
    readonly phase: PairingPhase;
    /** The `(device, bridge_grant)` the boundary bound, or `null` before binding. */
    readonly bound: { readonly device: DeviceId; readonly bridgeGrant: BridgeGrantId } | null;
    /** Whether the owner has accepted — the pairing is complete (`active()`). */
    readonly paired: boolean;
}

/** Parse a wire pairing-status envelope (snake_case) into the branded status.
 *  An unrecognized phase string degrades to `Proposed` (never-paired) so an
 *  unexpected server value can never read as `Active`/paired. */
export function parsePairingStatus(raw: {
    phase?: unknown;
    bound?: { device?: unknown; bridge_grant?: unknown } | null;
    paired?: unknown;
}): PairingStatus {
    const known: readonly PairingPhase[] = [
        "Proposed", "Declared", "DeviceBinding", "Active", "Draining", "TornDown", "Denied",
    ];
    const phase = (typeof raw.phase === "string" && (known as readonly string[]).includes(raw.phase)
        ? raw.phase
        : "Proposed") as PairingPhase;
    let bound: PairingStatus["bound"] = null;
    if (raw.bound != null && typeof raw.bound.device === "string" && typeof raw.bound.bridge_grant === "string") {
        bound = {
            device: raw.bound.device as DeviceId,
            bridgeGrant: raw.bound.bridge_grant as BridgeGrantId,
        };
    }
    return { phase, bound, paired: raw.paired === true };
}

// ----- Flow state -------------------------------------------------------------

/** The step the pairing flow is on. A strict progression: the user enters a
 *  ticket, the request is submitted, the device is bound and the flow waits for
 *  the owner to accept, then it settles `paired` (success) or `failed`. The
 *  vocabulary is the user-facing arc; the underlying boundary phase is folded in. */
export type PairingStep =
    /** No ticket yet — show the QR scanner / code field (the entry affordance). */
    | "entry"
    /** A ticket is parsed and the request is in flight (`POST /pairing-requests`). */
    | "submitting"
    /** The boundary bound the device; waiting for the owner to accept (the device
     *  polls `GET /pairing-status/:id`). This is the "approval wait" screen. */
    | "awaiting-approval"
    /** The owner accepted, the boundary is `Active`: paired. The grant is held. */
    | "paired"
    /** The flow failed — a bad ticket, a denied/torn-down boundary, or a transport
     *  error. Carries a reason and offers a retry back to `entry`. */
    | "failed";

/** The pairing flow's state. `ticket` is set once entry parses; `pairingId` once
 *  the request is accepted (the handle the status poll keys on); `status` carries
 *  the latest polled boundary status; `error` explains a `failed` step. The
 *  {@link PairingStep} is *derived* from these — it is carried so the island reads
 *  it directly, but it is never set independently (same discipline as
 *  `connection.ts`). */
export interface PairingState {
    readonly step: PairingStep;
    /** The parsed ticket, or `null` before entry. */
    readonly ticket: PairingTicket | null;
    /** The server-minted pairing id to poll, or `null` before the request lands. */
    readonly pairingId: string | null;
    /** The latest polled status, or `null` before the first poll. */
    readonly status: PairingStatus | null;
    /** A human-readable failure reason when `step === "failed"`, else `null`. */
    readonly error: string | null;
}

/** A freshly opened pairing flow: at the entry screen, nothing entered yet. */
export const initialPairing: PairingState = {
    step: "entry",
    ticket: null,
    pairingId: null,
    status: null,
    error: null,
};

// ----- Derivation (the pure heart) -------------------------------------------

/** Decide the step from the flow's facts. Pure: same facts ⇒ same step. The
 *  order is the law-bearing part: a recorded error is `failed` first (a denied or
 *  torn-down boundary, a parse failure, or a transport error never reads as
 *  progress); then a polled status drives the arc — `paired` once the server says
 *  so (`status.paired`), else `awaiting-approval` while the device is bound but
 *  not yet accepted; a submitted request with no status yet is also
 *  `awaiting-approval`; a parsed ticket with no request in flight is `submitting`;
 *  with neither we are at `entry`. */
export function deriveStep(
    ticket: PairingTicket | null,
    pairingId: string | null,
    status: PairingStatus | null,
    error: string | null,
): PairingStep {
    if (error !== null) return "failed";
    if (status !== null && status.paired) return "paired";
    if (status !== null || pairingId !== null) return "awaiting-approval";
    if (ticket !== null) return "submitting";
    return "entry";
}

// ----- Derived presentation ---------------------------------------------------

/** A fully-derived plan for what the pairing screen should show and enable. The
 *  island reads this and paints; it makes no progression decision itself (same
 *  split as `mobile-content`'s `presentContent`). */
export interface PairingPresentation {
    /** The step to render — selects which screen (entry / waiting / success). */
    readonly step: PairingStep;
    /** Whether the entry control (scan/submit) is offered (only at `entry`). */
    readonly canSubmit: boolean;
    /** Whether a retry back to entry is offered (only after a `failed` flow). */
    readonly canRetry: boolean;
    /** Whether the flow is settled — `paired` (success) or `failed`. A settled
     *  flow no longer polls; the host may dismiss it or hand off to the carousel. */
    readonly settled: boolean;
    /** Whether the flow is actively waiting on the owner (drives the spinner). */
    readonly waiting: boolean;
    /** The failure reason to show when `failed`, else `null`. */
    readonly error: string | null;
}

/** Derive the pairing presentation from its state. */
export function presentPairing(state: PairingState): PairingPresentation {
    return {
        step: state.step,
        canSubmit: state.step === "entry",
        canRetry: state.step === "failed",
        settled: state.step === "paired" || state.step === "failed",
        waiting: state.step === "submitting" || state.step === "awaiting-approval",
        error: state.error,
    };
}

// ----- Events -----------------------------------------------------------------

/** The events that move the flow. Each updates one fact; the step is re-derived.
 *  They mirror the only things that move a pairing: the user entering a ticket,
 *  the request being accepted (id assigned), a status poll landing, a transport
 *  or parse failure, and a retry resetting to entry. */
export type PairingEvent =
    /** The user supplied a ticket (parsed from QR/code). A `null` ticket is a
     *  parse failure → `failed` with an "invalid ticket" reason. */
    | { readonly kind: "ticket-entered"; readonly ticket: PairingTicket | null }
    /** `POST /pairing-requests` was accepted; the server assigned `pairingId`. */
    | { readonly kind: "request-accepted"; readonly pairingId: string }
    /** A `GET /pairing-status/:id` poll landed with the current status. */
    | { readonly kind: "status"; readonly status: PairingStatus }
    /** A transport / server error (bad request, network down, 404). */
    | { readonly kind: "error"; readonly reason: string }
    /** Start over from a failed (or any) flow — back to a clean entry screen. */
    | { readonly kind: "retry" };

// ----- The reducer ------------------------------------------------------------

/** Apply an event: update the one fact it carries, then re-derive the step. Pure
 *  — returns the same reference unchanged when the event is a no-op, so the island
 *  can cheaply diff. A `Denied`/`TornDown` status that arrives is recorded as a
 *  failure (the owner refused, or the boundary was torn down): the flow cannot
 *  silently sit "awaiting" on a boundary that can never accept. */
export function reducePairing(state: PairingState, event: PairingEvent): PairingState {
    const next = applyEvent(state, event);
    if (next === state) return state;
    const step = deriveStep(next.ticket, next.pairingId, next.status, next.error);
    return step === next.step ? next : { ...next, step };
}

function applyEvent(state: PairingState, event: PairingEvent): PairingState {
    switch (event.kind) {
        case "ticket-entered":
            if (event.ticket === null) {
                if (state.error === "invalid ticket" && state.ticket === null) return state;
                return { ...state, ticket: null, error: "invalid ticket" };
            }
            return { ...state, ticket: event.ticket, error: null };
        case "request-accepted":
            if (event.pairingId === state.pairingId) return state;
            return { ...state, pairingId: event.pairingId, error: null };
        case "status": {
            // A denied or torn-down boundary is terminal — record it as a failure
            // rather than poll a boundary that can never go `Active`.
            if (event.status.phase === "Denied" || event.status.phase === "TornDown") {
                const reason = event.status.phase === "Denied"
                    ? "the owner denied the pairing"
                    : "the pairing was torn down";
                if (state.error === reason) return state;
                return { ...state, status: event.status, error: reason };
            }
            if (event.status === state.status) return state;
            return { ...state, status: event.status };
        }
        case "error":
            if (state.error === event.reason) return state;
            return { ...state, error: event.reason };
        case "retry":
            if (state === initialPairing) return state;
            return initialPairing;
    }
}
