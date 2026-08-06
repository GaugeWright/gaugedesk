/**
 * The mobile **Chat composer's** view-derived vocabulary (`mobile-client.md`,
 * MOB-020): the small, pure state the {@link MobileChat} island needs to paint a
 * draft → send/stop control at the `chat` carousel stop. Sending a message is one
 * of the few *commands* the client may issue (`mobile-client.md`, "Projection-first
 * compliance": "Only send / approve / reject … are commands"); everything else in
 * the carousel is local view state. So the composer is where the **optimistic
 * reconcile** discipline lives on the client edge.
 *
 * The model mirrors `gaugedesk_core::run::pending_commands` (MOB-003) exactly:
 *
 *   - A **send** while a turn is running does not manufacture truth. It clears the
 *     draft and records an *optimistic* pending entry keyed by a fresh
 *     {@link ClientRequestId} (`principles.md`, `INV-5`: the client cannot
 *     manufacture truth — the entry is *non-standing* until the environment
 *     confirms, `mobile-client.md` "Optimistic UI carries a `clientRequestId`").
 *   - A projection answering that command arrives carrying its id
 *     ({@link ProjectionCarriage.clientRequestId}) and {@link reconcile}s the
 *     pending entry away — the same retire path `RunState::Reconcile` walks.
 *   - **Stop** is offered only while a turn is running (there is something to
 *     abort); like send it is a request, not a fact.
 *
 * Like {@link mobile-content} / {@link mobile-files} this is a thin, DOM-free pure
 * layer: every "what may I do, and what does this draft become?" decision is a
 * pure function here, and the {@link MobileChat} island only wires Solid signals
 * and DOM events onto it.
 */

import type {
    ClientRequestId,
    ProjectionCarriage,
} from "@gaugewright/control-plane-client";

// ----- Turn liveness ----------------------------------------------------------

/** Whether the addressed environment currently has a turn in flight. Only a
 *  running turn admits a {@link stop}; only a running turn lets a {@link send}
 *  record an optimistic pending entry (mirrors `RunPhase::Running`, the only
 *  phase `pending_commands` may grow under). Idle turns send eagerly with no
 *  pending entry — there is nothing to reconcile against until the run starts. */
export type TurnPhase =
    /** No turn in flight — a send starts one; there is nothing to stop. */
    | "idle"
    /** A turn is running — a send is optimistic (pending) and stop is offered. */
    | "running";

// ----- Composer state ---------------------------------------------------------

/** The composer's state: the working draft plus the optimistic pending ledger.
 *  `pending` mirrors `RunState.pending_commands` — the ids of sends awaiting the
 *  environment's confirming projection. It is *not* truth; it only drives the
 *  in-flight UI (a spinner / greyed re-send) until {@link reconcile} retires it. */
export interface ComposerState {
    /** The current, unsent draft text (local view state — never a command). */
    readonly draft: string;
    /** Optimistic sends awaiting reconciliation, in submit order (MOB-003). The
     *  same id never appears twice — two distinct sends never collapse. */
    readonly pending: readonly ClientRequestId[];
}

/** A freshly opened composer: empty draft, no optimistic work outstanding. */
export const empty: ComposerState = { draft: "", pending: [] };

// ----- Derived presentation ---------------------------------------------------

/** A fully-derived plan for what the composer should render and enable. The
 *  island reads this and paints; it makes no liveness or reconcile decision
 *  itself (same split as `mobile-content`'s {@link presentContent}). */
export interface ComposerPresentation {
    /** The draft to show in the input. */
    readonly draft: string;
    /** Whether the *send* control is enabled. A send needs a non-blank draft;
     *  blank-or-whitespace drafts never produce a command (no empty messages). */
    readonly canSend: boolean;
    /** Whether the *stop* control is offered — only while a turn is running, when
     *  there is actually something to abort. */
    readonly canStop: boolean;
    /** How many optimistic sends are still awaiting reconciliation. Drives the
     *  in-flight indicator; `0` means the composer is settled. */
    readonly pendingCount: number;
    /** Whether any optimistic send is still in flight (`pendingCount > 0`). */
    readonly hasPending: boolean;
}

/** Whether a draft carries something sendable — non-empty once trimmed. The
 *  composer never issues an empty-message command. */
export function isSendable(draft: string): boolean {
    return draft.trim().length > 0;
}

/** Derive the composer presentation from its state and the turn's liveness. Send
 *  is gated on a non-blank draft; stop is offered only while running; the pending
 *  count surfaces the optimistic in-flight work. */
export function presentComposer(
    state: ComposerState,
    phase: TurnPhase,
): ComposerPresentation {
    return {
        draft: state.draft,
        canSend: isSendable(state.draft),
        canStop: phase === "running",
        pendingCount: state.pending.length,
        hasPending: state.pending.length > 0,
    };
}

// ----- Transitions (pure) -----------------------------------------------------

/** Replace the draft (every keystroke). Pure: returns the same reference when the
 *  text did not actually change, so the island can cheaply diff. */
export function edit(state: ComposerState, draft: string): ComposerState {
    if (draft === state.draft) return state;
    return { ...state, draft };
}

/** Discard the draft without sending (the input was cleared). */
export function clearDraft(state: ComposerState): ComposerState {
    return state.draft === "" ? state : { ...state, draft: "" };
}

/** Send the draft as an optimistic command keyed by `rid`. Mirrors
 *  `RunState::RecordPending` (MOB-003): the draft is cleared and — while a turn
 *  is *running* — `rid` is appended to the pending ledger so the UI shows it
 *  in-flight until the environment's projection {@link reconcile}s it away. An
 *  *idle* send starts the turn with nothing yet to reconcile, so it records no
 *  pending entry (the safe direction is fewer optimistic claims, `INV-5`).
 *
 *  A blank draft is a no-op (the same reference back) — the composer never emits
 *  an empty-message command. A duplicate `rid` is rejected the same way
 *  `RecordPending` is fresh-keyed, so two sends never collapse onto one id. */
export function send(
    state: ComposerState,
    rid: ClientRequestId,
    phase: TurnPhase,
): ComposerState {
    if (!isSendable(state.draft)) return state;
    if (phase !== "running") return { ...state, draft: "" };
    if (state.pending.includes(rid)) return { ...state, draft: "" };
    return { draft: "", pending: [...state.pending, rid] };
}

/** Retire the optimistic pending entry for `rid` once the environment confirms
 *  it. Mirrors `RunState::Reconcile` (MOB-003): drop exactly the matching id,
 *  leaving every other in-flight send pending. A `rid` that is not pending is a
 *  no-op (the same reference back) — reconciling twice is idempotent. */
export function reconcile(state: ComposerState, rid: ClientRequestId): ComposerState {
    if (!state.pending.includes(rid)) return state;
    return { ...state, pending: state.pending.filter((p) => p !== rid) };
}

/** Reconcile against a projection that arrived: if the carriage names an
 *  optimistic command ({@link ProjectionCarriage.clientRequestId}), retire it.
 *  A carriage with no correlation id (a plain projection, not an answer to a
 *  send) leaves the ledger untouched. This is the wire-facing convenience over
 *  {@link reconcile} the island uses when a projection lands. */
export function reconcileCarriage<T>(
    state: ComposerState,
    carriage: ProjectionCarriage<T>,
): ComposerState {
    const rid = carriage.clientRequestId;
    return rid === null ? state : reconcile(state, rid);
}
