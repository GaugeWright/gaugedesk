/**
 * The mobile **Chat composer** (`mobile-client.md`, MOB-020): the draft → send /
 * stop control shown at the `chat` carousel stop, beneath the live transcript.
 * Sending is one of the few *commands* the client may issue (`mobile-client.md`,
 * "Projection-first compliance"); the rest of the carousel is local view state.
 *
 * Like {@link MobileFiles} / {@link MobileContent} / {@link Carousel} this is a
 * thin renderer: every "may I send? may I stop? what does this draft become?"
 * decision is a pure function in `mobile-composer.ts` (`presentComposer`,
 * `send`, `reconcile`). The island only wires Solid's events onto that derived
 * presentation and routes the resulting state back through the host via
 * {@link MobileChatProps.onState} — it owns no truth and decides no liveness
 * itself. The optimistic pending ledger surfaces as an unobtrusive in-flight
 * caption (a send is *non-standing* until the environment confirms, `INV-5`).
 */

import { Show, type JSX } from "solid-js";
import {
    edit,
    presentComposer,
    send,
    type ComposerState,
    type TurnPhase,
} from "./mobile-composer";
import { canSendOnConnection } from "./connection-banner";
import { type ConnectionStatus } from "./connection";

export interface MobileChatProps {
    /** The composer's draft + optimistic pending ledger. The host holds the
     *  signal; the island reads it reactively and routes edits/sends back. */
    readonly state: ComposerState;
    /** Whether a turn is in flight — gates the stop control and whether a send
     *  records an optimistic pending entry (the host derives this from the run
     *  projection). */
    readonly phase: TurnPhase;
    /** The current connection status (MOB-018). A send is a *standing command*,
     *  so it is permitted only when the connection can carry one
     *  ({@link canSendOnConnection}); a degraded connection (offline / revoked /
     *  expired) disables send here, paired with the {@link ConnectionBanner} that
     *  explains why — never a silently dead control (MOB-028). */
    readonly connection: ConnectionStatus;
    /** Opt the next candidate into review; false keeps shared-line auto-sync. */
    readonly reviewNext?: boolean;
    /** Apply a reduced composer state (the host's setter). Every edit and send
     *  flows through here; the island never mutates truth itself. */
    readonly onState: (next: ComposerState) => void;
    /** Submit the drafted message as a command, tagged with the {@link
     *  ClientRequestId} the host minted for it (so the answering projection can
     *  reconcile it). The host issues the actual control-plane request. */
    readonly onSend: (text: string) => void;
    readonly onToggleReview?: () => void;
    /** Request the running turn be aborted (the stop command). The host issues
     *  the control-plane stop; this island only offers the affordance. */
    readonly onStop: () => void;
}

export function MobileChat(props: MobileChatProps): JSX.Element {
    const view = () => presentComposer(props.state, props.phase);

    // The send control needs both a sendable draft *and* a connection that can
    // carry a standing command — offline / revoked / expired disables it, the
    // explicit outcome the ConnectionBanner narrates (MOB-028). The two read one
    // predicate, so the button is never live when the banner says it cannot send.
    const canSend = () => view().canSend && canSendOnConnection(props.connection);

    // A send hands the text to the host, then optimistically clears the draft
    // (and records the pending entry while running) via the pure reducer. The
    // host mints the ClientRequestId and routes the reconciling state back.
    const submit = () => {
        if (!canSend()) return;
        props.onSend(props.state.draft);
    };

    return (
        <div class="mobile-chat-composer" data-pane="chat">
            <textarea
                class="composer-draft"
                data-composer-draft
                rows={1}
                placeholder="Message…"
                value={view().draft}
                onInput={(e) => props.onState(edit(props.state, e.currentTarget.value))}
                // Enter submits; Shift+Enter inserts a newline (a multi-line draft).
                onKeyDown={(e) => {
                    if (e.key === "Enter" && !e.shiftKey) {
                        e.preventDefault();
                        submit();
                    }
                }}
            />

            <div class="composer-controls">
                {/* In-flight caption: a send is non-standing until the
                    environment confirms (the optimistic pending ledger). */}
                <Show when={view().hasPending}>
                    <span class="composer-pending" data-pending role="status">
                        sending… ({view().pendingCount})
                    </span>
                </Show>

                <Show when={props.onToggleReview && !view().canStop}>
                    <button
                        type="button"
                        class="review-toggle"
                        classList={{ active: props.reviewNext === true }}
                        data-review-next
                        aria-pressed={props.reviewNext === true}
                        onClick={() => props.onToggleReview?.()}
                    >
                        review
                    </button>
                </Show>

                {/* Stop is offered only while a turn is running. */}
                <Show
                    when={view().canStop}
                    fallback={
                        <button
                            type="button"
                            class="composer-send"
                            data-composer-send
                            aria-disabled={!canSend()}
                            disabled={!canSend()}
                            onClick={submit}
                        >
                            send
                        </button>
                    }
                >
                    <button
                        type="button"
                        class="composer-stop"
                        data-composer-stop
                        onClick={() => props.onStop()}
                    >
                        stop
                    </button>
                </Show>
            </div>
        </div>
    );
}

/** Re-export the pure send so a host that submits a drafted message lands the
 *  optimistic state (cleared draft + recorded pending id) without reaching into
 *  the reducer module directly — the mirror of {@link Carousel.applySelection}. */
export function applySend(
    state: ComposerState,
    rid: Parameters<typeof send>[1],
    phase: TurnPhase,
): ComposerState {
    return send(state, rid, phase);
}
