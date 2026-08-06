/**
 * The mobile **inline merge/review approval card** (`mobile-client.md`, MOB-031):
 * the card threaded into the chat transcript when a turn surfaces a result that
 * needs approval. It is the carousel's answer to the desktop output catalog:
 * the same conjunctive-consent review lifecycle (`gaugedesk_core::review`, `INV-7`),
 * but inline in the chat stop rather than a second shelf the phone has no room for.
 *
 * Like {@link AccessRequestPanel} / {@link MobileChat} / {@link Carousel} this is a
 * thin renderer: every "what may the user do, and what do we show?" decision is a
 * pure function in `chat-approval.ts` (`presentChatApproval`), so the component only
 * wires Solid's `<Switch>` / `<Show>` onto the derived presentation and never
 * decides the review itself (it never clears — clearance is the parties' conjunctive
 * consent, server-side).
 *
 * Consenting and releasing are *standing commands* (`INV-5`), so — exactly like the
 * {@link MobileChat} send — they are permitted only when the connection can carry
 * one ({@link canCommand}); a degraded link disables them here, paired with the
 * {@link ConnectionBanner} that explains why (MOB-028), never a silently dead button.
 */

import { Show, Switch, Match, type JSX } from "solid-js";
import { presentChatApproval, type ChatApprovalState } from "./chat-approval";
import { canCommand, type ConnectionStatus } from "./connection";

export interface ChatApprovalCardProps {
    /** The review-flow state for the proposal this card is about. */
    readonly state: ChatApprovalState;
    /** The current connection status (MOB-018). Consent/release are standing
     *  commands, so they are offered only when the connection can carry one; a
     *  degraded link disables them, paired with the {@link ConnectionBanner}. */
    readonly connection: ConnectionStatus;
    /** Submit this party's consent. The host issues the `review consent` command
     *  tagged with the {@link ClientRequestId} it minted, and feeds the answering
     *  review projection back as a `review` event; this card only invokes the intent. */
    readonly onConsent: (proposalId: string) => void;
    /** Release the cleared result. The host issues the `review release` command. */
    readonly onRelease: (proposalId: string) => void;
}

export function ChatApprovalCard(props: ChatApprovalCardProps): JSX.Element {
    const view = () => presentChatApproval(props.state);
    // A standing command needs a connection that can carry one (MOB-028): offline /
    // revoked / expired disables the affordance, the outcome the banner narrates.
    const live = () => canCommand(props.connection);

    return (
        <div
            class="chat-approval"
            data-chat-approval
            data-phase={view().phase}
            role="group"
            aria-label="merge review approval"
        >
            <div class="chat-approval-caption" data-chat-approval-label>
                {view().label}
            </div>

            {/* Conjunctive-consent progress: how many of the required parties are in. */}
            <Show when={view().consentsNeeded > 0}>
                <div class="chat-approval-progress" data-chat-approval-progress>
                    consented {view().consentsIn} / {view().consentsNeeded}
                    <Show when={view().outstanding.length > 0}>
                        {" · awaiting "}
                        {view().outstanding.join(", ")}
                    </Show>
                </div>
            </Show>

            <Switch>
                {/* This party may consent — offer the affordance, gated on the link. */}
                <Match when={view().canConsent}>
                    <button
                        type="button"
                        class="chat-approval-consent"
                        data-chat-approval-consent
                        aria-disabled={!live()}
                        disabled={!live()}
                        onClick={() => props.onConsent(view().proposalId)}
                    >
                        consent
                    </button>
                </Match>

                {/* Cleared — the user may release the result. */}
                <Match when={view().canRelease}>
                    <button
                        type="button"
                        class="chat-approval-release"
                        data-chat-approval-release
                        aria-disabled={!live()}
                        disabled={!live()}
                        onClick={() => props.onRelease(view().proposalId)}
                    >
                        release
                    </button>
                </Match>

                {/* Settled (released / withheld) — terminal, no further affordance. */}
                <Match when={view().settled}>
                    <div class="chat-approval-settled" data-chat-approval-settled>
                        {view().released ? "released" : "withdrawn"}
                    </div>
                </Match>

                {/* Still waiting on the other required parties. */}
                <Match when={view().waiting}>
                    <div class="chat-approval-waiting" data-chat-approval-waiting>
                        <span class="spinner" aria-hidden="true" />
                    </div>
                </Match>
            </Switch>
        </div>
    );
}
