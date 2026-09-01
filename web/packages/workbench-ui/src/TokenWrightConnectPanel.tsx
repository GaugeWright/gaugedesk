/**
 * **Add a TokenWright box.** The operator pastes the pairing string printed on
 * the box's console, and this claims it and stores how to reach it again.
 *
 *   ┌──────────────────────────────────────────────────┐
 *   │ Pairing string                                   │
 *   │ ┌──────────────────────────────────────────────┐ │
 *   │ │ tw1_…                                        │ │
 *   │ └──────────────────────────────────────────────┘ │
 *   │ relay        wss://relay.example                 │
 *   │ certificate  sha256:9d1f04…                      │
 *   │                                    [ Add box ]   │
 *   └──────────────────────────────────────────────────┘
 *
 * Like {@link ConnectionBanner} this is a thin renderer: the journey — read,
 * dial, claim, store — is the {@link connectTokenWrightBox} machine in
 * `tokenwright-connect.ts`, and this island decides no truth of its own.
 *
 * Two details here are load-bearing rather than styling:
 *
 * - The field is `type="password"`-shaped by default. A pairing string is a
 *   bearer capability for an unclaimed box, and this panel is the one place it
 *   is ever on screen — often while someone is sharing that screen with the
 *   person reading the code to them.
 * - The retry control appears only when the machine says the same string could
 *   plausibly work again. A retry after a spent claim code cannot succeed, and
 *   offering it hides the fact that a new code must come from the box.
 */

import { Show, createSignal, type JSX } from "solid-js";
import {
    connectTokenWrightBox,
    IDLE,
    type ConnectDependencies,
    type TokenWrightConnectState,
} from "./tokenwright-connect";

export interface TokenWrightConnectPanelProps {
    /** Everything the journey needs from the host: how to open a pinned tunnel,
     * where to persist the result, and which Home is claiming. */
    readonly dependencies: ConnectDependencies;
    /** Told once a box is claimed and stored, so the host can show it. */
    readonly onConnected?: (state: TokenWrightConnectState) => void;
}

const BUSY: readonly TokenWrightConnectState["phase"][] = [
    "reading", "dialling", "claiming", "storing",
];

export function TokenWrightConnectPanel(props: TokenWrightConnectPanelProps): JSX.Element {
    const [token, setToken] = createSignal("");
    const [reveal, setReveal] = createSignal(false);
    const [state, setState] = createSignal<TokenWrightConnectState>(IDLE);

    const busy = () => BUSY.includes(state().phase);

    async function submit(event: Event): Promise<void> {
        event.preventDefault();
        if (busy()) return;
        const finished = await connectTokenWrightBox(token(), {
            ...props.dependencies,
            onState: (next) => {
                setState(next);
                props.dependencies.onState?.(next);
            },
        });
        setState(finished);
        if (finished.phase === "connected") {
            // Cleared on success only. After a failure the operator is going to
            // look at what they pasted, and wiping it takes away the thing they
            // need to look at.
            setToken("");
            props.onConnected?.(finished);
        }
    }

    return (
        <form class="tokenwright-connect" data-phase={state().phase} onSubmit={submit}>
            <label class="tokenwright-connect__label" for="tokenwright-pairing-string">
                Pairing string
            </label>
            <div class="tokenwright-connect__field">
                <input
                    id="tokenwright-pairing-string"
                    class="tokenwright-connect__input"
                    // A live claim code. Masked by default because this panel is
                    // often open while the operator is reading it off another
                    // screen with someone watching.
                    type={reveal() ? "text" : "password"}
                    autocomplete="off"
                    spellcheck={false}
                    placeholder="tw1_…"
                    disabled={busy()}
                    value={token()}
                    onInput={(event) => setToken(event.currentTarget.value)}
                />
                <button
                    type="button"
                    class="tokenwright-connect__reveal"
                    aria-pressed={reveal()}
                    onClick={() => setReveal((shown) => !shown)}
                >
                    {reveal() ? "Hide" : "Show"}
                </button>
            </div>

            <Show when={state().invite}>
                {(invite) => (
                    // What the operator is about to trust, before it is dialled.
                    // The pin is the whole of the box's identity here — there is
                    // no chain to build and no authority to ask — so it is shown
                    // rather than left implicit.
                    <dl class="tokenwright-connect__facts">
                        <dt>Relay</dt>
                        <dd>{invite().relayEndpoint}</dd>
                        <dt>Certificate</dt>
                        <dd class="tokenwright-connect__pin">{invite().fingerprint}</dd>
                    </dl>
                )}
            </Show>

            <p
                class="tokenwright-connect__message"
                data-phase={state().phase}
                // Announced, because the outcome of pressing the button is text
                // that appears somewhere else on the panel.
                role="status"
                aria-live="polite"
            >
                {state().message}
            </p>

            <Show when={state().phase === "failed" && state().connection}>
                {(connection) => (
                    // The claim succeeded and the save did not. This is the only
                    // copy of the route that exists anywhere, so it goes on
                    // screen rather than into a log the operator cannot reach.
                    <output class="tokenwright-connect__rescue">
                        <strong>Write this down before closing:</strong>
                        <code>{connection().route}</code>
                    </output>
                )}
            </Show>

            <button
                type="submit"
                class="tokenwright-connect__submit"
                disabled={busy() || !token().trim() || (state().phase === "failed" && !state().retryable)}
            >
                {busy() ? "Working…" : state().phase === "failed" ? "Try again" : "Add box"}
            </button>
        </form>
    );
}
