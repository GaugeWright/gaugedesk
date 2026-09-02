/**
 * **Your boxes** — the TokenWright section of Provider Connections.
 *
 *   ┌────────────────────────────────────────────────────────────┐
 *   │ Your boxes                                    [ Add a box ] │
 *   │ ● key_c30f    tinyllama, qwen2.5-7b +2                      │
 *   │ ○ key_44af    Not answering — last seen 4 hours ago         │
 *   └────────────────────────────────────────────────────────────┘
 *
 * A box is an OpenAI-compatible endpoint the person owns — in ADR 0158's words,
 * the thing that "takes the place of api.openai.com for that Home" — so it sits
 * with the other provider connections. It is not a Project Host (it runs no
 * Home) and not a GaugeApp (those have read models our server builds; a box's
 * come from the box).
 *
 * ## Everything about a box happens on the other side of this page
 *
 * Adding one sends a pairing string to the Home and gets back a description.
 * The page does not parse the string, derive a rendezvous, dial a relay, or pin
 * a certificate — the Home does all of that, seals what the box hands over, and
 * carries later requests under that seal. Listing returns the relay endpoint and
 * the certificate pin and no capability at all, so this component could not leak
 * one if it tried.
 *
 * That is a correction. An earlier version of this panel opened its own tunnel
 * to the box, borrowing the wasm carrier that exists to reach *a Home that is
 * not publicly addressable* (ADR 0130). A box is not a Home.
 *
 * Thin, like the other panels: {@link tokenwrightProviderRow} decides what a row
 * may claim and this paints it. It reads no clock and derives no reachability.
 */

import { For, Show, createResource, createSignal, type JSX } from "solid-js";
import {
    claimBox,
    forgetBox,
    listBoxes,
    type RouteJson,
    type StoredBox,
} from "@gaugewright/control-plane-client";
import { tokenwrightProviderRow, type TokenWrightObservation } from "./tokenwright-provider";

export interface TokenWrightBoxesSectionProps {
    /** The Home's transport. Every box operation goes through it. */
    readonly json: RouteJson;
    /** What each box last said, keyed by `sha256:`-prefixed fingerprint.
     * Supplied by the host: this section opens nothing and polls nothing. */
    readonly observations?: Readonly<Record<string, TokenWrightObservation>>;
    readonly now?: () => number;
}

export function TokenWrightBoxesSection(props: TokenWrightBoxesSectionProps): JSX.Element {
    const [generation, setGeneration] = createSignal(0);
    const [adding, setAdding] = createSignal(false);
    const [pairingString, setPairingString] = createSignal("");
    const [reveal, setReveal] = createSignal(false);
    const [busy, setBusy] = createSignal(false);
    const [message, setMessage] = createSignal<string | null>(null);

    const [boxes, { refetch }] = createResource(
        generation,
        async () => await listBoxes(props.json),
        { initialValue: [] as readonly StoredBox[] },
    );

    const rows = () => boxes().map((box) => ({
        box,
        row: tokenwrightProviderRow(
            box,
            props.observations?.[box.fingerprint] ?? {},
            props.now?.() ?? Date.now(),
        ),
    }));

    async function add(event: Event): Promise<void> {
        event.preventDefault();
        if (busy() || !pairingString().trim()) return;
        setBusy(true);
        setMessage("Reaching the box…");
        try {
            const added = await claimBox(props.json, pairingString());
            // Cleared on success only. After a failure the operator is going to
            // look at what they pasted, and wiping it takes away the thing they
            // need to look at.
            setPairingString("");
            setAdding(false);
            setMessage(
                added.sealed
                    ? null
                    // The Home claimed it and said it is not sealed. The code is
                    // spent either way, so this is not a retry — it is a box
                    // that must be unpaired in person before it can be paired
                    // again, and saying "added" would hide that.
                    : "The box was claimed but its credential was not stored. It must be"
                      + " unpaired on the box itself before it can be paired again.",
            );
            setGeneration((value) => value + 1);
            void refetch();
        } catch (error) {
            setMessage(error instanceof Error ? error.message : String(error));
        } finally {
            setBusy(false);
        }
    }

    async function forget(box: StoredBox): Promise<void> {
        await forgetBox(props.json, box.fingerprint);
        setGeneration((value) => value + 1);
        void refetch();
    }

    return (
        <section class="tokenwright-providers" aria-labelledby="tokenwright-boxes-heading">
            <header class="tokenwright-providers__header">
                <h3 id="tokenwright-boxes-heading">Your boxes</h3>
                <button
                    type="button"
                    class="tokenwright-providers__add"
                    aria-expanded={adding()}
                    onClick={() => { setAdding((open) => !open); setMessage(null); }}
                >
                    {adding() ? "Cancel" : "Add a box"}
                </button>
            </header>

            <Show when={adding()}>
                <form class="tokenwright-connect" onSubmit={add}>
                    <label class="tokenwright-connect__label" for="tokenwright-pairing-string">
                        Pairing string
                    </label>
                    <div class="tokenwright-connect__field">
                        <input
                            id="tokenwright-pairing-string"
                            class="tokenwright-connect__input"
                            // A live claim code for an unclaimed box, and this is
                            // the one place it is on screen — often while the
                            // operator reads it off another machine.
                            type={reveal() ? "text" : "password"}
                            autocomplete="off"
                            spellcheck={false}
                            placeholder="tw1_…"
                            disabled={busy()}
                            value={pairingString()}
                            onInput={(event) => setPairingString(event.currentTarget.value)}
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
                    <button
                        type="submit"
                        class="tokenwright-connect__submit"
                        disabled={busy() || !pairingString().trim()}
                    >
                        {busy() ? "Working…" : "Add box"}
                    </button>
                </form>
            </Show>

            <Show when={message()}>
                {(text) => (
                    <p
                        class="tokenwright-connect__message"
                        data-phase={busy() ? "working" : "failed"}
                        // Announced, because the outcome of pressing the button
                        // is text that appears somewhere else on the panel.
                        role="status"
                        aria-live="polite"
                    >
                        {text()}
                    </p>
                )}
            </Show>

            <Show
                when={rows().length > 0}
                fallback={
                    <p class="tokenwright-providers__empty">
                        No boxes yet. A TokenWright box serves models on hardware you
                        own, and is reached without opening a port on it.
                    </p>
                }
            >
                <ul class="tokenwright-providers__list">
                    <For each={rows()}>
                        {({ box, row }) => (
                            <li
                                class="tokenwright-providers__row"
                                data-reachability={row.reachability}
                            >
                                {/* Not colour alone: every state is in the row's
                                    own words too. */}
                                <span class="tokenwright-providers__dot" aria-hidden="true" />
                                <span class="tokenwright-providers__id">{row.boxId}</span>
                                <span class="tokenwright-providers__summary">{row.summary}</span>
                                <button
                                    type="button"
                                    class="tokenwright-providers__forget"
                                    onClick={() => void forget(box)}
                                >
                                    Forget
                                </button>
                            </li>
                        )}
                    </For>
                </ul>
            </Show>

            <p class="tokenwright-providers__note">
                Forgetting a box removes this account's only way to reach it. It does
                not unpair the box, which still serves the Home that claimed it — and
                the route cannot be recovered, so reaching it again means unpairing it
                in person.
            </p>
        </section>
    );
}
