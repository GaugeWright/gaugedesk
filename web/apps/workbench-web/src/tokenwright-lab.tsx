/**
 * Prototype bench for **Your boxes** on Provider Connections.
 *
 * It runs the real component against the real stylesheet, so what is agreed
 * here is what ships. Served in development only (`/tokenwright-lab.html`); no
 * shipped bundle names this entry.
 *
 * Two modes, and the difference between them is the point of the bench:
 *
 * - **fixtures** — one row per state, because the states are the design
 *   question. A box that is quiet and a box that is gone must not read alike.
 * - **live** — pointed at a real GaugeDesk control plane on loopback. Adding a
 *   box runs the actual journey: the *Home* parses the pairing string, dials
 *   the relay, pins the certificate, claims, and seals. This page sends one
 *   string and holds no capability at any point, which is exactly what it must
 *   be possible to see.
 */
import { createSignal, Show, type JSX } from "solid-js";
import { render } from "solid-js/web";
import {
    TokenWrightBoxesSection,
    type TokenWrightObservation,
} from "@gaugewright/workbench-ui";
import {
    browserRouteJson,
    type RouteJson,
    type StoredBox,
} from "@gaugewright/control-plane-client";
import "@gaugewright/workbench-ui/styles.css";

const MINUTE = 60_000;
const NOW = Date.now();

/** One fixture per state a row can be in. */
const FIXTURES: readonly (StoredBox & { readonly seen: TokenWrightObservation })[] = [
    {
        fingerprint: `sha256:${"ab".repeat(32)}`, relayEndpoint: "wss://relay.gaugewright.com",
        pairedAt: "2026-08-30T09:00:00Z", homeId: "home_a", keyId: "key_c30f", sealed: true,
        seen: { lastSeen: NOW - 4_000, models: ["tinyllama", "qwen2.5-7b", "llama-3.1-8b", "phi-4"] },
    },
    {
        fingerprint: `sha256:${"cd".repeat(32)}`, relayEndpoint: "wss://relay.gaugewright.com",
        pairedAt: "2026-08-12T14:00:00Z", homeId: "home_a", keyId: "key_44af", sealed: true,
        seen: { lastSeen: NOW - 22 * MINUTE, models: ["deepseek-v3.1-terminus"] },
    },
    {
        fingerprint: `sha256:${"ef".repeat(32)}`, relayEndpoint: "wss://relay.gaugewright.com",
        pairedAt: "2026-07-02T11:00:00Z", homeId: "home_a", keyId: "key_9b21", sealed: true,
        seen: { lastSeen: NOW - 5 * 60 * MINUTE, models: ["mistral-small"] },
    },
    {
        fingerprint: `sha256:${"01".repeat(32)}`, relayEndpoint: "wss://relay.gaugewright.com",
        pairedAt: "2026-09-01T08:00:00Z", homeId: "home_a", keyId: "key_7e30", sealed: true,
        seen: { lastSeen: NOW - 30_000, models: [] },
    },
    {
        fingerprint: `sha256:${"23".repeat(32)}`, relayEndpoint: "wss://relay.gaugewright.com",
        pairedAt: "2026-09-01T21:00:00Z", homeId: "home_a", keyId: "key_0c58", sealed: true,
        seen: {},
    },
    {
        // Recorded, unopenable. Listed and unreachable, and not because the box
        // is off — so it must not read as "not answering".
        fingerprint: `sha256:${"45".repeat(32)}`, relayEndpoint: "wss://relay.gaugewright.com",
        pairedAt: "2026-06-14T10:00:00Z", homeId: "home_a", keyId: "key_5f77", sealed: false,
        seen: { lastSeen: NOW - 9 * 60 * MINUTE, models: ["gemma-2-9b"] },
    },
];

const observations: Record<string, TokenWrightObservation> = Object.fromEntries(
    FIXTURES.map((fixture) => [fixture.fingerprint, fixture.seen]),
);

/** A stand-in Home that answers the three box routes from the fixtures, so the
 *  bench exercises the *component* without a control plane running. */
function fixtureHome(): RouteJson {
    let held = [...FIXTURES.map(({ seen: _seen, ...box }) => box)];
    return async (method, path) => {
        if (method === "GET" && path === "/account/boxes") return { boxes: held.map(toWire) };
        if (method === "POST" && path === "/account/boxes/claim") {
            // The Home is what would fail here, and it would fail with a
            // sentence. Standing in for that rather than succeeding is the
            // honest fixture: a bench that always paired would agree with
            // nothing.
            throw new Error(
                "No Home is running. Start one and switch this bench to live to"
                + " claim a real box.",
            );
        }
        const forgotten = /^\/account\/boxes\/([0-9a-f]{64})$/u.exec(path);
        if (method === "DELETE" && forgotten) {
            held = held.filter((box) => !box.fingerprint.endsWith(forgotten[1]!));
            return { forgotten: true };
        }
        throw new Error(`the bench does not answer ${method} ${path}`);
    };
}

function toWire(box: StoredBox): Record<string, unknown> {
    return {
        fingerprint: box.fingerprint,
        relay_endpoint: box.relayEndpoint,
        paired_at: box.pairedAt,
        home_id: box.homeId,
        key_id: box.keyId,
        sealed: box.sealed,
    };
}

function Bench(): JSX.Element {
    const [live, setLive] = createSignal(false);
    const fixtures = fixtureHome();
    // The real transport. `?home=` points the bench at a control plane on
    // another port; without it, this origin — which is what the shipped app
    // does, since the page is served by the Home it talks to.
    const base = new URLSearchParams(location.search).get("home") ?? "";
    const home = browserRouteJson(base);

    return (
        <div class="lab">
            <header class="lab-head">
                <h1>Your boxes — Provider Connections</h1>
                <p>
                    A TokenWright box is an OpenAI-compatible endpoint the person owns.
                    It is not a Project Host (it runs no Home) and not a GaugeApp (its
                    read models come from the box), so it sits with the other provider
                    connections in Account Settings.
                </p>
                <p class="lab-note">
                    Every box operation goes to the Home. Adding one sends a pairing
                    string and gets back a description — the Home parses it, dials the
                    relay, pins the certificate, claims, and seals. This page never
                    holds the box's route or key, and the list it reads has nowhere to
                    put them.
                </p>
                <label class="lab-actions">
                    <input type="checkbox" checked={live()}
                           onChange={(event) => setLive(event.currentTarget.checked)} />
                    Live — talk to a real control plane on this origin
                </label>
            </header>

            <div class="lab-stage">
                <Show
                    when={live()}
                    fallback={
                        <TokenWrightBoxesSection json={fixtures} observations={observations} />
                    }
                >
                    <TokenWrightBoxesSection json={home} />
                </Show>
            </div>
        </div>
    );
}

const mount = document.getElementById("root");
if (mount) render(() => <Bench />, mount);
