/**
 * A TokenWright box as a row on **Provider Connections**.
 *
 * Deciding where a box belongs is most of this file's value, so the reasoning
 * is here rather than in a commit message nobody will find.
 *
 * A box is not a [[Project Host]]: it runs no Home and hosts no project work.
 * It is not a GaugeApp either — those have first-party read models built by our
 * own server, and ADR 0158's whole point is that a box's control plane is *not*
 * ours. What a box actually is, in the words of its own ADR, is the thing that
 * "takes the place of `api.openai.com` for that Home": an OpenAI-compatible
 * endpoint the person owns. That is a **provider connection**, and it sits
 * beside the other ones in Account Settings.
 *
 * It differs from every other provider connection in three ways, and each is a
 * consequence of owning the machine rather than renting an API:
 *
 * - **You do not type a key.** The box mints one and hands it over during
 *   pairing, exactly once. There is no field to paste into.
 * - **You do not type an endpoint.** A box has no inbound port by design; it is
 *   reached at a rendezvous on a blind relay, and the route is a capability
 *   rather than an address.
 * - **Its model list is not operator-declared.** An OpenAI-compatible
 *   connection asks the operator to state which models exist, because nothing
 *   can check. A box publishes its own inference document, so the list is
 *   observed — and therefore has to be freshness-labelled, because observed
 *   facts go stale and declared ones do not.
 *
 * This module is the pure fold from what the account holds about a box, plus
 * whatever the box last said, into the row the page paints. It performs no I/O
 * and decides no truth about reachability: it is told when the box was last
 * heard from.
 *
 * What it is given is deliberately thin. A `StoredBox` carries the relay
 * endpoint, the certificate pin, and when it was paired — and neither the route
 * nor the key, because those are sealed in the account and a page never holds
 * them. The row could not leak a capability if it tried.
 */

import type { StoredBox } from "@gaugewright/control-plane-client";

/**
 * How much the row can honestly claim right now.
 *
 * `unreachable` and `stale` are deliberately different. A box that answered
 * four seconds ago and one that answered four days ago are both "not answering
 * this instant", and collapsing them would tell an operator to go check a
 * machine that is fine — or let a genuinely dead one look merely quiet.
 */
export type TokenWrightReachability =
    | "connected"
    | "stale"
    | "unreachable"
    | "never-reached"
    /** Recorded, but the Home can no longer open its credential. Not a
     *  reachability state at all — it is why reachability cannot be asked. */
    | "unusable";

export interface TokenWrightProviderRow {
    readonly boxId: string;
    readonly relayEndpoint: string;
    /** Truncated for display. The full pin belongs in the box's own detail. */
    readonly fingerprint: string;
    readonly reachability: TokenWrightReachability;
    /** Observed from the box's inference document, never declared by a person. */
    readonly models: readonly string[];
    /** Words, not a timestamp: the row is one line and a person reads it in
     * passing. `null` when there is nothing honest to say yet. */
    readonly freshness: string | null;
    /** One line. A person may own several boxes and many models. */
    readonly summary: string;
}

/** Past this, a last-seen time is old enough that repeating it as fact would be
 * misleading rather than informative. Ten minutes is roughly the point at which
 * "just now" stops being true for a machine that reports on connect. */
const STALE_AFTER_MS = 10 * 60 * 1000;
/** Past this, the box has not been heard from across anything that looks like a
 * working day, and the row should say so plainly rather than keep hedging. */
const UNREACHABLE_AFTER_MS = 60 * 60 * 1000;

function ago(milliseconds: number): string {
    const seconds = Math.floor(milliseconds / 1000);
    if (seconds < 60) return "just now";
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes} minute${minutes === 1 ? "" : "s"} ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours} hour${hours === 1 ? "" : "s"} ago`;
    const days = Math.floor(hours / 24);
    return `${days} day${days === 1 ? "" : "s"} ago`;
}

export interface TokenWrightObservation {
    /** When the box last answered, in epoch milliseconds. */
    readonly lastSeen?: number;
    /** The `models.present` the box's inference document reported. */
    readonly models?: readonly string[];
    /** The box's own view of its engine, if it was asked. */
    readonly engineStatus?: string;
}

/**
 * Build the row.
 *
 * `now` is a parameter because a row that reads the clock cannot be tested for
 * the boundary that matters — the moment "connected" becomes "stale".
 */
export function tokenwrightProviderRow(
    box: StoredBox,
    observation: TokenWrightObservation = {},
    now: number = Date.now(),
): TokenWrightProviderRow {
    if (!box.sealed) {
        // Listed and unreachable. Saying "not answering" would send someone to
        // look at a machine that is fine: nothing here can open the credential,
        // so nothing will ever dial it, and the fix is to pair it again rather
        // than to go and check the box.
        return {
            boxId: box.keyId || box.fingerprint.replace(/^sha256:/, "").slice(0, 12),
            relayEndpoint: box.relayEndpoint,
            fingerprint: `${box.fingerprint.slice(0, 17)}…`,
            reachability: "unusable",
            models: [],
            freshness: null,
            summary: "Its stored credential cannot be opened — pair this box again",
        };
    }
    const models = [...(observation.models ?? [])];
    const seen = observation.lastSeen;
    const age = typeof seen === "number" && Number.isFinite(seen) ? now - seen : null;

    let reachability: TokenWrightReachability;
    if (age === null) reachability = "never-reached";
    // A clock that has gone backwards — a laptop waking, a corrected NTP step —
    // must not read as a box from the future. Treat it as just seen.
    else if (age < 0) reachability = "connected";
    else if (age < STALE_AFTER_MS) reachability = "connected";
    else if (age < UNREACHABLE_AFTER_MS) reachability = "stale";
    else reachability = "unreachable";

    const freshness = age === null ? null : ago(Math.max(0, age));

    let summary: string;
    if (reachability === "never-reached") {
        summary = "Paired, not yet reached";
    } else if (reachability === "unreachable") {
        // Named as evidence rather than diagnosis. From here a box that is off,
        // a relay that is down, and a network in between look identical, and
        // saying "offline" would be picking one of them without grounds.
        summary = `Not answering — last seen ${freshness}`;
    } else if (models.length === 0) {
        // A reachable box with no model is a real and ordinary state: it is
        // installed and paired, and nothing has been loaded onto it.
        summary = reachability === "stale"
            ? `No model loaded — last seen ${freshness}`
            : "No model loaded";
    } else {
        const named = models.length <= 2
            ? models.join(", ")
            : `${models.slice(0, 2).join(", ")} +${models.length - 2}`;
        summary = reachability === "stale" ? `${named} — last seen ${freshness}` : named;
    }

    return {
        boxId: box.keyId || box.fingerprint.replace(/^sha256:/, "").slice(0, 12),
        relayEndpoint: box.relayEndpoint,
        fingerprint: `${box.fingerprint.slice(0, 17)}…`,
        reachability,
        models,
        freshness,
        summary,
    };
}
