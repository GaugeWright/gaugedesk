/**
 * Paired boxes, kept where every other provider credential is kept: sealed on
 * the server, under the person's own account scope, never read back.
 *
 * ## What sealing costs, and why it is still right
 *
 * A browser that cannot read the route and the key **cannot open a tunnel to
 * the box**. That is not an oversight in this module; it is the point of it.
 * The two capabilities a box hands over are exactly what a person's browser
 * should not be holding — a browser is the thing most likely to be shared,
 * synced between machines, or extended by something nobody audited, and the
 * route in particular can never be reissued.
 *
 * So the shape here is deliberately lopsided:
 *
 * - {@link listBoxes} returns what is public — the relay endpoint, the
 *   certificate pin, when it was paired — which is everything a row needs.
 * - {@link recordPairedBox} sends the capabilities *up*, once, and nothing
 *   sends them back down.
 *
 * Reaching a box therefore happens through the runtime holding the seal, the
 * same way every other provider's token is used by the thing that has it rather
 * than by the page. A page that needs to reach a box asks the server to.
 */

import type { RouteJson } from "./control-plane-transport";
import type { TokenWrightConnection } from "./tokenwright-pairing";

/** A paired box as the account will describe it: no capability, ever. */
export interface StoredBox {
    /** `sha256:<hex>`, the box's stable public identity. */
    readonly fingerprint: string;
    readonly relayEndpoint: string;
    readonly pairedAt: string;
    readonly homeId: string;
    /** The id of the key the box minted — the id, never the secret. */
    readonly keyId: string;
    /** Whether the server still holds openable material for this box. A record
     * without it lists but cannot be reached, and saying so here is better than
     * discovering it when something tries. */
    readonly sealed: boolean;
}

function text(value: unknown): string {
    return typeof value === "string" ? value : "";
}

/** Every box this person has paired. */
export async function listBoxes(json: RouteJson): Promise<readonly StoredBox[]> {
    const answer = (await json("GET", "/account/boxes")) as { boxes?: unknown };
    const rows = Array.isArray(answer?.boxes) ? answer.boxes : [];
    return rows.map((row) => {
        const record = (row ?? {}) as Record<string, unknown>;
        return {
            fingerprint: text(record.fingerprint),
            relayEndpoint: text(record.relay_endpoint),
            pairedAt: text(record.paired_at),
            homeId: text(record.home_id),
            keyId: text(record.key_id),
            sealed: record.sealed === true,
        };
    });
}

/**
 * Seal a box that was just claimed.
 *
 * **This is the only moment the route exists anywhere but on the box.** A claim
 * that succeeded and was not recorded has spent a single-use code and lost the
 * box — recovering it means unpairing in person — so a caller must treat a
 * failure here as that severe rather than as a save it can retry later from
 * memory it no longer has.
 */
export async function recordPairedBox(
    json: RouteJson,
    connection: TokenWrightConnection,
): Promise<StoredBox> {
    const answer = (await json("POST", "/account/boxes", {
        fingerprint: connection.fingerprint,
        route: connection.route,
        key: connection.key,
        relay_endpoint: connection.relayEndpoint,
        paired_at: connection.pairedAt,
        home_id: connection.homeId,
        key_id: connection.keyId,
    })) as Record<string, unknown>;
    return {
        fingerprint: text(answer?.fingerprint) || connection.fingerprint,
        relayEndpoint: text(answer?.relay_endpoint) || connection.relayEndpoint,
        pairedAt: connection.pairedAt,
        homeId: connection.homeId,
        keyId: connection.keyId,
        sealed: answer?.sealed === true,
    };
}

/**
 * Forget a box.
 *
 * The box is untouched and still serves the Home that claimed it. What goes is
 * this account's only copy of how to reach it, and nothing can reissue that.
 */
export async function forgetBox(json: RouteJson, fingerprint: string): Promise<void> {
    const bare = fingerprint.replace(/^sha256:/, "");
    await json("DELETE", `/account/boxes/${encodeURIComponent(bare)}`);
}
