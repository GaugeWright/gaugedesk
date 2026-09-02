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
 * - {@link claimBox} hands the Home a pairing string; the capabilities are
 *   obtained, sealed, and used without ever entering a page.
 *
 * Reaching a box therefore happens through the runtime holding the seal, the
 * same way every other provider's token is used by the thing that has it rather
 * than by the page. A page that needs to reach a box asks the server to.
 */

import type { RouteJson } from "./control-plane-transport";

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
 * Claim a box and have the Home seal what it hands over.
 *
 * The browser sends the pairing string and nothing comes back but the public
 * description. It does not parse the string, derive a rendezvous, dial a relay,
 * or pin a certificate — the Home does all of that, because the Home is what
 * holds the credential afterwards.
 *
 * That is a correction, not a simplification. A page used to run this journey
 * over the wasm tunnel, which exists to reach **a Home that is not publicly
 * addressable** (ADR 0130) and is keyed by Home id everywhere it is used. A box
 * is not a Home; it is a peer of one, like every other provider.
 */
export async function claimBox(json: RouteJson, pairingString: string): Promise<StoredBox> {
    const answer = (await json("POST", "/account/boxes/claim", {
        pairing_string: pairingString,
    })) as Record<string, unknown>;
    return {
        fingerprint: text(answer?.fingerprint),
        relayEndpoint: text(answer?.relay_endpoint),
        pairedAt: text(answer?.paired_at),
        homeId: text(answer?.home_id),
        keyId: text(answer?.key_id),
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
    const bare = encodeURIComponent(fingerprint.replace(/^sha256:/, ""));
    await json("DELETE", `/account/boxes/${encodeURIComponent(bare)}`);
}

/**
 * A `RouteJson` that reaches one box **through the Home**.
 *
 * The existing management functions take a transport and do not care what it
 * is, so `openManagementEnvironment(boxRouteJson(json, fingerprint),
 * "tokenwright")` works unchanged. That is the whole point of the shape: what
 * changed is which side of the wire holds the credential, not the surface.
 *
 * It replaces a tunnel the page opened for itself. A page cannot dial a box any
 * more — the box's key is sealed in the account, and the wasm tunnel it used to
 * borrow exists to reach a Home that is not publicly addressable (ADR 0130),
 * which a box is not.
 *
 * The Home carries only the operations the peer contract declares, so a path
 * this repository has not declared returns 404 from the Home rather than
 * reaching the box. That is deliberate: the alternative is a courier that would
 * carry a page's request to a box's model surface under a key the page never
 * had.
 */
export function boxRouteJson(json: RouteJson, fingerprint: string): RouteJson {
    const bare = encodeURIComponent(fingerprint.replace(/^sha256:/, ""));
    return (method, path, body, options) => {
        // The box's path, prefixed. Nothing is rewritten: a proxy that
        // understood the surface would be a second copy of it here.
        // The literal `/` before the dynamic part is not styling: the contract
        // checks read these template literals textually, and a `${…}` appended
        // straight onto `surface` reads as part of that segment rather than as
        // the path it is.
        const suffix = path.startsWith("/") ? path.slice(1) : path;
        return json(method, `/account/boxes/${bare}/surface/${suffix}`, body, options);
    };
}
