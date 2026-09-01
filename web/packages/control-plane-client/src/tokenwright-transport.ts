/**
 * Opening a pinned tunnel to a TokenWright box.
 *
 * This is the glue the connection journey needs and the only piece that touches
 * a socket: `tokenwright-pairing.ts` decides *where* to dial and what to prove,
 * and this dials it. It lives in `control-plane-client` because that is the
 * declared transport owner (`scripts/architecture-check.py`), and it is built
 * from the same three pieces every other carried Home uses — `openTunnel`,
 * `browserTunnelSocket`, `tunnelRouteJson` — because a box is not special
 * enough to deserve its own transport.
 *
 * ## What "the fingerprint the transport presented" means here
 *
 * The tunnel is *constructed with* the pin. `BrowserTunnel` refuses any
 * certificate whose DER does not hash to it, with no chain to build and no
 * authority to consult — so there is no separate value to read back afterwards
 * and asking for one would be inventing an observation.
 *
 * What can be said, and is what the claim check actually needs, is stronger
 * than an observation: **a request completed at all, therefore the pin held.**
 * So the pin is reported as presented once the tunnel has carried something,
 * and the check in `claimTokenWrightBox` compares it against what the box says
 * about itself in the response body. Those are two different layers — one is
 * what TLS verified, the other is a field the box authored — and a box that
 * disagrees with its own certificate is not one to keep talking to.
 */

import type { OpaqueRelayLocator } from "./home-routing";
import { browserTunnelSocket, tunnelRouteJson } from "./tunnel-route-json";
import { openTunnel, tunnelAvailable } from "./tunnel-module";

/** A tunnel to one box, and the way to hang it up.
 *
 * Hanging up is not optional. The box holds a leg parked against the relay and
 * neither end notices a caller losing interest, so a tunnel whose owner has gone
 * leaves that leg spliced — and every later attempt to reach the box waits for a
 * splice that cannot happen. Dropping the reference does not close this.
 */
export interface TokenWrightBoxRoute {
    readonly json: (method: string, path: string, body?: unknown) => Promise<unknown>;
    /** The pin the transport enforced. See the note above on what this asserts. */
    readonly presentedFingerprint: string;
    readonly close: () => void;
}

export interface OpenTokenWrightBoxOptions {
    /** The box's key, read per call so a rotated one is used without rebuilding
     * the route. Absent while claiming, which is the one unauthenticated call a
     * box answers. */
    readonly bearer?: () => string | null;
    readonly timeoutMs?: number;
}

/**
 * Dial a box at a locator and return a route over the pinned tunnel.
 *
 * Throws when this build carries no wasm tunnel. A box reached only through a
 * relay has no other path — there is no endpoint to fall back to, unlike a Home
 * — so failing here says the one true thing rather than producing a route that
 * cannot connect.
 */
export function openTokenWrightBox(
    locator: OpaqueRelayLocator,
    options: OpenTokenWrightBoxOptions = {},
): TokenWrightBoxRoute {
    if (!tunnelAvailable()) {
        throw new Error(
            "This build cannot open a relay tunnel, and a TokenWright box is reachable no other way.",
        );
    }
    const route = tunnelRouteJson({
        open: async () => {
            const { tunnel, handshake } = await openTunnel(locator);
            const url = `${locator.endpoint}/v1/relay/${locator.handle}`;
            return { tunnel, socket: await browserTunnelSocket(url, handshake) };
        },
        bearer: options.bearer,
        timeoutMs: options.timeoutMs,
    });
    return {
        json: (method, path, body) => route(method, path, body),
        // Restored to the spelling the box's own documents use, so a caller
        // comparing this against a claim response is comparing like with like.
        presentedFingerprint: `sha256:${locator.homeFingerprint.replace(/^sha256:/, "")}`,
        close: () => route.close(),
    };
}
