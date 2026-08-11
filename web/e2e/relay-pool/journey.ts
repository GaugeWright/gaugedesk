/**
 * DESK-7's joined lane: a project resolved through the pool, admitted through
 * the tunnel the pool built.
 *
 * The two halves were each proved and neither joined. `browser_journey.rs`
 * drives `BrowserTunnel` in a real browser, but builds it straight from the
 * harness description — it never asks the pool for anything. `home-pool.test.ts`
 * drives `HomePool.connectProject` over a stubbed `RouteJson` — it never touches
 * wasm, a relay, or a Home. So the seam between them, `HomePool` → `routeJson`
 * → `openTunnel` → `browserTunnelSocket`, was the one part of the browser's path
 * to a relay-only Home that nothing executed.
 *
 * This runs that seam in a real browser against `examples/hermetic-home.rs`:
 * real wasm, a real relay splice, and a real parked Home leg. The route it
 * resolves has **no endpoint at all**, so there is no direct path to fall back
 * to — the admission arrives over the tunnel or not at all.
 *
 * The negative is what makes the positive mean something. A pool given a route
 * naming a Home the responder is not must refuse it, and it must refuse *after*
 * a working tunnel, since a broken tunnel would also fail and prove nothing.
 * Both cases dial the same live Home; only the claimed identity differs.
 */

import {
    HomePool,
    browserTunnelSocket,
    openTunnel,
    setTunnelModuleLoader,
    tunnelRouteJson,
    type HomeId,
    type OpaqueHomeRoute,
    type ProjectId,
    type RouteJson,
    type TunnelRoute,
} from "@gaugewright/control-plane-client";

/** Where `examples/hermetic-home.rs` publishes itself. Fixed, because the
 * relay's own port is ephemeral and this page cannot be told it any other way. */
const CONFIG_URL = "http://127.0.0.1:7908/";

/** Any id will do — the point is that the pool routes *per project*, and this
 * one is routed to a Home with no endpoint. */
const PROJECT = "proj-hermetic" as ProjectId;

interface HarnessDescription {
    readonly relay_endpoint: string;
    readonly handle: string;
    readonly proof: string;
    readonly route_epoch: number;
    readonly home_fingerprint: string;
    readonly home_id: string;
}

export interface JourneyResult {
    readonly homeId: string;
    readonly state: string;
    /** The Home reached by id alone, with no project named (DESK-8). */
    readonly byHome: string;
    /** How the pool refused a route naming the wrong Home. */
    readonly mismatch: string;
}

/** The registration the deployed app performs in `wasm-modules.ts`. Repeated
 * rather than imported so this lane depends on the transport, not on one host's
 * startup file. */
setTunnelModuleLoader(async () => {
    const module = await import("@gaugewright/control-plane-client/generated/tunnel.js");
    await module.default();
    return module;
});

function routeTo(homeId: string, description: HarnessDescription): OpaqueHomeRoute {
    return {
        project: PROJECT,
        homeId: homeId as HomeId,
        // The whole point: nothing to dial. A pool that quietly used an endpoint
        // here would prove the fast path and pass just as green.
        endpoint: "",
        relay: {
            endpoint: description.relay_endpoint,
            handle: description.handle,
            proof: description.proof,
            routeEpoch: description.route_epoch,
            homeFingerprint: description.home_fingerprint,
        },
    };
}

function poolFor(route: OpaqueHomeRoute): HomePool<{ json: RouteJson }> {
    // The app's own wiring (`workbench-control-plane.ts`), which is what makes
    // this a test of the seam rather than of a fixture built to pass.
    const tunnels = new Map<HomeId, TunnelRoute>();
    return new HomePool<{ json: RouteJson }>([route], () => "hermetic-bearer", {
        routeJson: (_endpoint, _auth, resolved) => {
            const carried = tunnelRouteJson({
                open: async () => {
                    const relay = resolved.relay!;
                    const { tunnel, handshake } = await openTunnel(relay);
                    const url = `${relay.endpoint}/v1/relay/${relay.handle}`;
                    return { tunnel, socket: await browserTunnelSocket(url, handshake) };
                },
            });
            tunnels.get(resolved.homeId)?.close();
            tunnels.set(resolved.homeId, carried);
            return carried;
        },
        closeRoute: async (homeId) => {
            tunnels.get(homeId)?.close();
            tunnels.delete(homeId);
        },
        client: (context) => ({ json: context.routeJson }),
    });
}

export async function runJourney(): Promise<JourneyResult> {
    const response = await fetch(CONFIG_URL);
    if (!response.ok) throw new Error(`the hermetic harness answered ${response.status}`);
    const description = (await response.json()) as HarnessDescription;

    const pool = poolFor(routeTo(description.home_id, description));
    const connection = await pool.connectProject(PROJECT);
    if (connection.homeId !== description.home_id) {
        throw new Error(`the pool connected ${connection.homeId}`);
    }
    if (connection.state !== "live") {
        throw new Error(`the connection settled ${connection.state}`);
    }

    // Hang up before dialing again, and note what that costs to get wrong: the
    // Home stays spliced to a client that has gone, never re-parks, and the
    // second dial waits out its timeout against a Home that is running fine.
    // This is the `closeRoute` seam doing its job, not test hygiene.
    await pool.closeAll();

    // Reaching the Home by id alone, with no project named (DESK-8, ADR 0134
    // §3). This is the path that serves the chat list — the work a person does
    // *before* there is a project open — and without it nothing in a browser
    // ever arrives at a relay-only Home at all. A fresh pool, so this opens its
    // own tunnel rather than inheriting the one above.
    const account = poolFor(routeTo(description.home_id, description));
    const byHome = await account.connectHome(description.home_id as HomeId);
    if (byHome.homeId !== description.home_id) {
        throw new Error(`connectHome reached ${byHome.homeId}`);
    }
    await account.closeAll();

    // The same Home, reached the same way, claimed to be someone else. The
    // admission succeeds and the pool throws it away, which is the check.
    const wrong = poolFor(routeTo("home:not-the-hermetic-one", description));
    let mismatch = "";
    try {
        await wrong.connectProject(PROJECT);
    } catch (error) {
        mismatch = error instanceof Error ? error.message : String(error);
    }
    await wrong.closeAll();
    if (!/Home identity mismatch/.test(mismatch)) {
        throw new Error(`a Home answering as another id was accepted: ${mismatch || "no error"}`);
    }
    return { homeId: connection.homeId, state: connection.state, byHome: byHome.homeId, mismatch };
}

declare global {
    interface Window {
        __relayPoolJourney?: { ok: true; result: JourneyResult } | { ok: false; error: string };
    }
}

void runJourney().then(
    (result) => { window.__relayPoolJourney = { ok: true, result }; },
    (error: unknown) => {
        window.__relayPoolJourney = {
            ok: false,
            error: error instanceof Error ? `${error.message}\n${error.stack ?? ""}` : String(error),
        };
    },
);
