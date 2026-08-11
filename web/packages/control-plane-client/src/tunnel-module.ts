/**
 * Wiring the browser tunnel's wasm module (DESK-7).
 *
 * The module is a *build artifact* — `scripts/build-wasm-tunnel.sh` produces it
 * and it is gitignored — so this package never imports it directly. It could
 * not: a fresh checkout has no such file, and an unresolvable import would
 * either break every typecheck or be dodged with a cast that stops describing
 * anything.
 *
 * Instead the app registers a loader once, at the edge that knows the build
 * produced one. The seam is the same one used everywhere else here: injection
 * keeps this file testable, and keeps the failure mode explicit.
 */

import type { OpaqueRelayLocator } from "./home-routing";
import type { TunnelFacade } from "./tunnel-route-json";

/** What the generated module exports. Declared so a change to the Rust
 * binding's names is a type error here rather than a runtime failure in a
 * browser. */
export interface TunnelModule {
    readonly BrowserTunnel: {
        new (homeFingerprint: string): TunnelFacade;
        relayHandshake(endpoint: string, handle: string, proof: string, epoch: number): Uint8Array;
    };
}

let loader: (() => Promise<TunnelModule>) | null = null;
let loaded: Promise<TunnelModule> | null = null;

/**
 * Register how to obtain the tunnel module. The app calls this once, with an
 * import of the generated artifact; a test calls it with a stand-in.
 */
export function setTunnelModuleLoader(next: (() => Promise<TunnelModule>) | null): void {
    loader = next;
    loaded = null;
}

async function load(): Promise<TunnelModule> {
    if (!loader) {
        // Said plainly, because the alternative diagnosis — a Home that is
        // simply unreachable — sends someone to the network instead of the build.
        throw new Error(
            "the browser tunnel is not available: no module loader registered "
                + "(run scripts/build-wasm-tunnel.sh and register it at startup)",
        );
    }
    loaded ??= loader().catch((error) => {
        loaded = null;
        throw new Error(
            `the browser tunnel module failed to load: ${
                error instanceof Error ? error.message : String(error)
            }`,
        );
    });
    return loaded;
}

/** Whether a browser can tunnel at all. Callers use this to decide between a
 * relay locator and a direct endpoint rather than discovering it by failing. */
export function tunnelAvailable(): boolean {
    return loader !== null;
}

/** A tunnel pinned to one Home, and the handshake for its route. */
export async function openTunnel(
    locator: OpaqueRelayLocator,
): Promise<{ tunnel: TunnelFacade; handshake: Uint8Array }> {
    const module = await load();
    return {
        tunnel: new module.BrowserTunnel(locator.homeFingerprint),
        handshake: module.BrowserTunnel.relayHandshake(
            locator.endpoint,
            locator.handle,
            locator.proof,
            locator.routeEpoch,
        ),
    };
}
