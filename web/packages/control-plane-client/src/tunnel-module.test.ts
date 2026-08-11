import { afterEach, describe, expect, it } from "vitest";
import {
    openTunnel,
    setTunnelModuleLoader,
    tunnelAvailable,
    type TunnelModule,
} from "./tunnel-module";
import type { OpaqueRelayLocator } from "./home-routing";

const locator: OpaqueRelayLocator = {
    endpoint: "wss://relay.example",
    handle: "A".repeat(43),
    proof: "B".repeat(42) + "A",
    routeEpoch: 4,
    homeFingerprint: "ab".repeat(32),
};

function stub(): TunnelModule {
    return {
        BrowserTunnel: class {
            static relayHandshake(_e: string, _h: string, _p: string, epoch: number) {
                return new Uint8Array([epoch]);
            }
            constructor(public fingerprint: string) {}
            receiveFrame() {}
            sendRequest() {}
            takeOutgoing() { return new Uint8Array(); }
            pollStatus() { return undefined; }
            takeBody() { return ""; }
            isHandshaking() { return true; }
        } as unknown as TunnelModule["BrowserTunnel"],
    };
}

afterEach(() => setTunnelModuleLoader(null));

describe("the browser tunnel module seam (DESK-7)", () => {
    it("says the tunnel is unavailable rather than letting a Home look unreachable", async () => {
        expect(tunnelAvailable()).toBe(false);
        await expect(openTunnel(locator)).rejects.toThrow(/not available|build-wasm-tunnel/);
    });

    it("opens a tunnel pinned to the Home and hands back its route handshake", async () => {
        setTunnelModuleLoader(async () => stub());
        expect(tunnelAvailable()).toBe(true);
        const { tunnel, handshake } = await openTunnel(locator);
        expect((tunnel as unknown as { fingerprint: string }).fingerprint).toBe(locator.homeFingerprint);
        expect(handshake).toEqual(new Uint8Array([4]));
    });

    it("names the build when the module itself fails to load", async () => {
        setTunnelModuleLoader(async () => { throw new Error("wasm fetch 404"); });
        await expect(openTunnel(locator)).rejects.toThrow(/failed to load: wasm fetch 404/);
    });

    it("retries a failed load rather than caching the failure forever", async () => {
        let attempts = 0;
        setTunnelModuleLoader(async () => {
            attempts += 1;
            if (attempts === 1) throw new Error("cold start");
            return stub();
        });
        await expect(openTunnel(locator)).rejects.toThrow(/cold start/);
        await expect(openTunnel(locator)).resolves.toBeTruthy();
        expect(attempts).toBe(2);
    });
});
