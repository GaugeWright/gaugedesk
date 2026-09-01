import { afterEach, describe, expect, it, vi } from "vitest";

import { setTunnelModuleLoader } from "./tunnel-module";
import { openTokenWrightBox } from "./tokenwright-transport";
import type { OpaqueRelayLocator } from "./home-routing";

const LOCATOR: OpaqueRelayLocator = {
    endpoint: "wss://relay.example",
    handle: "F8E0l3whZo41YL6B8yzSJAQdF8E0l3whZo41YL6B8yw",
    proof: "gfpUk0DpnlGVnz40Ug6dYPPBd5DPBjVVIxZBpuqjj1c",
    routeEpoch: 1,
    homeFingerprint: "ab".repeat(32),
};

afterEach(() => {
    setTunnelModuleLoader(null);
    vi.unstubAllGlobals();
});

describe("opening a box", () => {
    it("refuses when this build carries no tunnel", () => {
        // A box reached only through a relay has no other path — unlike a Home,
        // there is no endpoint to fall back to. Handing back a route that cannot
        // connect would move the failure to the first click.
        setTunnelModuleLoader(null);
        expect(() => openTokenWrightBox(LOCATOR)).toThrow(/no other way/);
    });

    it("reports the pin it enforced, in the spelling the box uses", async () => {
        // The tunnel is constructed with the pin and refuses anything else, so
        // there is no separate value to read back. What this asserts is that a
        // caller comparing it against a claim response compares like with like:
        // the documents carry `sha256:`, the tunnel wants bare hex.
        setTunnelModuleLoader(async () => ({
            default: async () => undefined,
            BrowserTunnel: class {
                static relayHandshake(): Uint8Array { return new Uint8Array(84); }
            },
        }) as never);
        const route = openTokenWrightBox(LOCATOR);
        expect(route.presentedFingerprint).toBe(`sha256:${"ab".repeat(32)}`);
        route.close();
    });

    it("dials the relay path the handle names", async () => {
        // The URL is the one thing here that is not checked by anything else:
        // a wrong path is a socket that opens against the relay and never pairs.
        const opened: string[] = [];
        vi.stubGlobal("WebSocket", class {
            binaryType = "";
            onopen: (() => void) | null = null;
            onerror: (() => void) | null = null;
            onclose: (() => void) | null = null;
            onmessage: ((event: MessageEvent) => void) | null = null;
            constructor(url: string) {
                opened.push(url);
                queueMicrotask(() => this.onopen?.());
            }
            send(): void {}
            close(): void {}
        });
        setTunnelModuleLoader(async () => ({
            default: async () => undefined,
            BrowserTunnel: class {
                static relayHandshake(): Uint8Array { return new Uint8Array(84); }
                isHandshaking(): boolean { return false; }
                isPaired(): boolean { return false; }
                receiveFrame(): void {}
                takeOutgoing(): Uint8Array { return new Uint8Array(); }
                pollStatus(): number | undefined { return undefined; }
                sendRequest(): void {}
            },
        }) as never);

        const route = openTokenWrightBox(LOCATOR, { timeoutMs: 20 });
        await route.json("GET", "/v1/models").catch(() => undefined);
        expect(opened).toEqual([`wss://relay.example/v1/relay/${LOCATOR.handle}`]);
        route.close();
    });
});
