import { describe, expect, it } from "vitest";
import { tunnelRouteJson, type TunnelFacade, type TunnelSocket } from "./tunnel-route-json";
import type { OpaqueRelayLocator } from "./home-routing";

const locator: OpaqueRelayLocator = {
    endpoint: "wss://relay.example",
    handle: "A".repeat(43),
    proof: "B".repeat(42) + "A",
    routeEpoch: 1,
    homeFingerprint: "ab".repeat(32),
};

/** A tunnel that answers after `afterPumps` pumps, so the loop's polling is
 * exercised rather than short-circuited. */
function fakeTunnel(replies: Array<{ status: number; body: string }>, afterPumps = 2): TunnelFacade & { sent: string[] } {
    let pumps = 0;
    const sent: string[] = [];
    return {
        sent,
        receiveFrame: () => undefined,
        sendRequest: (method, path, body) => {
            pumps = 0;
            sent.push(`${method} ${path} ${body ?? ""}`.trim());
        },
        takeOutgoing: () => (pumps === 0 ? new Uint8Array([0, 1, 2]) : new Uint8Array()),
        pollStatus: () => {
            pumps += 1;
            return pumps > afterPumps ? replies[0]?.status : undefined;
        },
        takeBody: () => replies.shift()?.body ?? "",
        isHandshaking: () => false,
    };
}

function fakeSocket() {
    const frames: Uint8Array[] = [];
    let onClose = () => {};
    const socket: TunnelSocket = {
        send: (frame) => frames.push(frame),
        close: () => onClose(),
        onFrame: () => undefined,
        onClose: (handler) => { onClose = handler; },
    };
    return { socket, frames, drop: () => onClose() };
}

function build(tunnel: TunnelFacade, socket: TunnelSocket, timeoutMs = 30_000, clock?: () => number) {
    return tunnelRouteJson({
        open: async () => ({ tunnel, socket }),
        tick: async () => undefined,
        timeoutMs,
        ...(clock ? { now: clock } : {}),
    });
}

describe("routeJson over the tunnel (DESK-7)", () => {
    it("carries a request and parses the Home's reply", async () => {
        const tunnel = fakeTunnel([{ status: 201, body: '{"home":"home:a","admission":"t"}' }]);
        const { socket, frames } = fakeSocket();
        const json = build(tunnel, socket);
        await expect(json("POST", "/home/admissions")).resolves.toEqual({
            home: "home:a",
            admission: "t",
        });
        expect(tunnel.sent).toEqual(["POST /home/admissions"]);
        expect(frames.length).toBeGreaterThan(0);
    });

    it("raises the Home's refusal rather than returning it as a value", async () => {
        const tunnel = fakeTunnel([{ status: 403, body: "Home has no active owner" }]);
        const { socket } = fakeSocket();
        await expect(build(tunnel, socket)("POST", "/home/admissions")).rejects.toThrow(/403/);
    });

    it("serializes requests, because one stream cannot interleave two", async () => {
        const tunnel = fakeTunnel([
            { status: 200, body: '{"n":1}' },
            { status: 200, body: '{"n":2}' },
        ]);
        const { socket } = fakeSocket();
        const json = build(tunnel, socket);
        const [first, second] = await Promise.all([json("GET", "/a"), json("GET", "/b")]);
        expect([first, second]).toEqual([{ n: 1 }, { n: 2 }]);
        expect(tunnel.sent).toEqual(["GET /a", "GET /b"]);
    });

    it("fails the call when the tunnel stops answering", async () => {
        const tunnel: TunnelFacade = {
            receiveFrame: () => undefined,
            sendRequest: () => undefined,
            takeOutgoing: () => new Uint8Array(),
            pollStatus: () => undefined,
            takeBody: () => "",
            isHandshaking: () => true,
        };
        const { socket } = fakeSocket();
        let clock = 0;
        const json = build(tunnel, socket, 50, () => (clock += 30));
        await expect(json("GET", "/workspace")).rejects.toThrow(/timed out/);
    });

    it("does not wedge later requests behind a failed one", async () => {
        const tunnel = fakeTunnel([
            { status: 500, body: "boom" },
            { status: 200, body: '{"ok":true}' },
        ]);
        const { socket } = fakeSocket();
        const json = build(tunnel, socket);
        await expect(json("GET", "/a")).rejects.toThrow(/500/);
        await expect(json("GET", "/b")).resolves.toEqual({ ok: true });
    });
});
