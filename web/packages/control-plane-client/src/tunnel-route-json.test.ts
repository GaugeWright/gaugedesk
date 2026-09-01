import { describe, expect, it } from "vitest";
import { TurnStopped, TURN_STOPPED_STATUS } from "./control-plane-domain";
import { tunnelRouteJson, type TunnelFacade, type TunnelSocket } from "./tunnel-route-json";

/** A tunnel that answers after `afterPumps` pumps, so the loop's polling is
 * exercised rather than short-circuited. */
function fakeTunnel(
    replies: Array<{ status: number; body: string }>,
    afterPumps = 2,
    paired = true,
): TunnelFacade & { sent: string[]; headers: Array<Record<string, string> | undefined> } {
    let pumps = 0;
    const sent: string[] = [];
    const headers: Array<Record<string, string> | undefined> = [];
    return {
        sent,
        headers,
        isPaired: () => paired,
        receiveFrame: () => undefined,
        sendRequest: (method, path, body, extra) => {
            pumps = 0;
            sent.push(`${method} ${path} ${body ?? ""}`.trim());
            headers.push(extra);
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

    it("carries a bearer, because a carried surface may admit nothing without one", async () => {
        // A TokenWright box requires `Authorization` on every request. Before
        // this, a browser could reach one, claim it, and then never use it —
        // the binding built a header map holding only `content-type`.
        const tunnel = fakeTunnel([{ status: 200, body: "{}" }]);
        const { socket } = fakeSocket();
        const json = tunnelRouteJson({
            open: async () => ({ tunnel, socket }),
            tick: async () => undefined,
            bearer: () => "tw_secret",
        });
        await json("GET", "/v1/models");
        expect(tunnel.headers[0]).toEqual({ authorization: "Bearer tw_secret" });
    });

    it("reads the bearer per call, so a rotated key is used without rebuilding", async () => {
        const tunnel = fakeTunnel([{ status: 200, body: "{}" }, { status: 200, body: "{}" }]);
        const { socket } = fakeSocket();
        let key = "first";
        const json = tunnelRouteJson({
            open: async () => ({ tunnel, socket }),
            tick: async () => undefined,
            bearer: () => key,
        });
        await json("GET", "/a");
        key = "second";
        await json("GET", "/b");
        expect(tunnel.headers.map((h) => h?.authorization))
            .toEqual(["Bearer first", "Bearer second"]);
    });

    it("carries an idempotency key, which it previously dropped on the floor", async () => {
        // The route took no `RouteOptions` at all, so a command's key never
        // crossed the tunnel — and a replayed command would have done the work
        // twice on any surface that de-duplicates by it.
        const tunnel = fakeTunnel([{ status: 200, body: "{}" }]);
        const { socket } = fakeSocket();
        const json = tunnelRouteJson({
            open: async () => ({ tunnel, socket }),
            tick: async () => undefined,
        });
        await json("POST", "/commands", { a: 1 }, { idempotencyKey: "idem-1" });
        expect(tunnel.headers[0]).toEqual({ "idempotency-key": "idem-1" });
    });

    it("sends no header block when there is nothing to say", async () => {
        const tunnel = fakeTunnel([{ status: 200, body: "{}" }]);
        const { socket } = fakeSocket();
        const json = tunnelRouteJson({
            open: async () => ({ tunnel, socket }), tick: async () => undefined });
        await json("GET", "/v1/models");
        expect(tunnel.headers[0]).toBeUndefined();
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
            isPaired: () => true,
        };
        const { socket } = fakeSocket();
        let clock = 0;
        const json = build(tunnel, socket, 50, () => (clock += 30));
        await expect(json("GET", "/workspace")).rejects.toThrow(/timed out/);
    });

    it("writes nothing until the relay has paired the leg", async () => {
        // No reply, so the call ends at the deadline and the frames it did not
        // send are the assertion.
        const tunnel = fakeTunnel([], 2, false);
        const { socket, frames } = fakeSocket();
        let clock = 0;
        const json = build(tunnel, socket, 50, () => (clock += 30));
        await expect(json("GET", "/workspace")).rejects.toThrow(/timed out/);
        expect(frames).toEqual([]);
    });

    it("hangs the carrier up on close, and refuses to carry more", async () => {
        // Closing matters more here than for a direct route: the Home stays
        // spliced to a client that has gone and never re-parks, so a carrier
        // that is merely forgotten makes the *next* attempt to reach that Home
        // wait for a splice that cannot happen.
        const tunnel = fakeTunnel([{ status: 200, body: '{"ok":true}' }]);
        const { socket } = fakeSocket();
        let closes = 0;
        const json = build(tunnel, { ...socket, close: () => { closes += 1; } });
        await expect(json("GET", "/workspace")).resolves.toEqual({ ok: true });
        json.close();
        expect(closes).toBe(1);
        await expect(json("GET", "/workspace")).rejects.toThrow(/closed/);
    });

    it("closes nothing it never opened, and closes only once", async () => {
        const tunnel = fakeTunnel([]);
        const { socket } = fakeSocket();
        let closes = 0;
        const json = build(tunnel, { ...socket, close: () => { closes += 1; } });
        json.close();
        json.close();
        expect(closes).toBe(0);
    });

    it("reports a stopped turn as stopped, not as a delivery failure", async () => {
        // A relay-only Home carries `/task` here, so a `499` decoded only by the
        // direct route would make exactly those Stops look like breakage.
        const tunnel = fakeTunnel([{ status: TURN_STOPPED_STATUS, body: '{"error":"stopped"}' }]);
        const { socket } = fakeSocket();
        await expect(build(tunnel, socket)("POST", "/chats/c1/task"))
            .rejects.toBeInstanceOf(TurnStopped);
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
