import { afterEach, describe, expect, it, vi } from "vitest";
import { TurnStopped, TURN_STOPPED_STATUS } from "./control-plane-domain";
import {
    browserTunnelSocket,
    TUNNEL_KEEPALIVE_INTERVAL_MS,
    TUNNEL_KEEPALIVE_REQUEST,
    TUNNEL_KEEPALIVE_RESPONSE,
    tunnelRouteJson,
    type TunnelFacade,
    type TunnelSocket,
} from "./tunnel-route-json";

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

    it("mints a key for a mutating call that brought none, as the direct transport does", async () => {
        // A Home refuses a command without one, and the first command a
        // relay-only Home receives is its admission: `POST /home/admissions`
        // with no options. Sending a key only when asked meant the tunnel could
        // reach the Home and never be let in.
        const tunnel = fakeTunnel([
            { status: 200, body: "{}" }, { status: 200, body: "{}" }, { status: 200, body: "{}" },
        ]);
        const { socket } = fakeSocket();
        const json = tunnelRouteJson({
            open: async () => ({ tunnel, socket }), tick: async () => undefined });
        await json("POST", "/home/admissions");
        await json("DELETE", "/home/admissions");
        await json("GET", "/home/admissions");
        const [post, del, get] = tunnel.headers;
        expect(post?.["idempotency-key"]).toMatch(/\S{8,}/);
        expect(del?.["idempotency-key"]).toMatch(/\S{8,}/);
        expect(del?.["idempotency-key"]).not.toBe(post?.["idempotency-key"]);
        expect(get).toBeUndefined();
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

describe("a carrier that closes under the route (DESK-7)", () => {
    /** Opens a fresh fake carrier per call and remembers each, so a test can
     * close one the way the relay or the Home would. */
    function reopening(replies: Array<{ status: number; body: string }>, afterPumps = 2) {
        const tunnel = fakeTunnel(replies, afterPumps);
        const carriers: Array<ReturnType<typeof fakeSocket>> = [];
        const json = tunnelRouteJson({
            open: async () => {
                const carrier = fakeSocket();
                carriers.push(carrier);
                return { tunnel, socket: carrier.socket };
            },
            tick: async () => undefined,
        });
        return { json, tunnel, carriers };
    }

    it("reopens on the next call after the carrier closed while idle", async () => {
        // The relay closes a leg that broke its keepalive promise, and a Home
        // ends a crossing that has carried nothing for its idle bound. Either
        // way the route used to set a permanent flag, and every later call on
        // it answered "the Home tunnel closed" until the pool happened to
        // rebuild it.
        const { json, carriers } = reopening([
            { status: 200, body: '{"n":1}' },
            { status: 200, body: '{"n":2}' },
        ]);
        await expect(json("GET", "/a")).resolves.toEqual({ n: 1 });
        carriers[0]!.drop();
        await expect(json("GET", "/b")).resolves.toEqual({ n: 2 });
        expect(carriers).toHaveLength(2);
        expect(carriers[1]!.frames.length).toBeGreaterThan(0);
    });

    it("keeps using a carrier that has not closed", async () => {
        const { json, carriers } = reopening([
            { status: 200, body: "{}" }, { status: 200, body: "{}" },
        ]);
        await json("GET", "/a");
        await json("GET", "/b");
        expect(carriers).toHaveLength(1);
    });

    it("fails a request whose carrier closes under it, and does not resend it", async () => {
        // The request may already have reached the Home; only the caller knows
        // whether it is safe to send twice. The next call still reopens.
        const { json, tunnel, carriers } = reopening([
            { status: 200, body: '{"ok":true}' },
        ], 1_000);
        let pumps = 0;
        const original = tunnel.pollStatus;
        tunnel.pollStatus = () => {
            pumps += 1;
            if (pumps === 3) carriers[0]!.drop();
            return original();
        };
        await expect(json("POST", "/commands", { a: 1 })).rejects.toThrow(/closed mid-request/);
        expect(tunnel.sent).toEqual(['POST /commands {"a":1}']);
        tunnel.pollStatus = () => 200;
        await expect(json("GET", "/workspace")).resolves.toEqual({ ok: true });
        expect(carriers).toHaveLength(2);
    });

    it("ignores a late close from a carrier it has already replaced", async () => {
        const replies = [
            { status: 200, body: "{}" }, { status: 200, body: "{}" }, { status: 200, body: "{}" },
        ];
        const { json, carriers } = reopening(replies);
        await json("GET", "/a");
        const first = carriers[0]!;
        first.drop();
        await json("GET", "/b");
        // The first carrier's close arrives again, late. It must not orphan the
        // second, which would open a third and leave the second spliced to a
        // Home that never re-parks.
        first.drop();
        await json("GET", "/c");
        expect(carriers).toHaveLength(2);
    });

    it("still refuses for good once the caller hangs up", async () => {
        const { json, carriers } = reopening([{ status: 200, body: "{}" }]);
        await json("GET", "/a");
        json.close();
        await expect(json("GET", "/b")).rejects.toThrow(/closed/);
        expect(carriers).toHaveLength(1);
    });

    it("closes a carrier that finished opening after the caller hung up", async () => {
        const tunnel = fakeTunnel([{ status: 200, body: "{}" }]);
        let closes = 0;
        let release: () => void = () => {};
        const opened = new Promise<void>((resolve) => { release = resolve; });
        const json = tunnelRouteJson({
            open: async () => {
                await opened;
                return { tunnel, socket: { ...fakeSocket().socket, close: () => { closes += 1; } } };
            },
            tick: async () => undefined,
        });
        const call = json("GET", "/a");
        await Promise.resolve();
        json.close();
        release();
        await expect(call).rejects.toThrow(/closed/);
        expect(closes).toBe(1);
    });
});

/** A `WebSocket` with nothing behind it: it records what is sent, and a test
 * plays the relay by calling its handlers. */
class StubWebSocket {
    static last: StubWebSocket | null = null;
    readonly OPEN = 1;
    readyState = 0;
    binaryType = "blob";
    readonly sent: Array<string | ArrayBuffer> = [];
    onopen: (() => void) | null = null;
    onclose: (() => void) | null = null;
    onerror: (() => void) | null = null;
    onmessage: ((event: { data: unknown }) => void) | null = null;

    constructor(readonly url: string) {
        StubWebSocket.last = this;
    }
    send(data: string | ArrayBuffer) { this.sent.push(data); }
    close() { this.drop(); }

    open() {
        this.readyState = 1;
        this.onopen?.();
    }
    drop() {
        if (this.readyState === 3) return;
        this.readyState = 3;
        this.onclose?.();
    }
    pings() { return this.sent.filter((data) => data === TUNNEL_KEEPALIVE_REQUEST).length; }
}

async function openStub(keepaliveMs?: number) {
    const opening = browserTunnelSocket("wss://relay.test/v1/relay/h", new Uint8Array([9]), {
        WebSocket: StubWebSocket as unknown as new (url: string) => WebSocket,
        ...(keepaliveMs === undefined ? {} : { keepaliveMs }),
    });
    const stub = StubWebSocket.last!;
    stub.open();
    return { socket: await opening, stub };
}

describe("the browser carrier's keepalive (DESK-7)", () => {
    afterEach(() => { vi.useRealTimers(); });

    it("keeps the handshake's promise: a GWRPING every interval while open", async () => {
        // The client handshake sets the keepalive flag, so the relay judges this
        // leg on its silence and closes it 150s after the last ping — carried
        // data does not count. Nothing in the browser sent one, so every
        // browser tunnel to a Home was closed 150s after pairing, in use or not.
        vi.useFakeTimers();
        const { stub } = await openStub();
        expect(stub.sent).toHaveLength(1); // the handshake, and nothing else yet
        vi.advanceTimersByTime(TUNNEL_KEEPALIVE_INTERVAL_MS - 1);
        expect(stub.pings()).toBe(0);
        vi.advanceTimersByTime(1);
        expect(stub.pings()).toBe(1);
        vi.advanceTimersByTime(4 * TUNNEL_KEEPALIVE_INTERVAL_MS);
        expect(stub.pings()).toBe(5);
    });

    it("pings whether or not anything is being carried", async () => {
        vi.useFakeTimers();
        const { socket, stub } = await openStub(1_000);
        socket.send(new Uint8Array([1, 2, 3]));
        vi.advanceTimersByTime(3_000);
        expect(stub.pings()).toBe(3);
    });

    it("stops pinging once the socket closes, from either end", async () => {
        vi.useFakeTimers();
        const ours = await openStub(1_000);
        ours.socket.close();
        vi.advanceTimersByTime(5_000);
        expect(ours.stub.pings()).toBe(0);

        const theirs = await openStub(1_000);
        vi.advanceTimersByTime(1_000);
        theirs.stub.drop();
        vi.advanceTimersByTime(5_000);
        expect(theirs.stub.pings()).toBe(1);
        expect(vi.getTimerCount()).toBe(0);
    });

    it("ignores the relay's GWRPONG and delivers only binary frames", async () => {
        const { socket, stub } = await openStub();
        const frames: number[][] = [];
        socket.onFrame((frame) => frames.push([...frame]));
        stub.onmessage?.({ data: TUNNEL_KEEPALIVE_RESPONSE });
        stub.onmessage?.({ data: new Uint8Array([7, 8]).buffer });
        expect(frames).toEqual([[7, 8]]);
    });

    it("reports a close that landed before anyone was listening", async () => {
        // Otherwise the route would hold a dead carrier as live and wait out
        // every call's deadline on it.
        const { socket, stub } = await openStub();
        stub.drop();
        let closed = 0;
        socket.onClose(() => { closed += 1; });
        expect(closed).toBe(1);
    });

    it("leaves room inside the edge's idle bound for missed pings", () => {
        // gaugewright-cloud's relay closes a keepalive-judged leg whose last
        // ping is older than IDLE_MILLIS. The native pump holds itself to the
        // same bound in `the_keepalive_interval_leaves_room_for_missed_pings`.
        const EDGE_IDLE_MILLIS = 150_000;
        expect(TUNNEL_KEEPALIVE_INTERVAL_MS * 5).toBeLessThanOrEqual(EDGE_IDLE_MILLIS);
        // A hidden tab's timers may run once a minute; two must still land.
        expect(Math.max(TUNNEL_KEEPALIVE_INTERVAL_MS, 60_000) * 2).toBeLessThan(EDGE_IDLE_MILLIS);
    });
});
