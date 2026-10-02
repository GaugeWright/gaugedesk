import { afterEach, describe, expect, it, vi } from "vitest";
import { TurnStopped, TURN_STOPPED_STATUS } from "./control-plane-domain";
import {
    browserTunnelSocket,
    HomeTunnelError,
    TUNNEL_KEEPALIVE_INTERVAL_MS,
    TUNNEL_KEEPALIVE_REQUEST,
    TUNNEL_KEEPALIVE_RESPONSE,
    tunnelRouteEventStream,
    tunnelRouteJson,
    type EventTunnelFacade,
    type TunnelFacade,
    type TunnelStreamPoll,
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
        takeCredit: () => new Uint8Array(),
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

describe("Home tunnel failure lifecycle", () => {
    it("closes a timed-out carrier before the next attempt", async () => {
        const tunnel = fakeTunnel([], 100);
        const { socket } = fakeSocket();
        const closed = vi.spyOn(socket, "close");
        let now = 0;
        const json = build(tunnel, socket, 1, () => now++);
        await expect(json("GET", "/x")).rejects.toBeInstanceOf(HomeTunnelError);
        expect(closed).toHaveBeenCalledOnce();
    });

    it("does not resurrect a carrier that closed before its callback was attached", async () => {
        const tunnel = fakeTunnel([], 100);
        const socket: TunnelSocket = {
            send: () => undefined, close: () => undefined, onFrame: () => undefined,
            onClose: (handler) => handler("relay connection capacity reached"),
        };
        await expect(build(tunnel, socket)("POST", "/home/admissions"))
            .rejects.toThrow("relay connection capacity reached");
    });
});

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

    it("carries the Home admission beside the bearer, as the direct transport does", async () => {
        // A Home's work routes refuse a login bearer that arrives without the
        // admission it minted (HOME-1), and so does revoking one. The tunnel
        // sent only the bearer, so a caller admitted over it was then refused.
        const tunnel = fakeTunnel([{ status: 200, body: "{}" }]);
        const { socket } = fakeSocket();
        const json = tunnelRouteJson({
            open: async () => ({ tunnel, socket }),
            tick: async () => undefined,
            bearer: () => "login",
            homeAdmission: () => "admitted",
        });
        await json("GET", "/workspace");
        expect(tunnel.headers[0]).toEqual({
            authorization: "Bearer login",
            "x-gaugewright-home-admission": "admitted",
        });
    });

    it("reads the admission per call: absent for the admission, present for the work after it", async () => {
        // Exactly how `HomePool` wires it: one getter answering null until
        // `POST /home/admissions` returns, then the admission for every later
        // call over the same route — the revocation included.
        const tunnel = fakeTunnel([
            { status: 201, body: '{"home":"home:a","admission":"minted"}' },
            { status: 200, body: "{}" },
            { status: 200, body: "{}" },
        ]);
        const { socket } = fakeSocket();
        let admission: string | null = null;
        const json = tunnelRouteJson({
            open: async () => ({ tunnel, socket }),
            tick: async () => undefined,
            bearer: () => "login",
            homeAdmission: () => admission,
        });
        const admitted = (await json("POST", "/home/admissions")) as { admission: string };
        admission = admitted.admission;
        await json("GET", "/workspace");
        await json("DELETE", "/home/admissions");
        expect(tunnel.headers.map((h) => h?.["x-gaugewright-home-admission"]))
            .toEqual([undefined, "minted", "minted"]);
        expect(tunnel.headers.map((h) => h?.authorization))
            .toEqual(["Bearer login", "Bearer login", "Bearer login"]);
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
            takeCredit: () => new Uint8Array(),
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
    onclose: ((event: CloseEvent) => void) | null = null;
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
        this.onclose?.({ reason: "" } as CloseEvent);
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

/** An event tunnel whose output is released frame by frame: each frame the
 * relay delivers makes the next batch of polls available, which is how the
 * real one behaves — nothing changes in a client's session except on arrival. */
function fakeEventTunnel(batches: TunnelStreamPoll[][]): EventTunnelFacade & { frames: number } {
    const ready: TunnelStreamPoll[] = [];
    let paired = false;
    const tunnel = {
        frames: 0,
        receiveFrame: () => {
            tunnel.frames += 1;
            paired = true;
            ready.push(...(batches.shift() ?? []));
        },
        takeOutgoing: () => new Uint8Array(paired ? [9] : []),
        pollEvent: () => ready.shift(),
        isPaired: () => paired,
        // Owed after every third frame, so a test sees both answers.
        takeCredit: () => new Uint8Array(tunnel.frames % 3 === 0 ? [3, 0, 0, 64, 0] : []),
    };
    return tunnel;
}

function eventSocket() {
    let deliver: (frame: Uint8Array) => void = () => {};
    let closed: (reason?: string) => void = () => {};
    const sent: Uint8Array[] = [];
    let closes = 0;
    const socket: TunnelSocket = {
        send: (frame) => sent.push(frame),
        close: () => { closes += 1; closed(); },
        onFrame: (handler) => { deliver = handler; },
        onClose: (handler) => { closed = handler; },
    };
    return {
        socket,
        sent,
        frame: () => deliver(new Uint8Array([1])),
        drop: (reason?: string) => closed(reason),
        closes: () => closes,
    };
}

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

describe("event streams over the tunnel (WS-634)", () => {
    it("delivers each event as it arrives, after reporting the stream open", async () => {
        const tunnel = fakeEventTunnel([
            [],
            [{ kind: "opened" }, { kind: "event", data: "one" }],
            [{ kind: "event", data: "two" }],
        ]);
        const carrier = eventSocket();
        const opened: Array<{ path: string; headers?: Record<string, string> }> = [];
        const events = tunnelRouteEventStream({
            open: async (path, headers) => {
                opened.push({ path, headers });
                return { tunnel, socket: carrier.socket };
            },
            bearer: () => "account-bearer",
            homeAdmission: () => "home-admission",
        });
        const seen: string[] = [];
        const onOpen = vi.fn();
        const onClose = vi.fn();
        const stop = events("/chats/c1/events", (data) => seen.push(data), onOpen, onClose);
        await flush();

        expect(opened).toEqual([{
            path: "/chats/c1/events",
            headers: {
                authorization: "Bearer account-bearer",
                "x-gaugewright-home-admission": "home-admission",
            },
        }]);
        carrier.frame(); // READY: the handshake goes out, nothing to report
        expect(carrier.sent.length).toBe(1);
        expect(onOpen).not.toHaveBeenCalled();
        carrier.frame();
        expect(onOpen).toHaveBeenCalledOnce();
        expect(seen).toEqual(["one"]);
        carrier.frame();
        expect(seen).toEqual(["one", "two"]);
        expect(onClose).not.toHaveBeenCalled();

        stop();
        expect(carrier.closes()).toBe(1);
        expect(onClose).not.toHaveBeenCalled();
    });

    it("reports a refusal with the Home's reason, so an expired admission is admitted again", async () => {
        const tunnel = fakeEventTunnel([[{
            kind: "refused",
            status: 401,
            body: JSON.stringify({ error: "target Home admission required" }),
        }]]);
        const carrier = eventSocket();
        const events = tunnelRouteEventStream({ open: async () => ({ tunnel, socket: carrier.socket }) });
        const onClose = vi.fn();
        events("/workspace/events", () => undefined, undefined, onClose);
        await flush();
        carrier.frame();
        expect(onClose).toHaveBeenCalledWith({ status: 401, detail: "target Home admission required" });
        expect(carrier.closes()).toBe(1);
    });

    it("reports a stream the Home ended, and a carrier that closed under it", async () => {
        const ended = eventSocket();
        const dropped = eventSocket();
        const sockets = [ended, dropped];
        const tunnels = [
            fakeEventTunnel([[{ kind: "opened" }, { kind: "ended" }]]),
            fakeEventTunnel([[{ kind: "opened" }]]),
        ];
        const events = tunnelRouteEventStream({
            open: async () => ({ tunnel: tunnels.shift()!, socket: sockets.shift()!.socket }),
        });
        const first = vi.fn();
        const second = vi.fn();
        events("/workspace/events", () => undefined, undefined, first);
        events("/chats/c1/events", () => undefined, undefined, second);
        await flush();
        ended.frame();
        expect(first).toHaveBeenCalledWith(undefined);
        dropped.frame();
        dropped.drop("relay keepalive missed");
        expect(second).toHaveBeenCalledWith({ detail: "relay keepalive missed" });
    });

    it("gives up on a Home that never answers the stream", async () => {
        vi.useFakeTimers();
        try {
            const carrier = eventSocket();
            const events = tunnelRouteEventStream({
                open: async () => ({ tunnel: fakeEventTunnel([]), socket: carrier.socket }),
                openTimeoutMs: 1_000,
            });
            const onClose = vi.fn();
            events("/workspace/events", () => undefined, undefined, onClose);
            await vi.advanceTimersByTimeAsync(1_001);
            expect(onClose).toHaveBeenCalledWith({ detail: "the Home event stream did not open in time" });
            expect(carrier.closes()).toBe(1);
        } finally {
            vi.useRealTimers();
        }
    });

    it("reports a stream that could not be opened at all", async () => {
        const events = tunnelRouteEventStream({
            open: async () => { throw new Error("relay connection capacity reached"); },
        });
        const onClose = vi.fn();
        events("/workspace/events", () => undefined, undefined, onClose);
        await flush();
        expect(onClose).toHaveBeenCalledWith({ detail: "relay connection capacity reached" });
    });

    it("closes a carrier that finished opening after its subscriber left", async () => {
        const carrier = eventSocket();
        let release: () => void = () => {};
        const events = tunnelRouteEventStream({
            open: () => new Promise((resolve) => {
                release = () => resolve({ tunnel: fakeEventTunnel([]), socket: carrier.socket });
            }),
        });
        const onClose = vi.fn();
        const stop = events("/workspace/events", () => undefined, undefined, onClose);
        stop();
        release();
        await flush();
        expect(carrier.closes()).toBe(1);
        expect(onClose).not.toHaveBeenCalled();
    });

    it("ends every open stream when its route closes, as closed under the subscriber", async () => {
        const carriers = [eventSocket(), eventSocket()];
        const sockets = [...carriers];
        const events = tunnelRouteEventStream({
            open: async () => ({ tunnel: fakeEventTunnel([[{ kind: "opened" }]]), socket: sockets.shift()!.socket }),
        });
        const closes = [vi.fn(), vi.fn()];
        events("/workspace/events", () => undefined, undefined, closes[0]);
        events("/chats/c1/events", () => undefined, undefined, closes[1]);
        await flush();
        events.closeAll();
        expect(carriers.map((carrier) => carrier.closes())).toEqual([1, 1]);
        for (const close of closes) expect(close).toHaveBeenCalledWith({ detail: "the Home tunnel closed" });
    });
});

describe("reporting consumption to the relay (DR-0302)", () => {
    it("sends a stream's credit on its carrier after the frame that earned it", async () => {
        const tunnel = fakeEventTunnel([[], [{ kind: "opened" }], []]);
        const carrier = eventSocket();
        const events = tunnelRouteEventStream({ open: async () => ({ tunnel, socket: carrier.socket }) });
        events("/workspace/events", () => undefined);
        await flush();
        carrier.frame();
        carrier.frame();
        expect(carrier.sent.some((frame) => frame[0] === 3)).toBe(false);
        carrier.frame();
        expect(carrier.sent.filter((frame) => frame[0] === 3)).toEqual([new Uint8Array([3, 0, 0, 64, 0])]);
    });

    it("sends the calls' credit on their carrier, and nothing when none is owed", async () => {
        let deliver: (frame: Uint8Array) => void = () => {};
        const sent: Uint8Array[] = [];
        let owed = false;
        const tunnel = { ...fakeTunnel([{ status: 200, body: "{}" }]), takeCredit: () => {
            const credit = owed ? new Uint8Array([3, 0, 0, 0, 7]) : new Uint8Array();
            owed = false;
            return credit;
        } };
        const socket: TunnelSocket = {
            send: (frame) => sent.push(frame),
            close: () => undefined,
            onFrame: (handler) => { deliver = handler; },
            onClose: () => undefined,
        };
        const json = build(tunnel, socket);
        await json("GET", "/x");
        deliver(new Uint8Array([0, 1]));
        expect(sent.some((frame) => frame[0] === 3)).toBe(false);
        owed = true;
        deliver(new Uint8Array([0, 1]));
        expect(sent.at(-1)).toEqual(new Uint8Array([3, 0, 0, 0, 7]));
    });
});

