/**
 * The pool's `routeJson`, carried over the WASM tunnel (DESK-7).
 *
 * This is the last link between a relay locator and the transport the multi-Home
 * pool consumes. The socket lives here because `control-plane-client` is the
 * declared browser transport owner (ADR 0130 §6) — the wasm module is
 * deliberately pump-driven so it never opens one, which keeps the boundary
 * `scripts/architecture-check.py` enforces describing reality.
 *
 * Everything with a decision in it — TLS, framing, reassembly, the certificate
 * pin — is on the Rust side and tested there. What is left here is a loop, and
 * the seams below exist so that loop is testable without a browser or a wasm
 * build.
 */

import { TurnStopped, TURN_STOPPED_STATUS } from "./control-plane-domain";
import { newIdempotencyKey, type RouteJson, type RouteOptions } from "./control-plane-transport";
import type { RouteEventClose, RouteEventStream, RouteRequest } from "./browser-route-json";

/** The `BrowserTunnel` facade, as a structural type so a test can stand one in
 * without loading wasm. Method names match the exported binding exactly. */
export interface TunnelFacade {
    receiveFrame(frame: Uint8Array): void;
    /** Whether the Home has sent its `FIN` on this session: it answers nothing
     *  more, though its leg stays open through a teardown grace. */
    peerFinished?(): boolean;
    sendRequest(method: string, path: string, body?: string,
                headers?: Record<string, string>): void;
    takeOutgoing(): Uint8Array;
    pollStatus(): number | undefined;
    takeBody(): string;
    isHandshaking(): boolean;
    /** Whether the relay has spliced this leg to the Home's. */
    isPaired(): boolean;
    /** The report of consumption the relay is owed after the last frame, or
     * empty (DR-0302). */
    takeCredit(): Uint8Array;
}

/** The same binding, read raw: a request whose body follows in parts, and a
 * reply's bytes and headers rather than its text (WS-678). */
export interface RawTunnelFacade extends TunnelFacade {
    sendRequestHead(method: string, path: string, headers: Record<string, string> | undefined,
                    contentLength: number): void;
    sendBody(chunk: Uint8Array): void;
    /** Bytes queued and not yet handed to the socket. */
    bufferedBytes(): number;
    takeBodyBytes(): Uint8Array;
    takeHeaders(): Record<string, string>;
}

/** The socket, narrowed to what the loop uses. */
export interface TunnelSocket {
    send(frame: Uint8Array): void;
    close(): void;
    /** Bytes the socket has accepted and not yet put on the wire, when the
     * carrier can say. A body is fed no faster than this drains. */
    bufferedAmount?(): number;
    onFrame(handler: (frame: Uint8Array) => void): void;
    onClose(handler: (reason?: string) => void): void;
}

/** Extra headers for one call, assembled the way the direct transport does.
 *
 * A carried surface may demand one: TokenWright admits nothing without
 * `Authorization`, so a tunnel that sent no headers could reach a box, claim it,
 * and then never use it. A Home demands two: its work routes and the revocation
 * of an admission refuse a login bearer that arrives without the admission the
 * Home minted (`HOME-1`). */
function headersFor(credentials: TunnelCredentials,
                    method: string,
                    options?: RouteOptions): Record<string, string> | undefined {
    const headers: Record<string, string> = {};
    const token = credentials.bearer?.();
    if (token) headers.authorization = `Bearer ${token}`;
    // Read per call, like the bearer: the pool's getter answers null until
    // `POST /home/admissions` has returned, and the admission itself is the one
    // call that must go without it.
    const admission = credentials.homeAdmission?.();
    if (admission) headers["x-gaugewright-home-admission"] = admission;
    // Every mutating call carries a key, minted here when the caller brought
    // none — exactly as `browserRouteJson` does. A Home refuses a command
    // without one, and the first command any relay-only Home ever receives is
    // the admission itself, so a tunnel that sent a key only when asked could
    // reach a Home and never be let in (2026-09-24: `POST /home/admissions`
    // answered 400 "missing Idempotency-Key header" over the relay).
    const mutating = method !== "GET" && method !== "HEAD" && method !== "OPTIONS";
    const key = options?.idempotencyKey ?? (mutating ? newIdempotencyKey() : undefined);
    if (key) headers["idempotency-key"] = key;
    return Object.keys(headers).length > 0 ? headers : undefined;
}

export interface TunnelRouteOptions {
    /** Open the pinned tunnel and its carrier. Async because the wasm module
     * loads on demand, so nothing is fetched until a relay-only Home is opened. */
    readonly open: () => Promise<{ tunnel: TunnelFacade; socket: TunnelSocket }>;
    /** Bounds a request. A tunnel that stops answering must fail the call rather
     * than leave a caller waiting forever. */
    readonly timeoutMs?: number;
    readonly now?: () => number;
    /** Yield between pumps; a test drives it synchronously. */
    readonly tick?: () => Promise<void>;
    /** The credential the carried surface requires, read per call so a rotated
     * key is used without rebuilding the route. Shaped like `browserRouteJson`'s
     * so the two transports are configured the same way. */
    readonly bearer?: () => string | null;
    /** The Home's admission for this caller, read per call for the same reason.
     * `HomePool` hands one to every transport it builds; a tunnel that dropped
     * it could be admitted to a Home and then refused by it. */
    readonly homeAdmission?: () => string | null;
    /** How many sessions the calls may hold open to the Home at once
     * ([`TUNNEL_CALL_SESSIONS`] unless given). */
    readonly sessions?: number;
}

/**
 * How many pinned sessions a route's calls may hold open at once.
 *
 * One session answers one call at a time, so a route with one session ran every
 * call behind whichever was in front of it: a turn, a slow handler, or simply a
 * page's dozen calls on opening a project, each a relay round trip, one after
 * another. A browser gives a site six connections for the same reason. Each
 * session is a crossing the Home holds until it idles out, so this stays small,
 * and a second is opened only when every open one is busy — a page making one
 * call at a time uses one, exactly as before.
 */
export const TUNNEL_CALL_SESSIONS = 4;

type TunnelCredentials = Pick<TunnelRouteOptions, "bearer" | "homeAdmission">;

export class HomeTunnelError extends Error {}
class TunnelClosed extends HomeTunnelError {}
/** The relay paired the session and the Home never finished the TLS handshake:
 * a leg that died before the relay noticed. Nothing of the request reached the
 * Home, so it is safe to send again on a fresh session. */
class TunnelSilent extends HomeTunnelError {}

/** How long a paired session may take to finish its TLS handshake. A live Home
 * answers within a round trip or two; past this the leg it was paired with is
 * gone, and another dial is served by one of the Home's other parked legs. */
export const TUNNEL_HANDSHAKE_TIMEOUT_MS = 4_000;

/** How many sessions a call tries when the Home never answers the handshake. */
const TUNNEL_HANDSHAKE_ATTEMPTS = 3;

/**
 * A tunnel's `RouteJson`, plus the handle needed to hang it up.
 *
 * A direct route is closed by forgetting it — the browser owns the socket and
 * reclaims it. A tunnel is not: the carrier holds a `WebSocket` and the Home
 * holds a leg parked against it, and neither notices a caller losing interest.
 * A Home that keeps a leg spliced to a client that has gone never re-parks, so
 * *every later attempt to reach it waits for a splice that cannot happen*.
 * Dropping the reference is therefore not a way to close this.
 */
export type TunnelRoute = RouteJson & {
    /** Hang up: close the carrier and refuse further calls. Idempotent.
     *
     * The only thing that refuses further calls. A carrier that closes on its
     * own is reopened by the next call. */
    close(): void;
};

/** One carrier to a Home, opened on first use and reopened after it closes,
 * that runs one exchange at a time over it. Shared by the JSON calls and the
 * raw requests, which each hold one of their own. */
interface Carrier<F> {
    /** Run one exchange on the live session, after every exchange before it. */
    run<T>(exchange: (session: CarrierSession<F>) => Promise<T>): Promise<T>;
    close(): void;
}

interface CarrierSession<F> {
    readonly tunnel: F;
    readonly socket: TunnelSocket;
    /** Whether this session is still the carrier's live one. */
    live(): boolean;
    /** Why it stopped being, if it has. */
    closeReason(): string | undefined;
    /** When the relay last delivered a frame on it. */
    lastFrameAt(): number;
    /** Abandon it mid-exchange: the next exchange opens a fresh one. */
    drop(): void;
    /** How many frames and closes the carrier has seen, to wait from. */
    events(): number;
    /** Resolve once the carrier sees a frame or a close after `since`, or after
     *  `ms`, whichever is first. */
    nextEvent(since: number, ms: number): Promise<void>;
}

/** The longest an exchange waits without a frame before looking again: for
 *  progress no frame announces, such as a send buffer draining or a deadline. */
const TUNNEL_IDLE_POLL_MS = 50;

function tunnelCarrier<F extends { receiveFrame(frame: Uint8Array): void; takeCredit(): Uint8Array; peerFinished?(): boolean }>(
    open: () => Promise<{ tunnel: F; socket: TunnelSocket }>,
    now: () => number,
): Carrier<F> {
    let live: { tunnel: F; socket: TunnelSocket } | null = null;
    // Only the caller hangs a route up for good. A carrier that closes under it
    // — the Home ending an idle crossing, the relay closing a leg — takes the
    // session with it, not the route: the next call opens a fresh one, exactly
    // as the first call did. Refusing forever instead left a live pool entry
    // answering "the Home tunnel closed" to every call until something else
    // happened to evict it.
    let closeReason: string | undefined;
    let hungUp = false;
    let lastFrameAt = now();
    let queue: Promise<unknown> = Promise.resolve();
    // An exchange waits on these rather than on a timer. A frame arrives on
    // the socket's own callback, so waking on it costs nothing, while a timer
    // is held to once a second in a background tab and a fresh crossing takes
    // several round trips (WS-850).
    let events = 0;
    const waiters = new Set<() => void>();
    const signal = () => {
        events += 1;
        const woken = [...waiters];
        waiters.clear();
        for (const wake of woken) wake();
    };

    async function ensure(): Promise<{ tunnel: F; socket: TunnelSocket }> {
        // A session the Home has finished is never reused: its socket stays
        // open through the Home's teardown grace, and a request written there
        // went unanswered until the relay reported 1011 (WS-850).
        if (live?.tunnel.peerFinished?.()) {
            const finished = live;
            live = null;
            finished.socket.close();
        }
        if (live) return live;
        let opened: { tunnel: F; socket: TunnelSocket };
        try { opened = await open(); }
        catch (error) {
            throw new HomeTunnelError(error instanceof Error ? error.message : String(error));
        }
        if (hungUp) {
            // Hung up while this was opening: nothing will ever close it.
            opened.socket.close();
            throw new TunnelClosed("the Home tunnel closed");
        }
        live = opened;
        opened.socket.onFrame((frame) => {
            lastFrameAt = now();
            opened.tunnel.receiveFrame(frame);
            sendCredit(opened.tunnel, opened.socket);
            signal();
        });
        closeReason = undefined;
        opened.socket.onClose((reason) => {
            // Only its own session. A late close from a carrier already
            // replaced must not orphan the one that replaced it.
            if (live === opened) { live = null; closeReason = reason; }
            signal();
        });
        return opened;
    }

    return {
        run<T>(exchange: (session: CarrierSession<F>) => Promise<T>): Promise<T> {
            // One at a time: the tunnel carries a single stream, so interleaving
            // two requests would splice their frames together.
            const run = queue.then(async () => {
                if (hungUp) throw new TunnelClosed("the Home tunnel closed");
                const opened = await ensure();
                return exchange({
                    tunnel: opened.tunnel,
                    socket: opened.socket,
                    live: () => live === opened,
                    closeReason: () => closeReason,
                    lastFrameAt: () => lastFrameAt,
                    drop: () => {
                        if (live === opened) live = null;
                        opened.socket.close();
                    },
                    events: () => events,
                    nextEvent: (since, ms) => since !== events ? Promise.resolve() : new Promise<void>((resolve) => {
                        const wake = () => {
                            clearTimeout(timer);
                            waiters.delete(wake);
                            resolve();
                        };
                        const timer = setTimeout(wake, ms);
                        waiters.add(wake);
                    }),
                });
            });
            // Keep the chain alive after a rejection so one failure does not
            // wedge every later request behind it.
            queue = run.catch(() => undefined);
            return run;
        },
        close() {
            hungUp = true;
            const open = live;
            live = null;
            open?.socket.close();
        },
    };
}

/**
 * Several carriers to one Home, each running one exchange at a time, so a call
 * never waits behind another unless every session is busy.
 *
 * An exchange goes to the first idle carrier, so calls made one at a time all
 * use the first and nothing else is opened. When every open carrier is busy a
 * new one is opened, up to `limit`; past that, the call queues on the carrier
 * with the least ahead of it.
 */
function carrierPool<F>(make: () => Carrier<F>, limit: number): Carrier<F> {
    const carriers: Array<{ carrier: Carrier<F>; busy: number }> = [];
    let hungUp = false;
    return {
        run<T>(exchange: (session: CarrierSession<F>) => Promise<T>): Promise<T> {
            // Hung up for good: no new carrier may be opened behind the caller.
            if (hungUp) return Promise.reject(new TunnelClosed("the Home tunnel closed"));
            let chosen = carriers.find((entry) => entry.busy === 0);
            if (!chosen && carriers.length < limit) {
                chosen = { carrier: make(), busy: 0 };
                carriers.push(chosen);
            }
            chosen ??= carriers.reduce((least, entry) => (entry.busy < least.busy ? entry : least));
            const entry = chosen;
            entry.busy += 1;
            return entry.carrier.run(exchange).finally(() => { entry.busy -= 1; });
        },
        close() {
            hungUp = true;
            for (const entry of carriers) entry.carrier.close();
        },
    };
}

/** Hand the socket every frame the tunnel has ready, holding back while the
 * socket already has `limit` bytes waiting. */
function flushFrames(tunnel: { takeOutgoing(): Uint8Array }, socket: TunnelSocket,
                     limit = Number.POSITIVE_INFINITY): void {
    while ((socket.bufferedAmount?.() ?? 0) < limit) {
        const outgoing = tunnel.takeOutgoing();
        if (outgoing.length === 0) return;
        socket.send(outgoing);
    }
}

/**
 * Build a `RouteJson` that carries each call over the pinned tunnel.
 *
 * Each session carries one request/response at a time, so a second caller
 * never interleaves frames into a session in use: it takes an idle session, or
 * opens another (up to [`TUNNEL_CALL_SESSIONS`]), or waits for the least busy.
 */
export function tunnelRouteJson(options: TunnelRouteOptions): TunnelRoute {
    const timeoutMs = options.timeoutMs ?? 30_000;
    const now = options.now ?? Date.now;
    const tick = options.tick;
    const carrier = carrierPool(
        () => tunnelCarrier(options.open, now),
        Math.max(1, options.sessions ?? TUNNEL_CALL_SESSIONS),
    );

    const exchange = (
        method: string,
        path: string,
        body?: unknown,
        routeOptions?: RouteOptions,
    ) => carrier.run(async (session) => {
        const { tunnel, socket } = session;
        tunnel.sendRequest(
            method, path,
            body === undefined ? undefined : JSON.stringify(body),
            headersFor(options, method, routeOptions),
        );
        const deadline = now() + timeoutMs;
        let pairedAt: number | undefined;
        for (;;) {
            const seen = session.events();
            // Not before the relay has spliced this leg. Ciphertext written
            // into an unpaired route has no other end, and relying on the
            // relay to hold it is relying on a component whose whole design
            // is to be dumb. It accumulates in the session either way.
            if (tunnel.isPaired()) {
                pairedAt ??= now();
                flushFrames(tunnel, socket);
                if (tunnel.isHandshaking() && now() - pairedAt > TUNNEL_HANDSHAKE_TIMEOUT_MS) {
                    session.drop();
                    throw new TunnelSilent(`${method} ${path}: the Home did not answer the tunnel`);
                }
            }
            const status = tunnel.pollStatus();
            if (status !== undefined) {
                const text = tunnel.takeBody();
                // A stopped turn is not a delivery failure on this transport
                // either. The hosted split composition carries `/task` through
                // here whenever a project's Home is relay-only, so decoding
                // `499` only in the direct browser route would leave exactly
                // those turns reported as broken — and the composer holding
                // the cancelled message for a retry nobody asked for.
                if (status === TURN_STOPPED_STATUS) throw new TurnStopped();
                if (status >= 400) {
                    throw new Error(`${method} ${path}: ${status} ${text}`.trim());
                }
                return text ? (JSON.parse(text) as unknown) : {};
            }
            // Not retried on a fresh session: the request may already have
            // reached the Home, and only the caller knows whether sending it
            // twice is safe.
            if (!session.live()) {
                throw new TunnelClosed(session.closeReason() ?? "the Home tunnel closed mid-request");
            }
            if (tunnel.peerFinished?.()) {
                session.drop();
                throw new TunnelClosed("the Home ended the tunnel mid-request");
            }
            if (now() > deadline) {
                session.drop();
                throw new HomeTunnelError(`${method} ${path}: the Home tunnel timed out`);
            }
            await (tick ? tick() : session.nextEvent(seen, TUNNEL_IDLE_POLL_MS));
        }
    });
    const route: TunnelRoute = Object.assign((
        method: string,
        path: string,
        body?: unknown,
        routeOptions?: RouteOptions,
    ) => {
        // One key for both attempts, so a retried mutation is the same
        // command. The credentials are still read when each attempt runs.
        const mutating = method !== "GET" && method !== "HEAD" && method !== "OPTIONS";
        const key = routeOptions?.idempotencyKey ?? (mutating ? newIdempotencyKey() : undefined);
        const keyed = key ? { ...routeOptions, idempotencyKey: key } : routeOptions;
        const attempt = (left: number): Promise<unknown> =>
            exchange(method, path, body, keyed).catch((error: unknown) => {
                if (error instanceof TunnelSilent && left > 1) return attempt(left - 1);
                throw error;
            });
        return attempt(TUNNEL_HANDSHAKE_ATTEMPTS);
    }, { close: () => carrier.close() });
    return route;
}

/** Whether a reply with this status carries no body, as `Response` requires. */
function nullBodyStatus(status: number): boolean {
    return status === 101 || status === 204 || status === 205 || status === 304;
}

/** A request body, readable in parts so a large one is never copied whole. */
interface PartedBody {
    readonly length: number;
    /** The content type `fetch` would have sent for it, if any. */
    readonly contentType?: string;
    read(offset: number, size: number): Promise<Uint8Array>;
}

function partedBody(body: RequestInit["body"]): PartedBody {
    if (body === undefined || body === null) {
        return { length: 0, read: async () => new Uint8Array() };
    }
    const whole = (bytes: Uint8Array, contentType?: string): PartedBody => ({
        length: bytes.length,
        ...(contentType ? { contentType } : {}),
        read: async (offset, size) => bytes.subarray(offset, offset + size),
    });
    if (typeof body === "string") {
        return whole(new TextEncoder().encode(body), "text/plain;charset=UTF-8");
    }
    if (body instanceof ArrayBuffer) return whole(new Uint8Array(body));
    if (ArrayBuffer.isView(body)) {
        return whole(new Uint8Array(body.buffer, body.byteOffset, body.byteLength));
    }
    if (typeof Blob !== "undefined" && body instanceof Blob) {
        return {
            length: body.size,
            ...(body.type ? { contentType: body.type } : {}),
            read: async (offset, size) =>
                new Uint8Array(await body.slice(offset, offset + size).arrayBuffer()),
        };
    }
    throw new HomeTunnelError("this request body cannot be carried over the Home tunnel");
}

/** How much of a body may wait unsent before the next part is read. */
const RAW_HIGH_WATER_BYTES = 1024 * 1024;
const RAW_PART_BYTES = 256 * 1024;

export type TunnelRouteRequest = RouteRequest & {
    /** Hang up: close the carrier and refuse further requests. Idempotent. */
    close(): void;
};

/**
 * Carry the raw requests — files, config, a merge preview, a context upload —
 * to a Home with no address of its own, over a pinned tunnel (WS-678).
 *
 * Until this, a relay-only Home in a browser had no way to take them: the
 * calls' tunnel carried JSON and nothing else, and every file and config
 * request said "Home raw transport unavailable". It answers the way `fetch`
 * does, with a `Response`, so its callers cannot tell the two apart.
 *
 * It has a carrier of its own, so a large file never holds the JSON calls
 * behind it, and it feeds a body in parts no faster than the socket drains.
 * Its deadline counts from the last progress either way rather than from the
 * start, because a large file legitimately takes longer than a call.
 */
export function tunnelRouteRequest(
    options: Omit<TunnelRouteOptions, "open"> & {
        readonly open: () => Promise<{ tunnel: RawTunnelFacade; socket: TunnelSocket }>;
    },
): TunnelRouteRequest {
    const timeoutMs = options.timeoutMs ?? 30_000;
    const now = options.now ?? Date.now;
    const tick = options.tick;
    const carrier = tunnelCarrier(options.open, now);

    const request = (path: string, init: RequestInit = {}) => carrier.run(async (session) => {
        const { tunnel, socket } = session;
        const method = (init.method ?? "GET").toUpperCase();
        const body = partedBody(init.body);
        const given: Record<string, string> = {};
        new Headers(init.headers).forEach((value, name) => { given[name] = value; });
        if (body.contentType && !given["content-type"]) given["content-type"] = body.contentType;
        const key = given["idempotency-key"];
        const headers = {
            ...given,
            ...headersFor(options, method, key ? { idempotencyKey: key } : undefined),
        };
        tunnel.sendRequestHead(method, path, headers, body.length);
        let offset = 0;
        let progressAt = now();
        for (;;) {
            const seen = session.events();
            if (init.signal?.aborted) {
                // Mid-request: what crossed already cannot be called back, so
                // the session goes with it and the next request opens another.
                session.drop();
                throw new DOMException("the request was aborted", "AbortError");
            }
            while (offset < body.length
                   && tunnel.bufferedBytes() + (socket.bufferedAmount?.() ?? 0) < RAW_HIGH_WATER_BYTES) {
                const part = await body.read(offset, Math.min(RAW_PART_BYTES, body.length - offset));
                tunnel.sendBody(part);
                offset += part.length;
                progressAt = now();
            }
            if (tunnel.isPaired()) {
                const before = socket.bufferedAmount?.() ?? 0;
                flushFrames(tunnel, socket, RAW_HIGH_WATER_BYTES);
                if ((socket.bufferedAmount?.() ?? 0) !== before) progressAt = now();
            }
            const status = tunnel.pollStatus();
            if (status !== undefined) {
                // Copied into a buffer of its own: `Response` takes no view over
                // memory it does not own, and wasm memory is not.
                const bytes = new Uint8Array(tunnel.takeBodyBytes());
                const replyHeaders = tunnel.takeHeaders();
                return new Response(
                    nullBodyStatus(status) || method === "HEAD" ? null : bytes,
                    { status, headers: replyHeaders },
                );
            }
            if (!session.live()) {
                throw new TunnelClosed(session.closeReason() ?? "the Home tunnel closed mid-request");
            }
            if (tunnel.peerFinished?.()) {
                session.drop();
                throw new TunnelClosed("the Home ended the tunnel mid-request");
            }
            if (now() - Math.max(progressAt, session.lastFrameAt()) > timeoutMs) {
                session.drop();
                throw new HomeTunnelError(`${method} ${path}: the Home tunnel timed out`);
            }
            await (tick ? tick() : session.nextEvent(seen, TUNNEL_IDLE_POLL_MS));
        }
    });
    return Object.assign(request, { close: () => carrier.close() });
}

/** What one poll of an event tunnel produced, as the binding reports it. */
export type TunnelStreamPoll =
    | { readonly kind: "opened" }
    | { readonly kind: "event"; readonly data: string }
    | { readonly kind: "refused"; readonly status: number; readonly body: string }
    | { readonly kind: "ended" };

/** The `BrowserEventTunnel` facade: one event stream on its own pinned
 * session, opened with its request already queued. */
export interface EventTunnelFacade {
    receiveFrame(frame: Uint8Array): void;
    takeOutgoing(): Uint8Array;
    pollEvent(): TunnelStreamPoll | undefined;
    isPaired(): boolean;
    takeCredit(): Uint8Array;
}

/** Tell the relay what this leg has consumed, when it owes a report. The relay
 * counts what it sends a leg until the leg says it has taken it, and under
 * pressure closes the pairs holding the most (DR-0302). */
function sendCredit(tunnel: { takeCredit(): Uint8Array }, socket: TunnelSocket): void {
    const credit = tunnel.takeCredit();
    if (credit.length > 0) socket.send(credit);
}

export interface TunnelEventStreamOptions {
    /** Open a pinned session for `GET path` as an event stream, and its
     * carrier. Each stream is its own crossing: a Home's stream never ends, so
     * sharing the calls' one-at-a-time session would hold every call behind it. */
    readonly open: (
        path: string,
        headers: Record<string, string> | undefined,
    ) => Promise<{ tunnel: EventTunnelFacade; socket: TunnelSocket }>;
    /** Bounds the wait for the Home to answer. Once open, a stream is bounded
     * by its carrier instead: the Home's keep-alive and the relay's idle rule. */
    readonly openTimeoutMs?: number;
    readonly bearer?: () => string | null;
    readonly homeAdmission?: () => string | null;
}

/** A tunnel's `RouteEventStream`, plus the handle to end every stream it has
 * open — which a closing route needs, because each holds a Home crossing. */
export type TunnelEventStream = RouteEventStream & {
    /** End every open stream as closed under its subscriber, so a reconnecting
     * subscriber resolves its Home again rather than waiting on a dead one. */
    closeAll(reason?: string): void;
};

/** The reason a refusal carries, as the direct transport reads it: a Home
 * answers `{ "error": "…" }`, and `target Home admission required` is what
 * makes desk admit again. */
function refusal(status: number, body: string): RouteEventClose {
    try {
        const parsed = JSON.parse(body) as { error?: unknown };
        if (typeof parsed.error === "string") return { status, detail: parsed.error };
    } catch {
        /* not JSON — the status is the whole reason */
    }
    return { status };
}

/**
 * Carry a relay-only Home's event streams over the pinned tunnel (WS-634).
 *
 * Without this a browser opened no stream to such a Home at all, so a turn
 * sent from another window or device appeared only on reload. Each
 * subscription opens its own session and carrier, sends the same credentials
 * the calls carry, and reports a refusal or a close the way the direct
 * transport does, so the reconnecting wrapper above it re-admits and reopens
 * exactly as it does for a Home it reaches directly.
 *
 * The loop is driven by arrivals, not by a timer: every change in a client's
 * TLS state follows a frame from the relay — `READY`, the Home's handshake,
 * its data — so pumping after each frame is all a stream needs.
 */
export function tunnelRouteEventStream(options: TunnelEventStreamOptions): TunnelEventStream {
    const openTimeoutMs = options.openTimeoutMs ?? 30_000;
    const live = new Set<(reason?: string) => void>();
    const stream: RouteEventStream = (path, onMessage, onOpen, onClose) => {
        let unsubscribed = false;
        let finished = false;
        let socket: TunnelSocket | null = null;
        let timer: ReturnType<typeof setTimeout> | undefined;
        const finish = (reason?: RouteEventClose) => {
            if (finished) return;
            finished = true;
            live.delete(hangUp);
            clearTimeout(timer);
            socket?.close();
            if (!unsubscribed) onClose?.(reason);
        };
        const hangUp = (detail?: string) => finish(detail ? { detail } : undefined);
        live.add(hangUp);
        timer = setTimeout(
            () => finish({ detail: "the Home event stream did not open in time" }),
            openTimeoutMs,
        );
        void (async () => {
            let opened: { tunnel: EventTunnelFacade; socket: TunnelSocket };
            try {
                opened = await options.open(path, headersFor(options, "GET"));
            } catch (error) {
                finish({ detail: error instanceof Error ? error.message : String(error) });
                return;
            }
            if (finished) {
                opened.socket.close();
                return;
            }
            socket = opened.socket;
            const { tunnel } = opened;
            const drain = () => {
                try {
                    if (tunnel.isPaired()) flushFrames(tunnel, opened.socket);
                    for (let next = tunnel.pollEvent(); next && !finished; next = tunnel.pollEvent()) {
                        switch (next.kind) {
                            case "opened":
                                clearTimeout(timer);
                                onOpen?.();
                                break;
                            case "event":
                                onMessage(next.data);
                                break;
                            case "refused":
                                finish(refusal(next.status, next.body));
                                break;
                            case "ended":
                                finish();
                                break;
                        }
                    }
                } catch (error) {
                    finish({ detail: error instanceof Error ? error.message : String(error) });
                }
            };
            opened.socket.onFrame((frame) => {
                if (finished) return;
                try {
                    tunnel.receiveFrame(frame);
                    sendCredit(tunnel, opened.socket);
                } catch (error) {
                    finish({ detail: error instanceof Error ? error.message : String(error) });
                    return;
                }
                drain();
            });
            opened.socket.onClose((reason) => finish({ detail: reason ?? "the Home tunnel closed" }));
            drain();
        })();
        return () => {
            unsubscribed = true;
            finish();
        };
    };
    return Object.assign(stream, {
        closeAll(reason?: string) {
            for (const hangUp of [...live]) hangUp(reason ?? "the Home tunnel closed");
        },
    });
}

/** Copy a view into its own buffer: frames come out of wasm memory, and a
 * `WebSocket` will not accept a view over it. */
function copyOut(frame: Uint8Array): ArrayBuffer {
    const copy = new Uint8Array(frame.length);
    copy.set(frame);
    return copy.buffer;
}

/** The liveness exchange, as `relay-transport`'s `WSS_KEEPALIVE_REQUEST` and
 * `WSS_KEEPALIVE_RESPONSE` spell it. Text, because the relay answers it from
 * its Durable Object auto-response: it never wakes the object and is never
 * forwarded to the Home. */
export const TUNNEL_KEEPALIVE_REQUEST = "GWRPING";
export const TUNNEL_KEEPALIVE_RESPONSE = "GWRPONG";

/**
 * How often the browser's leg tells the relay it is alive — the native pump's
 * `KEEPALIVE_INTERVAL`.
 *
 * The client handshake sets the keepalive flag, and a Home sets it too, so the
 * relay judges the pair on its silence: it closes a leg whose last keepalive is
 * older than its idle bound, 150s at the edge, with 1008 "relay keepalive
 * missed". Carried data does not count. Until this was sent, every browser
 * tunnel to a Home was closed 150s after pairing, in use or not.
 *
 * Five fit inside the bound. A hidden tab's timers may be held to one run a
 * minute, which still lands two.
 */
export const TUNNEL_KEEPALIVE_INTERVAL_MS = 30_000;

/** The pieces of the browser a [`browserTunnelSocket`] uses, so a test can
 * drive one without a relay. */
export interface BrowserTunnelSocketSeams {
    readonly WebSocket?: new (url: string) => WebSocket;
    readonly keepaliveMs?: number;
}

/**
 * A [`TunnelSocket`] over a browser `WebSocket` (DESK-7).
 *
 * This is the one place the browser tunnel touches a socket, and it lives here
 * because `control-plane-client` is the declared transport owner — the wasm
 * module stays pump-driven precisely so this stays in TypeScript, where
 * `scripts/architecture-check.py` can see it.
 *
 * Frames that arrive before the caller attaches a handler are buffered rather
 * than dropped: the relay's `READY` can land before the first `onFrame`, and
 * losing it would stall a handshake that had actually succeeded. A close that
 * lands before `onClose` is kept the same way, or the route would hold a dead
 * carrier as live.
 *
 * It keeps the handshake's keepalive promise for as long as it is open,
 * whether or not anything is being carried.
 */
export function browserTunnelSocket(
    url: string,
    handshake: Uint8Array,
    seams: BrowserTunnelSocketSeams = {},
): Promise<TunnelSocket> {
    const Socket = seams.WebSocket ?? WebSocket;
    const keepaliveMs = seams.keepaliveMs ?? TUNNEL_KEEPALIVE_INTERVAL_MS;
    return new Promise((resolve, reject) => {
        const socket = new Socket(url);
        socket.binaryType = "arraybuffer";
        let onFrame: ((frame: Uint8Array) => void) | null = null;
        let onClose: ((reason?: string) => void) | null = null;
        let closedReason: string | undefined;
        let opened = false;
        let isClosed = false;
        let keepalive: ReturnType<typeof setInterval> | undefined;
        const pending: Uint8Array[] = [];

        socket.onmessage = (event: MessageEvent) => {
            // Binary only. The relay's text `GWRPONG` answers our keepalive and
            // carries nothing for the tunnel.
            if (!(event.data instanceof ArrayBuffer)) return;
            const frame = new Uint8Array(event.data);
            if (onFrame) onFrame(frame);
            else pending.push(frame);
        };
        socket.onclose = (event: CloseEvent) => {
            isClosed = true;
            closedReason = event.reason || "the Home tunnel closed";
            if (!opened) reject(new HomeTunnelError(closedReason));
            clearInterval(keepalive);
            keepalive = undefined;
            onClose?.(closedReason);
        };
        socket.onerror = () => {
            clearInterval(keepalive);
            socket.close();
            reject(new HomeTunnelError("the Home tunnel could not open"));
        };
        socket.onopen = () => {
            opened = true;
            // The fabric's frame first, before any tunnel bytes. Copied into a
            // plain ArrayBuffer because a wasm view is backed by shared memory,
            // which `send` will not take.
            socket.send(copyOut(handshake));
            keepalive = setInterval(() => {
                if (socket.readyState === socket.OPEN) socket.send(TUNNEL_KEEPALIVE_REQUEST);
            }, keepaliveMs);
            resolve({
                send: (frame) => socket.send(copyOut(frame)),
                bufferedAmount: () => socket.bufferedAmount,
                close: () => {
                    clearInterval(keepalive);
                    keepalive = undefined;
                    socket.close();
                },
                onFrame: (handler) => {
                    onFrame = handler;
                    while (pending.length > 0) handler(pending.shift()!);
                },
                onClose: (handler) => {
                    onClose = handler;
                    if (isClosed) handler(closedReason);
                },
            });
        };
    });
}
