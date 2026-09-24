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

/** The `BrowserTunnel` facade, as a structural type so a test can stand one in
 * without loading wasm. Method names match the exported binding exactly. */
export interface TunnelFacade {
    receiveFrame(frame: Uint8Array): void;
    sendRequest(method: string, path: string, body?: string,
                headers?: Record<string, string>): void;
    takeOutgoing(): Uint8Array;
    pollStatus(): number | undefined;
    takeBody(): string;
    isHandshaking(): boolean;
    /** Whether the relay has spliced this leg to the Home's. */
    isPaired(): boolean;
}

/** The socket, narrowed to what the loop uses. */
export interface TunnelSocket {
    send(frame: Uint8Array): void;
    close(): void;
    onFrame(handler: (frame: Uint8Array) => void): void;
    onClose(handler: () => void): void;
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
}

type TunnelCredentials = Pick<TunnelRouteOptions, "bearer" | "homeAdmission">;

class TunnelClosed extends Error {}

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

/**
 * Build a `RouteJson` that carries each call over the pinned tunnel.
 *
 * Requests are serialized: the wire is one request/response at a time, so a
 * second caller waits rather than interleaving frames into the same session.
 */
export function tunnelRouteJson(options: TunnelRouteOptions): TunnelRoute {
    const timeoutMs = options.timeoutMs ?? 30_000;
    const now = options.now ?? Date.now;
    const tick = options.tick ?? (() => new Promise<void>((resolve) => setTimeout(resolve, 0)));
    let live: { tunnel: TunnelFacade; socket: TunnelSocket } | null = null;
    // Only the caller hangs a route up for good. A carrier that closes under it
    // — the Home ending an idle crossing, the relay closing a leg — takes the
    // session with it, not the route: the next call opens a fresh one, exactly
    // as the first call did. Refusing forever instead left a live pool entry
    // answering "the Home tunnel closed" to every call until something else
    // happened to evict it.
    let hungUp = false;
    let queue: Promise<unknown> = Promise.resolve();

    async function ensure(): Promise<{ tunnel: TunnelFacade; socket: TunnelSocket }> {
        if (live) return live;
        const opened = await options.open();
        if (hungUp) {
            // Hung up while this was opening: nothing will ever close it.
            opened.socket.close();
            throw new TunnelClosed("the Home tunnel closed");
        }
        opened.socket.onFrame((frame) => opened.tunnel.receiveFrame(frame));
        opened.socket.onClose(() => {
            // Only its own session. A late close from a carrier already
            // replaced must not orphan the one that replaced it.
            if (live === opened) live = null;
        });
        live = opened;
        return opened;
    }

    const route: TunnelRoute = Object.assign((
        method: string,
        path: string,
        body?: unknown,
        routeOptions?: RouteOptions,
    ) => {
        // One at a time: the tunnel carries a single stream, so interleaving two
        // requests would splice their frames together.
        const run = queue.then(async () => {
            if (hungUp) throw new TunnelClosed("the Home tunnel closed");
            const session = await ensure();
            const { tunnel, socket } = session;
            tunnel.sendRequest(
                method, path,
                body === undefined ? undefined : JSON.stringify(body),
                headersFor(options, method, routeOptions),
            );
            const deadline = now() + timeoutMs;
            for (;;) {
                // Not before the relay has spliced this leg. Ciphertext written
                // into an unpaired route has no other end, and relying on the
                // relay to hold it is relying on a component whose whole design
                // is to be dumb. It accumulates in the session either way.
                if (tunnel.isPaired()) {
                    const outgoing = tunnel.takeOutgoing();
                    if (outgoing.length > 0) socket.send(outgoing);
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
                if (live !== session) throw new TunnelClosed("the Home tunnel closed mid-request");
                if (now() > deadline) {
                    throw new Error(`${method} ${path}: the Home tunnel timed out`);
                }
                await tick();
            }
        });
        // Keep the chain alive after a rejection so one failure does not wedge
        // every later request behind it.
        queue = run.catch(() => undefined);
        return run;
    }, {
        close() {
            hungUp = true;
            const open = live;
            live = null;
            open?.socket.close();
        },
    });
    return route;
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
        let onClose: (() => void) | null = null;
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
        socket.onclose = () => {
            isClosed = true;
            clearInterval(keepalive);
            keepalive = undefined;
            onClose?.();
        };
        socket.onerror = () => reject(new Error(`the Home tunnel could not open: ${url}`));
        socket.onopen = () => {
            // The fabric's frame first, before any tunnel bytes. Copied into a
            // plain ArrayBuffer because a wasm view is backed by shared memory,
            // which `send` will not take.
            socket.send(copyOut(handshake));
            keepalive = setInterval(() => {
                if (socket.readyState === socket.OPEN) socket.send(TUNNEL_KEEPALIVE_REQUEST);
            }, keepaliveMs);
            resolve({
                send: (frame) => socket.send(copyOut(frame)),
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
                    if (isClosed) handler();
                },
            });
        };
    });
}
