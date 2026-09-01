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
import type { RouteJson, RouteOptions } from "./control-plane-transport";

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
 * and then never use it. */
function headersFor(bearer: (() => string | null) | undefined,
                    options?: RouteOptions): Record<string, string> | undefined {
    const headers: Record<string, string> = {};
    const token = bearer?.();
    if (token) headers.authorization = `Bearer ${token}`;
    if (options?.idempotencyKey) headers["idempotency-key"] = options.idempotencyKey;
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
}

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
    /** Hang up: close the carrier and refuse further calls. Idempotent. */
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
    let closed = false;
    let queue: Promise<unknown> = Promise.resolve();

    async function ensure(): Promise<{ tunnel: TunnelFacade; socket: TunnelSocket }> {
        if (live) return live;
        const opened = await options.open();
        opened.socket.onFrame((frame) => opened.tunnel.receiveFrame(frame));
        opened.socket.onClose(() => {
            closed = true;
            live = null;
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
            if (closed) throw new Error("the Home tunnel closed");
            const { tunnel, socket } = await ensure();
            tunnel.sendRequest(
                method, path,
                body === undefined ? undefined : JSON.stringify(body),
                headersFor(options.bearer, routeOptions),
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
                if (closed) throw new TunnelClosed("the Home tunnel closed mid-request");
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
            closed = true;
            const open = live;
            live = null;
            open?.socket.close();
        },
    });
    return route;
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
 * losing it would stall a handshake that had actually succeeded.
 */
/** Copy a view into its own buffer: frames come out of wasm memory, and a
 * `WebSocket` will not accept a view over it. */
function copyOut(frame: Uint8Array): ArrayBuffer {
    const copy = new Uint8Array(frame.length);
    copy.set(frame);
    return copy.buffer;
}

export function browserTunnelSocket(url: string, handshake: Uint8Array): Promise<TunnelSocket> {
    return new Promise((resolve, reject) => {
        const socket = new WebSocket(url);
        socket.binaryType = "arraybuffer";
        let onFrame: ((frame: Uint8Array) => void) | null = null;
        let onClose: (() => void) | null = null;
        const pending: Uint8Array[] = [];

        socket.onmessage = (event: MessageEvent) => {
            if (!(event.data instanceof ArrayBuffer)) return;
            const frame = new Uint8Array(event.data);
            if (onFrame) onFrame(frame);
            else pending.push(frame);
        };
        socket.onclose = () => onClose?.();
        socket.onerror = () => reject(new Error(`the Home tunnel could not open: ${url}`));
        socket.onopen = () => {
            // The fabric's frame first, before any tunnel bytes. Copied into a
            // plain ArrayBuffer because a wasm view is backed by shared memory,
            // which `send` will not take.
            socket.send(copyOut(handshake));
            resolve({
                send: (frame) => socket.send(copyOut(frame)),
                close: () => socket.close(),
                onFrame: (handler) => {
                    onFrame = handler;
                    while (pending.length > 0) handler(pending.shift()!);
                },
                onClose: (handler) => { onClose = handler; },
            });
        };
    });
}
