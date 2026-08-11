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

import type { RouteJson } from "./control-plane-transport";
import type { OpaqueRelayLocator } from "./home-routing";

/** The `BrowserTunnel` facade, as a structural type so a test can stand one in
 * without loading wasm. Method names match the exported binding exactly. */
export interface TunnelFacade {
    receiveFrame(frame: Uint8Array): void;
    sendRequest(method: string, path: string, body?: string): void;
    takeOutgoing(): Uint8Array;
    pollStatus(): number | undefined;
    takeBody(): string;
    isHandshaking(): boolean;
}

/** The socket, narrowed to what the loop uses. */
export interface TunnelSocket {
    send(frame: Uint8Array): void;
    close(): void;
    onFrame(handler: (frame: Uint8Array) => void): void;
    onClose(handler: () => void): void;
}

export interface TunnelRouteOptions {
    /** Open the carrier and send the handshake frame. */
    readonly connect: (locator: OpaqueRelayLocator, handshake: Uint8Array) => Promise<TunnelSocket>;
    /** The 84-byte `client` handshake, from the wasm binding. */
    readonly handshake: (locator: OpaqueRelayLocator) => Uint8Array;
    readonly tunnel: TunnelFacade;
    /** The Home's relay locator — what this tunnel is pinned to and dials. */
    readonly locator: OpaqueRelayLocator;
    /** Bounds a request. A tunnel that stops answering must fail the call rather
     * than leave a caller waiting forever. */
    readonly timeoutMs?: number;
    readonly now?: () => number;
    /** Yield between pumps; a test drives it synchronously. */
    readonly tick?: () => Promise<void>;
}

class TunnelClosed extends Error {}

/**
 * Build a `RouteJson` that carries each call over the pinned tunnel.
 *
 * Requests are serialized: the wire is one request/response at a time, so a
 * second caller waits rather than interleaving frames into the same session.
 */
export function tunnelRouteJson(options: TunnelRouteOptions): RouteJson {
    const timeoutMs = options.timeoutMs ?? 30_000;
    const now = options.now ?? Date.now;
    const tick = options.tick ?? (() => new Promise<void>((resolve) => setTimeout(resolve, 0)));
    let socket: TunnelSocket | null = null;
    let closed = false;
    let queue: Promise<unknown> = Promise.resolve();

    async function ensureSocket(locator: OpaqueRelayLocator): Promise<TunnelSocket> {
        if (socket) return socket;
        const opened = await options.connect(locator, options.handshake(locator));
        opened.onFrame((frame) => options.tunnel.receiveFrame(frame));
        opened.onClose(() => {
            closed = true;
            socket = null;
        });
        socket = opened;
        return opened;
    }

    return (method, path, body) => {
        const locator = options.locator;
        // One at a time: the tunnel carries a single stream, so interleaving two
        // requests would splice their frames together.
        const run = queue.then(async () => {
            if (closed) throw new Error("the Home tunnel closed");
            const live = await ensureSocket(locator);
            options.tunnel.sendRequest(method, path, body === undefined ? undefined : JSON.stringify(body));
            const deadline = now() + timeoutMs;
            for (;;) {
                const outgoing = options.tunnel.takeOutgoing();
                if (outgoing.length > 0) live.send(outgoing);
                const status = options.tunnel.pollStatus();
                if (status !== undefined) {
                    const text = options.tunnel.takeBody();
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
    };
}
