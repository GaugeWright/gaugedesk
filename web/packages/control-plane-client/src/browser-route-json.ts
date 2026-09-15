import { Rejected, TurnStopped, TURN_STOPPED_STATUS } from "./control-plane-domain";
import { newIdempotencyKey, type RouteJson } from "./control-plane-transport";
import { reportedClientBuild, type ClientBuildDeclaration } from "./client-build";

export interface BrowserRouteJsonOptions {
    readonly bearer?: () => string | null;
    readonly publishableKey?: () => string | null;
    /** Tenant context is explicit metadata for tenant-scoped control-plane
     * projections. It is never a grant; every route still admits the actor. */
    readonly tenant?: () => string | null;
    /** Target-Home admission is separate from account login (ADR 0084). */
    readonly homeAdmission?: () => string | null;
    /** Short-lived device-bound controller session for one exact Machine
     * (ADR 0109). It authenticates the same work routes; it is not a second API. */
    readonly machineSession?: () => string | null;
    /** Override only for compatibility tests or a nonstandard host. Production
     * browser/desktop clients report the manifest build automatically. */
    readonly clientBuild?: () => ClientBuildDeclaration | null;
}

export type RouteRequest = (path: string, init?: RequestInit) => Promise<Response>;

export interface RouteEventClose {
    readonly status?: number;
    readonly detail?: string;
}

export type RouteEventStream = (
    path: string,
    onMessage: (data: string) => void,
    onOpen?: () => void,
    onClose?: (reason?: RouteEventClose) => void,
) => () => void;

export interface ReconnectingEventStream {
    /** Permanently dispose this subscription and cancel any pending retry. */
    close(): void;
    /** Immediately resolve the route again, used when a project changes Home. */
    reconnect(): void;
}

export interface ReconnectingEventStreamOptions {
    readonly delaysMs?: readonly number[];
    readonly beforeReconnect?: (reason?: RouteEventClose) => void | Promise<void>;
}

/** Keep one reference-only SSE subscription alive without pretending it can
 * replay. `onOpen` runs after every successful connection so the owner can
 * reconcile its authoritative projection. Resolving the source anew on every
 * attempt is important for project-routed Homes: a retry may need a fresh
 * admission or a different endpoint. */
export function openReconnectingEventStream(
    resolve: () => RouteEventStream | undefined | Promise<RouteEventStream | undefined>,
    path: string,
    onMessage: (data: string) => void,
    onOpen?: () => void,
    onClose?: (reason?: RouteEventClose) => void,
    options: ReconnectingEventStreamOptions = {},
): ReconnectingEventStream {
    const delays = options.delaysMs?.length ? options.delaysMs : [250, 500, 1_000, 2_000, 5_000];
    let disposed = false;
    let attempt = 0;
    let failures = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let stopCurrent = () => {};

    const clearTimer = () => {
        if (timer !== undefined) clearTimeout(timer);
        timer = undefined;
    };
    const connect = async () => {
        if (disposed) return;
        clearTimer();
        const ownAttempt = ++attempt;
        try {
            const source = await resolve();
            if (disposed || ownAttempt !== attempt) return;
            if (!source) throw new Error("event stream unavailable");
            let opened = false;
            const stop = source(
                path,
                onMessage,
                () => {
                    if (disposed || ownAttempt !== attempt) return;
                    opened = true;
                    failures = 0;
                    onOpen?.();
                },
                (reason) => {
                    if (disposed || ownAttempt !== attempt) return;
                    const recoveryAttempt = ++attempt;
                    stopCurrent = () => {};
                    onClose?.(reason);
                    void (async () => {
                        try {
                            await options.beforeReconnect?.(reason);
                        } catch {
                            // Route repair is best-effort. The bounded retry loop
                            // remains the honest availability mechanism.
                        }
                        if (disposed || attempt !== recoveryAttempt) return;
                        const index = Math.min(failures, delays.length - 1);
                        failures = opened ? 0 : failures + 1;
                        timer = setTimeout(() => void connect(), delays[index]);
                    })();
                },
            );
            if (disposed || ownAttempt !== attempt) stop();
            else stopCurrent = stop;
        } catch {
            if (disposed || ownAttempt !== attempt) return;
            attempt += 1;
            const index = Math.min(failures, delays.length - 1);
            failures += 1;
            timer = setTimeout(() => void connect(), delays[index]);
        }
    };

    void connect();
    return {
        close() {
            if (disposed) return;
            disposed = true;
            attempt += 1;
            clearTimer();
            stopCurrent();
            stopCurrent = () => {};
        },
        reconnect() {
            if (disposed) return;
            attempt += 1;
            clearTimer();
            stopCurrent();
            stopCurrent = () => {};
            failures = 0;
            void connect();
        },
    };
}

/** RouteEventStream-shaped convenience for transports without an external
 * route-change signal. */
export function reconnectingRouteEventStream(
    resolve: () => RouteEventStream | undefined | Promise<RouteEventStream | undefined>,
    options: ReconnectingEventStreamOptions = {},
): RouteEventStream {
    return (path, onMessage, onOpen, onClose) => {
        const subscription = openReconnectingEventStream(
            resolve,
            path,
            onMessage,
            onOpen,
            onClose,
            options,
        );
        return () => subscription.close();
    };
}

/** One browser request edge for JSON, files/config, and authenticated SSE. */
export function browserRouteRequest(
    base: string,
    options: BrowserRouteJsonOptions = {},
): RouteRequest {
    const normalizedBase = base.replace(/\/+$/, "");
    return async (path, init = {}) => {
        const method = (init.method ?? "GET").toUpperCase();
        const headers = new Headers(init.headers);
        const bearer = options.bearer?.();
        const publishableKey = options.publishableKey?.();
        const tenant = options.tenant?.();
        const homeAdmission = options.homeAdmission?.();
        const machineSession = options.machineSession?.();
        const clientBuild = options.clientBuild === undefined
            ? reportedClientBuild()
            : options.clientBuild();
        if (bearer) headers.set("authorization", `Bearer ${bearer}`);
        if (publishableKey) headers.set("x-gw-publishable-key", publishableKey);
        if (tenant) headers.set("x-gaugewright-tenant", tenant);
        if (homeAdmission) {
            headers.set("x-gaugewright-home-admission", homeAdmission);
        }
        if (machineSession) {
            headers.set("x-gaugewright-machine-session", machineSession);
        }
        if (clientBuild) {
            headers.set("x-gaugedesk-client-version", clientBuild.version);
            headers.set("x-gaugedesk-client-protocol", String(clientBuild.protocol));
            headers.set("x-gaugedesk-client-channel", clientBuild.channel);
            headers.set("x-gaugedesk-client-platform", clientBuild.platform);
        }
        if (
            method !== "GET" &&
            method !== "HEAD" &&
            method !== "OPTIONS" &&
            !headers.has("idempotency-key")
        ) {
            headers.set("idempotency-key", newIdempotencyKey());
        }
        return fetch(normalizedBase + path, {
            ...init,
            method,
            headers,
            credentials: "include",
        });
    };
}

/** Fetch-backed SSE so a Home admission header can travel with the stream.
 * Native EventSource cannot attach that credential. */
export function browserRouteEventStream(
    base: string,
    options: BrowserRouteJsonOptions = {},
): RouteEventStream {
    const request = browserRouteRequest(base, options);
    return (path, onMessage, onOpen, onClose) => {
        const controller = new AbortController();
        void (async () => {
            let closeReason: RouteEventClose | undefined;
            try {
                const response = await request(path, {
                    headers: { accept: "text/event-stream" },
                    signal: controller.signal,
                });
                if (!response.ok) {
                    closeReason = { status: response.status };
                    const contentType = response.headers.get("content-type") ?? "";
                    const length = Number(response.headers.get("content-length"));
                    if (
                        contentType.startsWith("application/json")
                        && Number.isSafeInteger(length)
                        && length > 0
                        && length <= 256
                    ) {
                        try {
                            const body = await response.json() as { error?: unknown };
                            if (typeof body.error === "string") {
                                closeReason = { status: response.status, detail: body.error };
                            }
                        } catch {
                            /* keep the status-only close reason */
                        }
                    }
                    return;
                }
                if (!response.body) {
                    closeReason = { status: response.status, detail: "event stream body unavailable" };
                    return;
                }
                onOpen?.();
                const reader = response.body.getReader();
                const decoder = new TextDecoder();
                let buffer = "";
                while (!controller.signal.aborted) {
                    const { done, value } = await reader.read();
                    buffer += decoder.decode(value, { stream: !done }).replace(/\r\n/g, "\n");
                    let boundary = buffer.indexOf("\n\n");
                    while (boundary >= 0) {
                        const frame = buffer.slice(0, boundary);
                        buffer = buffer.slice(boundary + 2);
                        const data = frame
                            .split("\n")
                            .filter((line) => line.startsWith("data:"))
                            .map((line) => line.slice(5).replace(/^ /, ""))
                            .join("\n");
                        if (data) onMessage(data);
                        boundary = buffer.indexOf("\n\n");
                    }
                    if (done) break;
                }
            } catch (error) {
                if (!controller.signal.aborted) {
                    // A projection refetch repairs a dropped stream. Do not leak
                    // credentials or network details through an unhandled rejection.
                    void error;
                }
            } finally {
                if (!controller.signal.aborted) onClose?.(closeReason);
            }
        })();
        return () => controller.abort();
    };
}

/** Build a route error that carries the server's own message when it sent one.
 *  Control-plane failures return `{ "error": "…" }` (e.g. a 502 whose body explains a
 *  unavailable runtime); without this the UI only ever saw the bare status code. Falls
 *  back to the raw body, then to just the status when the body is empty/unreadable. */
export class RouteHttpError extends Error {
    readonly status: number;
    readonly method: string;
    readonly path: string;

    constructor(method: string, path: string, status: number, message: string) {
        super(message);
        this.name = "RouteHttpError";
        this.status = status;
        this.method = method;
        this.path = path;
    }
}

async function routeError(
    method: string,
    path: string,
    res: Response,
): Promise<RouteHttpError> {
    const prefix = `${method} ${path}: ${res.status}`;
    let detail = "";
    try {
        detail = await res.text();
    } catch {
        return new RouteHttpError(method, path, res.status, prefix);
    }
    try {
        const parsed = JSON.parse(detail) as { error?: unknown };
        if (typeof parsed.error === "string" && parsed.error) {
            return new RouteHttpError(method, path, res.status, `${prefix} ${parsed.error}`);
        }
    } catch {
        /* not JSON — fall through to the raw text */
    }
    return new RouteHttpError(method, path, res.status, detail ? `${prefix} ${detail}` : prefix);
}

export function browserRouteJson(
    base: string,
    options: BrowserRouteJsonOptions = {},
): RouteJson {
    const request = browserRouteRequest(base, options);
    return async (method, path, body, routeOptions) => {
        const mutating = method !== "GET" && method !== "HEAD" && method !== "OPTIONS";
        const idempotencyKey = mutating
            ? (routeOptions?.idempotencyKey ?? newIdempotencyKey())
            : null;
        const res = await request(path, {
            method,
            headers: {
                ...(body !== undefined ? { "content-type": "application/json" } : {}),
                ...(idempotencyKey ? { "idempotency-key": idempotencyKey } : {}),
            },
            // Send the shared `.gaugewright.com` session cookie cross-origin (GaugeDesk or Hub →
            // auth.gaugewright.com), so a cookie session
            // authenticates without a JS-visible bearer (ADR 0077; the server allows credentials for
            // its pinned origin allowlist). Same-origin/desktop is unaffected.
            body: body !== undefined ? JSON.stringify(body) : undefined,
        });
        if (res.status === 409) {
            const r = (await res.json()) as { rejected?: string; error?: string; message?: string; command_status?: string };
            throw new Rejected(r.rejected ?? r.error ?? r.message ?? "unknown", r.command_status);
        }
        if (res.status === TURN_STOPPED_STATUS) throw new TurnStopped();
        if (!res.ok) throw await routeError(method, path, res);
        return res.status === 204 ? null : res.json();
    };
}
