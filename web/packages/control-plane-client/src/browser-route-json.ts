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

export type RouteEventStream = (
    path: string,
    onMessage: (data: string) => void,
    onOpen?: () => void,
) => () => void;

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
    return (path, onMessage, onOpen) => {
        const controller = new AbortController();
        void (async () => {
            try {
                const response = await request(path, {
                    headers: { accept: "text/event-stream" },
                    signal: controller.signal,
                });
                if (!response.ok || !response.body) return;
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
            }
        })();
        return () => controller.abort();
    };
}

/** Build a route error that carries the server's own message when it sent one.
 *  Control-plane failures return `{ "error": "…" }` (e.g. a 502 whose body explains a
 *  unavailable runtime); without this the UI only ever saw the bare status code. Falls
 *  back to the raw body, then to just the status when the body is empty/unreadable. */
async function routeError(
    method: string,
    path: string,
    res: Response,
): Promise<string> {
    const prefix = `${method} ${path}: ${res.status}`;
    let detail = "";
    try {
        detail = await res.text();
    } catch {
        return prefix;
    }
    try {
        const parsed = JSON.parse(detail) as { error?: unknown };
        if (typeof parsed.error === "string" && parsed.error) return `${prefix} ${parsed.error}`;
    } catch {
        /* not JSON — fall through to the raw text */
    }
    return detail ? `${prefix} ${detail}` : prefix;
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
        if (!res.ok) throw new Error(await routeError(method, path, res));
        return res.status === 204 ? null : res.json();
    };
}
