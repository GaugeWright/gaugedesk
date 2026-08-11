/**
 * A bounded, exact-Home connection pool shared by every project-first client
 * (DESK-3, [ADR 0130](../../../../specs/decisions/0130-browser-thin-client-tunnels-the-relay-fabric-in-wasm.md)).
 *
 * Work is organized by project, never by Home: a client resolves a project to
 * its opaque route, opens or reuses a connection keyed by the exact Home, admits
 * the person there, and verifies the responding Home is the one the route named.
 * Several Homes are live at once and **there is no selected Home** — one Home
 * failing degrades only its own projects.
 *
 * Account-plane pointers select an endpoint and never become authority: every
 * new entry performs its own target admission, and a route that changes under a
 * connection tears that connection down rather than inheriting its admission.
 *
 * The pool owns connection lifecycle and state; it never calls a method on the
 * per-Home client, so the client type is a parameter. Native shells resolve a
 * relay-only route to a device-loopback endpoint outside the page; a browser has
 * no loopback to hand back and supplies its own transport instead. Both arrive
 * through the same two seams (`resolveEndpoint`, `routeJson`).
 */

import { browserRouteJson } from "./browser-route-json";
import type { RouteJson } from "./control-plane-transport";
import type { HomeId, ProjectId } from "./control-plane-domain";
import { opaqueHomeRouteKey, type OpaqueHomeRoute } from "./home-routing";

/** Why a Home is not currently serving. Each is distinct and said plainly; none
 * is collapsed into a generic failure, and none implies a retry that cannot
 * succeed (`experience/desk.md`). */
export type HomeConnectionState =
    | "needs-sign-in"
    | "needs-admission"
    | "connecting"
    | "live"
    | "stale"
    | "offline"
    | "grant-expired"
    | "grant-revoked"
    | "device-untrusted"
    | "policy-denied";

export interface HomeConnection<Api> {
    readonly homeId: HomeId;
    readonly endpoint: string;
    readonly api: Api;
    readonly state: HomeConnectionState;
    readonly lastUsedAt: number;
}

interface MutableHomeConnection<Api> {
    readonly homeId: HomeId;
    readonly endpoint: string;
    readonly routeKey: string;
    readonly admission: string;
    readonly api: Api;
    state: HomeConnectionState;
    lastUsedAt: number;
}

/** Everything a per-Home client needs, assembled by the pool. The two callbacks
 * are how a client reports trouble back without the pool knowing its shape. */
export interface HomeClientContext {
    readonly endpoint: string;
    readonly routeJson: RouteJson;
    readonly bearer: () => string | null;
    readonly homeAdmission: () => string | null;
    readonly onAuthorizationRejected: (status: number, detail: string) => void;
    readonly onTransportUnavailable: () => void;
}

export interface HomePoolOptions<Api> {
    /** Build the per-Home client. Required: it is the only thing that differs
     * between a phone, a desktop, and a browser. */
    readonly client: (context: HomeClientContext) => Api;
    readonly maxConnections?: number;
    readonly idleMs?: number;
    readonly now?: () => number;
    readonly onStateChange?: (homeId: HomeId, state: HomeConnectionState) => void;
    readonly routeJson?: (
        endpoint: string,
        auth: {
            readonly bearer: () => string | null;
            readonly homeAdmission: () => string | null;
        },
    ) => RouteJson;
    /** Turn an opaque route into something dialable. A native shell opens the
     * pinned tunnel and returns device loopback; the default takes the route's
     * own endpoint. */
    readonly resolveEndpoint?: (route: OpaqueHomeRoute) => Promise<string>;
    readonly closeRoute?: (homeId: HomeId) => Promise<void>;
    /** Re-read the account's routes. A rotation invalidates outstanding locators
     * the moment it lands at the relay, so a client refused for a stale epoch
     * re-reads once and retries rather than reporting the Home unreachable
     * (ADR 0131 §5). Without this seam the pool simply does not retry. */
    readonly refreshRoutes?: () => Promise<readonly OpaqueHomeRoute[]>;
}

/** Whether a failure looks like the relay refusing a superseded locator, rather
 * than the Home refusing the person. Only the former is worth re-reading for:
 * an admission refusal will refuse again just as fast. */
export function isStaleRouteFailure(error: unknown): boolean {
    return /stale|epoch|route proof|refused pairing/i.test(
        error instanceof Error ? error.message : String(error ?? ""),
    );
}

/** Map an authorization refusal onto a connection state. This is pool logic,
 * not client logic: what a 421 or a 401 *means* is the same everywhere. */
export function refusalState(status: number, detail: string): HomeConnectionState {
    if (status === 421) return "stale";
    if (status === 401) {
        return /target Home admission required/i.test(detail)
            ? "needs-admission"
            : "needs-sign-in";
    }
    return /Home admission/i.test(detail) ? "needs-admission" : "policy-denied";
}

export class HomePool<Api> {
    private routes = new Map<ProjectId, OpaqueHomeRoute>();
    private readonly connections = new Map<HomeId, MutableHomeConnection<Api>>();
    private readonly pending = new Map<HomeId, Promise<MutableHomeConnection<Api>>>();
    private readonly maxConnections: number;
    private readonly idleMs: number;
    private readonly now: () => number;
    private readonly makeClient: HomePoolOptions<Api>["client"];
    private readonly makeRouteJson: NonNullable<HomePoolOptions<Api>["routeJson"]>;
    private readonly resolveEndpoint: NonNullable<HomePoolOptions<Api>["resolveEndpoint"]>;
    private readonly closeRoute: NonNullable<HomePoolOptions<Api>["closeRoute"]>;
    private readonly refreshRoutes: HomePoolOptions<Api>["refreshRoutes"];
    private readonly onStateChange: NonNullable<HomePoolOptions<Api>["onStateChange"]>;

    constructor(
        routes: readonly OpaqueHomeRoute[],
        private readonly bearer: () => string | null,
        options: HomePoolOptions<Api>,
    ) {
        this.makeClient = options.client;
        this.maxConnections = Math.max(1, options.maxConnections ?? 3);
        this.idleMs = Math.max(1, options.idleMs ?? 5 * 60_000);
        this.now = options.now ?? Date.now;
        this.onStateChange = options.onStateChange ?? (() => undefined);
        this.makeRouteJson =
            options.routeJson ?? ((endpoint, auth) => browserRouteJson(endpoint, auth));
        this.resolveEndpoint = options.resolveEndpoint ?? (async (route) => route.endpoint);
        this.closeRoute = options.closeRoute ?? (async () => undefined);
        this.refreshRoutes = options.refreshRoutes;
        this.replaceRoutes(routes);
    }

    replaceRoutes(routes: readonly OpaqueHomeRoute[]): void {
        const next = new Map<ProjectId, OpaqueHomeRoute>();
        for (const route of routes) {
            const prior = next.get(route.project);
            if (prior && opaqueHomeRouteKey(prior) !== opaqueHomeRouteKey(route)) {
                throw new Error(`conflicting Home routes for project ${route.project}`);
            }
            next.set(route.project, route);
        }
        this.routes = next;

        for (const [homeId, connection] of this.connections) {
            const stillRouted = routes.some(
                (route) =>
                    route.homeId === homeId
                    && opaqueHomeRouteKey(route) === connection.routeKey,
            );
            if (!stillRouted) void this.disconnect(homeId);
        }
    }

    /** Which Homes this client can currently reach a project through. */
    routedProjects(): ProjectId[] {
        return [...this.routes.keys()];
    }

    routeFor(project: ProjectId): OpaqueHomeRoute {
        const route = this.routes.get(project);
        if (!route) throw new Error(`no granted Home route for project ${project}`);
        return route;
    }

    snapshot(): HomeConnection<Api>[] {
        return [...this.connections.values()]
            .map(({ admission: _admission, ...connection }) => connection)
            .sort((left, right) => left.homeId.localeCompare(right.homeId));
    }

    async connectProject(project: ProjectId): Promise<HomeConnection<Api>> {
        try {
            return await this.attemptProject(project);
        } catch (error) {
            // Exactly once. A rotation is a reachability event, so one re-read
            // resolves it; a second would be a retry loop against a Home that is
            // simply refusing.
            if (!this.refreshRoutes || !isStaleRouteFailure(error)) throw error;
            const refreshed = await this.refreshRoutes();
            const current = this.routes.get(project);
            const next = refreshed.find((route) => route.project === project);
            if (!next || (current && opaqueHomeRouteKey(current) === opaqueHomeRouteKey(next))) {
                // The route did not move, so the failure was not staleness.
                throw error;
            }
            this.replaceRoutes(refreshed);
            return this.attemptProject(project);
        }
    }

    private async attemptProject(project: ProjectId): Promise<HomeConnection<Api>> {
        const route = this.routeFor(project);
        const existing = this.connections.get(route.homeId);
        if (existing) {
            if (existing.routeKey !== opaqueHomeRouteKey(route)) {
                await this.disconnect(route.homeId);
            } else if (existing.state === "live") {
                existing.lastUsedAt = this.now();
                return this.publicConnection(existing);
            } else {
                await this.disconnect(route.homeId);
            }
        }

        let pending = this.pending.get(route.homeId);
        if (!pending) {
            pending = this.admit(route);
            this.pending.set(route.homeId, pending);
        }
        try {
            return this.publicConnection(await pending);
        } finally {
            this.pending.delete(route.homeId);
        }
    }

    mark(project: ProjectId, state: HomeConnectionState): void {
        const route = this.routeFor(project);
        const connection = this.connections.get(route.homeId);
        if (!connection) return;
        connection.state = state;
        connection.lastUsedAt = this.now();
        this.onStateChange(connection.homeId, state);
    }

    async evictIdle(now = this.now()): Promise<void> {
        const stale = [...this.connections.values()]
            .filter((connection) => now - connection.lastUsedAt >= this.idleMs)
            .map((connection) => connection.homeId);
        await Promise.all(stale.map((homeId) => this.disconnect(homeId)));
    }

    async closeAll(): Promise<void> {
        await Promise.all(
            [...this.connections.keys()].map((homeId) => this.disconnect(homeId)),
        );
        this.pending.clear();
    }

    private async admit(route: OpaqueHomeRoute): Promise<MutableHomeConnection<Api>> {
        if (!this.bearer()) throw new Error("sign in before opening a project");
        let admission: string | null = null;
        const auth = {
            bearer: this.bearer,
            homeAdmission: () => admission,
        };
        const routeKey = opaqueHomeRouteKey(route);
        const endpoint = await this.resolveEndpoint(route);
        const json = this.makeRouteJson(endpoint, auth);
        const result = (await json("POST", "/home/admissions")) as {
            home?: unknown;
            admission?: unknown;
        };
        // The route said which Home this is. A Home that answers as another one
        // does not get to serve, whatever the pointer claimed.
        if (result.home !== route.homeId || typeof result.admission !== "string") {
            if (typeof result.admission === "string") {
                admission = result.admission;
                await json("DELETE", "/home/admissions").catch(() => undefined);
            }
            throw new Error(`Home identity mismatch: expected ${route.homeId}`);
        }
        admission = result.admission;
        const current = this.routes.get(route.project);
        if (
            !current
            || current.homeId !== route.homeId
            || opaqueHomeRouteKey(current) !== routeKey
        ) {
            await json("DELETE", "/home/admissions").catch(() => undefined);
            throw new Error("project route changed during Home admission");
        }
        let connection: MutableHomeConnection<Api>;
        const api = this.makeClient({
            endpoint,
            routeJson: json,
            bearer: this.bearer,
            homeAdmission: () => admission,
            onAuthorizationRejected: (status, detail) => {
                connection.state = refusalState(status, detail);
                this.onStateChange(connection.homeId, connection.state);
            },
            onTransportUnavailable: () => {
                connection.state = "offline";
                connection.lastUsedAt = this.now();
                this.onStateChange(connection.homeId, "offline");
            },
        });
        connection = {
            homeId: route.homeId,
            endpoint,
            routeKey,
            admission,
            api,
            state: "live",
            lastUsedAt: this.now(),
        };
        this.connections.set(route.homeId, connection);
        this.onStateChange(connection.homeId, "live");
        await this.enforceBound();
        return connection;
    }

    private async enforceBound(): Promise<void> {
        while (this.connections.size > this.maxConnections) {
            const oldest = [...this.connections.values()].sort(
                (left, right) => left.lastUsedAt - right.lastUsedAt,
            )[0];
            if (!oldest) return;
            await this.disconnect(oldest.homeId);
        }
    }

    private async disconnect(homeId: HomeId): Promise<void> {
        const connection = this.connections.get(homeId);
        if (!connection) return;
        this.connections.delete(homeId);
        const auth = {
            bearer: this.bearer,
            homeAdmission: () => connection.admission,
        };
        await this.makeRouteJson(connection.endpoint, auth)(
            "DELETE",
            "/home/admissions",
        ).catch(() => undefined);
        await this.closeRoute(homeId).catch(() => undefined);
    }

    private publicConnection(
        connection: MutableHomeConnection<Api>,
    ): HomeConnection<Api> {
        return {
            homeId: connection.homeId,
            endpoint: connection.endpoint,
            api: connection.api,
            get state() {
                return connection.state;
            },
            get lastUsedAt() {
                return connection.lastUsedAt;
            },
        };
    }
}
