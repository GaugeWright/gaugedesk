import {
    accountHomeRoutes,
    accountTenants,
    browserRouteJson,
    opaqueHomeRouteKey,
    parseOpaqueHomeRoutes,
    type HomeId,
    type AccountTenant,
    type OpaqueHomeRoute,
    type ProjectId,
    type RouteJson,
} from "@gaugewright/control-plane-client";
import { MobileControlPlane } from "./mobile-control-plane";

export type MobileHomeConnectionState =
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

export interface MobileHomeConnection {
    readonly homeId: HomeId;
    readonly endpoint: string;
    readonly api: MobileControlPlane;
    readonly state: MobileHomeConnectionState;
    readonly lastUsedAt: number;
}

interface MutableHomeConnection {
    readonly homeId: HomeId;
    readonly endpoint: string;
    readonly routeKey: string;
    readonly admission: string;
    readonly api: MobileControlPlane;
    state: MobileHomeConnectionState;
    lastUsedAt: number;
}

export interface MobileHomePoolOptions {
    readonly maxConnections?: number;
    readonly idleMs?: number;
    readonly now?: () => number;
    readonly onStateChange?: (
        homeId: HomeId,
        state: MobileHomeConnectionState,
    ) => void;
    readonly routeJson?: (
        endpoint: string,
        auth: {
            readonly bearer: () => string | null;
            readonly homeAdmission: () => string | null;
        },
    ) => RouteJson;
    readonly resolveEndpoint?: (route: OpaqueHomeRoute) => Promise<string>;
    readonly closeRoute?: (homeId: HomeId) => Promise<void>;
}

/**
 * Bounded exact-Home connection registry for the signed-in mobile client.
 * Hub pointers can select an endpoint but never become authority: every new
 * entry performs target admission and pins the announced Home identity.
 */
export class MobileHomePool {
    private routes = new Map<ProjectId, OpaqueHomeRoute>();
    private readonly connections = new Map<HomeId, MutableHomeConnection>();
    private readonly pending = new Map<HomeId, Promise<MutableHomeConnection>>();
    private readonly maxConnections: number;
    private readonly idleMs: number;
    private readonly now: () => number;
    private readonly makeRouteJson: NonNullable<MobileHomePoolOptions["routeJson"]>;
    private readonly resolveEndpoint: NonNullable<MobileHomePoolOptions["resolveEndpoint"]>;
    private readonly closeRoute: NonNullable<MobileHomePoolOptions["closeRoute"]>;
    private readonly onStateChange: NonNullable<MobileHomePoolOptions["onStateChange"]>;

    constructor(
        routes: readonly OpaqueHomeRoute[],
        private readonly bearer: () => string | null,
        options: MobileHomePoolOptions = {},
    ) {
        this.maxConnections = Math.max(1, options.maxConnections ?? 3);
        this.idleMs = Math.max(1, options.idleMs ?? 5 * 60_000);
        this.now = options.now ?? Date.now;
        this.onStateChange = options.onStateChange ?? (() => undefined);
        this.makeRouteJson =
            options.routeJson
            ?? ((endpoint, auth) => browserRouteJson(endpoint, auth));
        this.resolveEndpoint = options.resolveEndpoint ?? (async (route) => route.endpoint);
        this.closeRoute = options.closeRoute ?? (async () => undefined);
        this.replaceRoutes(routes);
    }

    replaceRoutes(routes: readonly OpaqueHomeRoute[]): void {
        const next = new Map<ProjectId, OpaqueHomeRoute>();
        for (const route of routes) {
            const prior = next.get(route.project);
            if (
                prior
                && opaqueHomeRouteKey(prior) !== opaqueHomeRouteKey(route)
            ) {
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

    routeFor(project: ProjectId): OpaqueHomeRoute {
        const route = this.routes.get(project);
        if (!route) throw new Error(`no granted Home route for project ${project}`);
        return route;
    }

    snapshot(): MobileHomeConnection[] {
        return [...this.connections.values()]
            .map(({ admission: _admission, ...connection }) => connection)
            .sort((left, right) => left.homeId.localeCompare(right.homeId));
    }

    async connectProject(project: ProjectId): Promise<MobileHomeConnection> {
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

    mark(project: ProjectId, state: MobileHomeConnectionState): void {
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

    private async admit(route: OpaqueHomeRoute): Promise<MutableHomeConnection> {
        if (!this.bearer()) throw new Error("sign in before opening a project");
        let admission: string | null = null;
        const auth = {
            bearer: this.bearer,
            homeAdmission: () => admission,
        };
        const routeKey = opaqueHomeRouteKey(route);
        const endpoint = await this.resolveEndpoint(route);
        const json = this.makeRouteJson(endpoint, auth);
        const result = await json("POST", "/home/admissions") as {
            home?: unknown;
            admission?: unknown;
        };
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
        let connection: MutableHomeConnection;
        const api = new MobileControlPlane(endpoint, {
            routeJson: json,
            bearer: this.bearer,
            homeAdmission: () => admission,
            onAuthorizationRejected: (status, detail) => {
                connection.state =
                    status === 421
                        ? "stale"
                        : status === 401
                            ? (/target Home admission required/i.test(detail)
                                ? "needs-admission"
                                : "needs-sign-in")
                            : /Home admission/i.test(detail)
                                ? "needs-admission"
                                : "policy-denied";
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
            const oldest = [...this.connections.values()]
                .sort((left, right) => left.lastUsedAt - right.lastUsedAt)[0];
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
        connection: MutableHomeConnection,
    ): MobileHomeConnection {
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

export async function loadMobileHomeRoutes(
    accountBase: string,
    bearer: () => string | null,
): Promise<OpaqueHomeRoute[]> {
    const json = browserRouteJson(accountBase, { bearer });
    // Keep parsing at the shared transport boundary even though
    // accountHomeRoutes already returns the branded shape.
    const routes = await accountHomeRoutes(json);
    return parseOpaqueHomeRoutes({
        routes: routes.map((route) => ({
            project: route.project,
            home_id: route.homeId,
            endpoint: route.endpoint,
            relay: route.relay
                ? {
                    endpoint: route.relay.endpoint,
                    handle: route.relay.handle,
                    proof: route.relay.proof,
                    route_epoch: route.relay.routeEpoch,
                    home_fingerprint: route.relay.homeFingerprint,
                }
                : undefined,
        })),
    });
}

export async function loadMobileMemberships(
    accountBase: string,
    bearer: () => string | null,
): Promise<AccountTenant[]> {
    return accountTenants(browserRouteJson(accountBase, { bearer }));
}

export function accountTokenExpiresWithin(
    token: string,
    windowSeconds: number,
    nowSeconds = Date.now() / 1_000,
): boolean {
    try {
        const payload = token.split(".")[1];
        if (!payload) return true;
        const normalized = payload.replace(/-/g, "+").replace(/_/g, "/");
        const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
        const claims = JSON.parse(atob(padded)) as { exp?: unknown };
        return typeof claims.exp !== "number"
            || claims.exp <= nowSeconds + windowSeconds;
    } catch {
        return true;
    }
}

interface StoredRouteDirectory {
    readonly version: 1;
    readonly owners: Record<string, {
        readonly routes: readonly {
            readonly project: string;
            readonly home_id: string;
            readonly endpoint: string;
        }[];
        readonly updatedAt: number;
    }>;
}

/** Persist only Hub's secret-free opaque route directory, partitioned by the
 * authenticated account identity. Project labels and Home admissions never
 * enter this cache. */
export class MobileRouteCache {
    constructor(
        private readonly owner: string,
        private readonly storage: Pick<Storage, "getItem" | "setItem"> | null,
        private readonly key = "gw.mobile.route-directory.v1",
    ) {}

    load(): OpaqueHomeRoute[] {
        if (!this.storage) return [];
        try {
            const decoded = JSON.parse(this.storage.getItem(this.key) ?? "") as StoredRouteDirectory;
            const entry = decoded.version === 1 ? decoded.owners[this.owner] : undefined;
            return entry ? parseOpaqueHomeRoutes({ routes: entry.routes }) : [];
        } catch {
            return [];
        }
    }

    save(routes: readonly OpaqueHomeRoute[], updatedAt = Date.now()): void {
        if (!this.storage) return;
        try {
            let owners: StoredRouteDirectory["owners"] = {};
            const prior = this.storage.getItem(this.key);
            if (prior) {
                const decoded = JSON.parse(prior) as StoredRouteDirectory;
                if (decoded.version === 1 && decoded.owners) owners = decoded.owners;
            }
            owners = {
                ...owners,
                [this.owner]: {
                    routes: routes.map((route) => ({
                        project: route.project,
                        home_id: route.homeId,
                        endpoint: route.endpoint,
                    })),
                    updatedAt,
                },
            };
            this.storage.setItem(this.key, JSON.stringify({ version: 1, owners }));
        } catch {
            // Routing can always be rediscovered after sign-in.
        }
    }

    clear(): void {
        if (!this.storage) return;
        try {
            const decoded = JSON.parse(
                this.storage.getItem(this.key) ?? "",
            ) as StoredRouteDirectory;
            if (decoded.version !== 1 || !decoded.owners) return;
            const owners = { ...decoded.owners };
            delete owners[this.owner];
            this.storage.setItem(this.key, JSON.stringify({ version: 1, owners }));
        } catch {
            // Missing/corrupt routing storage is already effectively cleared.
        }
    }
}
