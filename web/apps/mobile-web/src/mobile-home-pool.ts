import {
    accountHomeRoutes,
    accountTenants,
    browserRouteJson,
    parseOpaqueHomeRoutes,
    HomePool,
    type AccountTenant,
    type HomeConnection,
    type HomeConnectionState,
    type HomePoolOptions,
    type OpaqueHomeRoute,
} from "@gaugewright/control-plane-client";
import { MobileControlPlane } from "./mobile-control-plane";

/**
 * Mobile's binding of the shared multi-Home pool (DESK-3). The pool itself —
 * routing, admission, identity verification, bounded eviction, per-Home state —
 * lives in `control-plane-client` and is used unchanged by every project-first
 * client. All that is mobile-specific is which client wraps each Home.
 */
export type MobileHomeConnectionState = HomeConnectionState;
export type MobileHomeConnection = HomeConnection<MobileControlPlane>;
export type MobileHomePoolOptions = Omit<HomePoolOptions<MobileControlPlane>, "client">;

export class MobileHomePool extends HomePool<MobileControlPlane> {
    constructor(
        routes: readonly OpaqueHomeRoute[],
        bearer: () => string | null,
        options: MobileHomePoolOptions = {},
    ) {
        super(routes, bearer, {
            ...options,
            client: (context) =>
                new MobileControlPlane(context.endpoint, {
                    routeJson: context.routeJson,
                    bearer: context.bearer,
                    homeAdmission: context.homeAdmission,
                    onAuthorizationRejected: context.onAuthorizationRejected,
                    onTransportUnavailable: context.onTransportUnavailable,
                }),
        });
    }
}

export async function loadMobileHomeRoutes(
    accountBase: string,
    bearer: () => string | null,
): Promise<OpaqueHomeRoute[]> {
    const json = browserRouteJson(accountBase, { bearer });
    // Keep parsing at the shared transport boundary even though
    // accountHomeRoutes already returns the branded shape.
    // The carve-out ADR 0133 §5 sequences: mobile does not read the signed
    // record yet, so declaring the truth here would strip every relay locator
    // and take its relay-only Machines offline. Removing it is this client's
    // half of DESK-5g, not a default to flip.
    const routes = await accountHomeRoutes(json, "signed");
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
    // Same provenance the hub read already used: re-parsing at a lower trust
    // would silently drop every relay locator and take relay-only Homes offline.
    }, "signed");
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
