import {
    accountTenants,
    browserRouteJson,
    parseOpaqueHomeRoutes,
    resolveHomeRoutes,
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

export interface LoadMobileHomeRoutesOptions {
    /** The signed-in account. It namespaces the root-key pin (ADR 0132 §5);
     * when empty, the subject the hub names for this session is used. */
    readonly subject?: string;
    /** Where the root-key pin lives. Without it the key is read fresh and used
     * from memory, so a relay-only Home is still reached; what is lost is
     * noticing a root that changed between launches (ADR 0133 §6). */
    readonly storage?: Pick<Storage, "getItem" | "setItem">;
    readonly fetchJson?: (url: string) => Promise<string | null>;
    readonly onDegraded?: (reason: string) => void;
    readonly onRootKeyConflict?: (error: Error) => void;
}

/**
 * Project→Home routes for the native app, across both channels (WS-746,
 * ADR 0133 §3 and §5).
 *
 * A serving Home publishes its routes, relay locators included, only into the
 * root-signed directory record; nothing writes a relay route into the hub's
 * table, and the table may not carry one anyway (ADR 0131). So mobile reads the
 * signed record exactly as the browser does — project, pin, verify — and takes
 * the hub's table at its true `unsigned` provenance for everything the record
 * does not cover. That retires the carve-out this function used to keep, which
 * read the hub table as `signed`: it honoured a pin anyone holding the person's
 * session could write, and it still never saw a relay-only Home, because no
 * such route ever arrived there.
 *
 * Every failure on the signed path — no verifier in this build, no projected
 * root, a directory outage, a record that does not verify — degrades to the
 * hub's endpoints rather than failing, which is what this read returned for a
 * directly addressable Home before.
 */
export async function loadMobileHomeRoutes(
    accountBase: string,
    bearer: () => string | null,
    options: LoadMobileHomeRoutesOptions = {},
): Promise<OpaqueHomeRoute[]> {
    const resolved = await resolveHomeRoutes({
        json: browserRouteJson(accountBase, { bearer }),
        subject: options.subject ?? "",
        ...(options.storage ? { storage: options.storage } : {}),
        ...(options.fetchJson ? { fetchJson: options.fetchJson } : {}),
        ...(options.onDegraded ? { onDegraded: options.onDegraded } : {}),
        ...(options.onRootKeyConflict ? { onRootKeyConflict: options.onRootKeyConflict } : {}),
    });
    return resolved.routes;
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
    // Native Hub account sessions are opaque. No client claim describes their
    // expiry; the Hub and each Home reject them when revoked or expired. Do
    // not erase one on startup merely because it is not a JWT.
    if (token.split(".").length !== 3) return false;
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
