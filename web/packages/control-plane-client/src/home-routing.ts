import type { HomeId, ProjectId } from "./control-plane-domain";
import { isSecureControlPlaneEndpoint } from "./control-plane-transport";
import { RemoteControlPlane, type RemoteControlPlaneOptions } from "./remote-control-plane";

/** The complete work-blind directory payload for one project. Names, grants,
 * content, logs, and runtime facts are deliberately absent. */
export interface OpaqueHomeRoute {
    readonly project: ProjectId;
    readonly homeId: HomeId;
    /** Empty only for a native relay-only Machine. */
    readonly endpoint: string;
    readonly relay?: OpaqueRelayLocator | null;
}

/** Non-authoritative transport locator (ADR 0116/0118). The opaque handle
 * selects one relay object and the rotatable proof permits a tunnel attempt;
 * Home admission remains separate. */
export interface OpaqueRelayLocator {
    readonly endpoint: string;
    readonly handle: string;
    readonly proof: string;
    readonly routeEpoch: number;
    readonly homeFingerprint: string;
}

function requiredString(value: unknown, field: string): string {
    if (typeof value !== "string" || !value.trim()) {
        throw new Error(`opaque Home route requires ${field}`);
    }
    return value;
}

export function parseOpaqueHomeRoute(raw: unknown): OpaqueHomeRoute {
    const route = (raw ?? {}) as Record<string, unknown>;
    const project = requiredString(route.project, "project");
    const homeId = requiredString(route.home_id, "home_id");
    const endpoint =
        typeof route.endpoint === "string" && route.endpoint.trim()
            ? route.endpoint.replace(/\/+$/, "")
            : "";
    if (endpoint && !isSecureControlPlaneEndpoint(endpoint)) {
        throw new Error(`refusing insecure Home endpoint for project ${project}`);
    }
    const relay = parseRelayLocator(route.relay);
    if (!endpoint && relay === null) {
        throw new Error(`opaque Home route requires endpoint or relay for project ${project}`);
    }
    return {
        project: project as ProjectId,
        homeId: homeId as HomeId,
        endpoint,
        ...(relay ? { relay } : {}),
    };
}

function parseRelayLocator(raw: unknown): OpaqueRelayLocator | null {
    if (raw === undefined || raw === null) return null;
    const relay = raw as Record<string, unknown>;
    const endpoint = requiredString(relay.endpoint, "relay.endpoint");
    const handle = requiredString(relay.handle, "relay.handle");
    const proof = requiredString(relay.proof, "relay.proof");
    const homeFingerprint = requiredString(
        relay.home_fingerprint,
        "relay.home_fingerprint",
    ).toLowerCase();
    const routeEpoch = relay.route_epoch;
    if (
        !/^wss:\/\/[A-Za-z0-9.-]+(?::[1-9][0-9]{0,4})?$/.test(endpoint)
        || !/^[A-Za-z0-9_-]{43}$/.test(handle)
        || !/^[A-Za-z0-9_-]{43}$/.test(proof)
        || !Number.isSafeInteger(routeEpoch)
        || (routeEpoch as number) <= 0
        || !/^[0-9a-f]{64}$/.test(homeFingerprint)
    ) {
        throw new Error("opaque Home route contains an invalid relay locator");
    }
    return {
        endpoint,
        handle,
        proof,
        routeEpoch: routeEpoch as number,
        homeFingerprint,
    };
}

export function opaqueHomeRouteKey(route: OpaqueHomeRoute): string {
    const relay = route.relay
        ? `${route.relay.endpoint}\n${route.relay.handle}\n${route.relay.proof}\n${route.relay.routeEpoch}\n${route.relay.homeFingerprint}`
        : "direct";
    return `${route.homeId}\n${route.endpoint}\n${relay}`;
}

export function parseOpaqueHomeRoutes(raw: unknown): OpaqueHomeRoute[] {
    const body = (raw ?? {}) as { routes?: unknown };
    if (!Array.isArray(body.routes)) throw new Error("Home directory response requires routes");
    return body.routes.map(parseOpaqueHomeRoute);
}

export interface HomeRouteDirectoryOptions {
    readonly bearer?: RemoteControlPlaneOptions["bearer"];
    /** Test/alternate-host injection. */
    readonly controlPlane?: (route: OpaqueHomeRoute) => RemoteControlPlane;
}

/** Exact project→Home resolver. Connecting performs target admission and checks
 * the target's stable identity before exposing its ControlPlane. */
export class HomeRouteDirectory {
    private readonly routes = new Map<ProjectId, OpaqueHomeRoute>();
    private readonly connected = new Map<string, Promise<RemoteControlPlane>>();
    private readonly makeControlPlane: (route: OpaqueHomeRoute) => RemoteControlPlane;

    constructor(routes: readonly OpaqueHomeRoute[], options: HomeRouteDirectoryOptions = {}) {
        for (const route of routes) {
            const prior = this.routes.get(route.project);
            if (
                prior &&
                opaqueHomeRouteKey(prior) !== opaqueHomeRouteKey(route)
            ) {
                throw new Error(`conflicting Home routes for project ${route.project}`);
            }
            this.routes.set(route.project, route);
        }
        this.makeControlPlane =
            options.controlPlane ??
            ((route) => {
                if (!route.endpoint) {
                    throw new Error(
                        `Home ${route.homeId} is relay-only and requires a native relay adapter`,
                    );
                }
                return new RemoteControlPlane(route.endpoint, { bearer: options.bearer });
            });
    }

    routeFor(project: ProjectId): OpaqueHomeRoute {
        const route = this.routes.get(project);
        if (!route) throw new Error(`no granted Home route for project ${project}`);
        return route;
    }

    async connectProject(
        project: ProjectId,
        expectedHome?: HomeId,
    ): Promise<RemoteControlPlane> {
        const route = this.routeFor(project);
        if (expectedHome && route.homeId !== expectedHome) {
            throw new Error(`project ${project} is not routed to Home ${expectedHome}`);
        }
        const key = opaqueHomeRouteKey(route);
        let connection = this.connected.get(key);
        if (!connection) {
            connection = this.connect(route);
            this.connected.set(key, connection);
        }
        try {
            return await connection;
        } catch (error) {
            this.connected.delete(key);
            throw error;
        }
    }

    private async connect(route: OpaqueHomeRoute): Promise<RemoteControlPlane> {
        const controlPlane = this.makeControlPlane(route);
        const admittedHome = await controlPlane.admitHome();
        if (admittedHome !== route.homeId) {
            await controlPlane.revokeHomeAdmission().catch(() => {});
            throw new Error(
                `Home identity mismatch for project ${route.project}: expected ${route.homeId}`,
            );
        }
        return controlPlane;
    }
}
