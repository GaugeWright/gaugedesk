import type { HomeId } from "./control-plane-domain";
import type { RouteJson } from "./control-plane-transport";

/** A tenant-owned computer that can run one or more Home nodes. It is not an
 * account device and carries no project content or admission credential. */
export interface TenantHost {
    readonly id: string;
    readonly displayName: string;
    readonly homeId: HomeId;
    readonly endpoint: string;
}

/** Operational evidence collected by the browser after ordinary Home admission.
 * This is intentionally never written to the Hub host directory. */
export interface TenantHostOverview extends TenantHost {
    readonly reachability: "online" | "offline" | "identity-mismatch";
    readonly projects: readonly { id: string; name: string }[];
}

function parse(value: unknown): TenantHost {
    const host = (value ?? {}) as Record<string, unknown>;
    if (
        typeof host.id !== "string" ||
        typeof host.display_name !== "string" ||
        typeof host.home_id !== "string" ||
        typeof host.endpoint !== "string"
    ) {
        throw new Error("registered computer response is malformed");
    }
    return {
        id: host.id,
        displayName: host.display_name,
        homeId: host.home_id as HomeId,
        endpoint: host.endpoint,
    };
}

export async function tenantHosts(json: RouteJson, tenant: string): Promise<TenantHost[]> {
    const body = (await json(
        "GET",
        `/account/tenants/${encodeURIComponent(tenant)}/hosts`,
    )) as { hosts?: unknown };
    if (!Array.isArray(body.hosts)) return [];
    return body.hosts.map(parse);
}
