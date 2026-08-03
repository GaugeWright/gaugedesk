import type { HomeId } from "./control-plane-domain";
import type { RouteJson } from "./control-plane-transport";

export type CloudHomeLifecycle =
    | "provisioning"
    | "active"
    | "suspended"
    | "retention"
    | "deleted";

export interface CloudHomeProjection {
    readonly tenant: string;
    readonly homeId: HomeId;
    readonly endpoint: string;
    readonly region: string;
    readonly status: CloudHomeLifecycle;
    readonly subscription: string;
    readonly retentionUntil: number | null;
    readonly storageBytes: number;
    readonly storageLimitBytes: number;
    readonly concurrentAgentLimit: number;
    readonly compute: "scale_to_zero";
}

function parse(tenant: string, raw: unknown): CloudHomeProjection {
    const body = (raw ?? {}) as Record<string, any>;
    const facility = (body.facility ?? {}) as Record<string, any>;
    const config = (facility.config ?? {}) as Record<string, any>;
    const usage = (body.usage ?? {}) as Record<string, any>;
    if (
        typeof config.home_id !== "string" ||
        typeof config.endpoint !== "string" ||
        typeof config.region !== "string" ||
        !["provisioning", "active", "suspended", "retention", "deleted"].includes(
            String(facility.status),
        )
    ) {
        throw new Error("Cloud Home response is malformed");
    }
    return {
        tenant,
        homeId: config.home_id as HomeId,
        endpoint: config.endpoint,
        region: config.region,
        status: facility.status as CloudHomeLifecycle,
        subscription: typeof config.subscription === "string" ? config.subscription : "unknown",
        retentionUntil: typeof config.retention_until === "number" ? config.retention_until : null,
        storageBytes: typeof usage.storage_bytes === "number" ? usage.storage_bytes : 0,
        storageLimitBytes:
            typeof usage.storage_limit_bytes === "number" ? usage.storage_limit_bytes : 0,
        concurrentAgentLimit:
            typeof usage.concurrent_agent_limit === "number" ? usage.concurrent_agent_limit : 0,
        compute: "scale_to_zero",
    };
}

export async function getCloudHome(json: RouteJson, tenant: string): Promise<CloudHomeProjection> {
    return parse(
        tenant,
        await json("GET", `/account/tenants/${encodeURIComponent(tenant)}/cloud-home`),
    );
}
