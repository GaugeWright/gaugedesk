import { booleanValue, integerValue, nullable, oneOf, shape, stringValue, type ModelReader } from "./gaugeapp-model-validation";
import { RemoteControlPlane } from "./remote-control-plane";

/**
 * A managed Home's own Isolated workspace policy (GaugeWright DR-0194).
 *
 * The policy an Isolated turn enforces lives in the tenant's Home, and only the
 * organization's owner sets it there, so it is read and written on the Home with
 * the owner's ordinary Home admission rather than through the Hub, whose copy
 * of a managed host's policy is not the one its turns enforce.
 */
const policy = shape({
    version: integerValue,
    tenant_id: stringValue,
    isolated_workspace_enabled: booleanValue,
    max_attempt_nanos_usd: integerValue,
});
const metering = shape({
    kind: oneOf("usage"),
    reservation_nanos_usd: nullable(integerValue),
    nanos_usd_per_second: nullable(integerValue),
});
/** The Home's own prices, which a Home that predates them does not report. */
const pricing: ModelReader<{ readonly reservation_nanos_usd: number | null; readonly nanos_usd_per_second: number | null } | null> =
    (value, path) => value === undefined || value === null ? null : shape({
        reservation_nanos_usd: nullable(integerValue),
        nanos_usd_per_second: nullable(integerValue),
    })(value, path);
const reading = shape({
    policy,
    isolated_workspace: shape({
        available: booleanValue,
        enabled_by_tenant_policy: booleanValue,
        reason: nullable(stringValue),
        metering,
    }),
    pricing,
    can_edit: booleanValue,
});

export type HomeExecutionPolicy = ReturnType<typeof reading>;

export function parseHomeExecutionPolicy(value: unknown): HomeExecutionPolicy {
    return reading(value, "home_execution_policy");
}

/** What the owner asks for. Disabling ignores the limit. */
export interface HomeExecutionPolicyChange {
    readonly isolated_workspace_enabled: boolean;
    readonly max_attempt_nanos_usd: number;
}

/** The two facts of a Project Host this needs: which Home, and where it is. */
export interface HomeExecutionPolicyHost {
    readonly home_id: string;
    readonly endpoint: string;
}

export interface HomeExecutionPolicyClient {
    read(host: HomeExecutionPolicyHost): Promise<HomeExecutionPolicy>;
    /** `idempotencyKey` is the caller's: kept for a retry of the same change,
     *  so the Home replays it rather than recording it twice. */
    set(host: HomeExecutionPolicyHost, change: HomeExecutionPolicyChange, idempotencyKey: string): Promise<HomeExecutionPolicy>;
}

export interface HomeExecutionPolicyClientOptions {
    readonly bearer: () => string | null;
    /** Test injection: the Home a host's endpoint is reached through. */
    readonly home?: (endpoint: string) => Pick<RemoteControlPlane, "admitHome" | "revokeHomeAdmission" | "homeExecutionPolicy" | "setHomeExecutionPolicy">;
}

/** Each call admits the host's Home, refuses one that answers as a different
 *  Home, and gives the admission back whatever happens. */
export function homeExecutionPolicyClient(options: HomeExecutionPolicyClientOptions): HomeExecutionPolicyClient {
    const open = options.home ?? ((endpoint: string) => new RemoteControlPlane(endpoint, { bearer: options.bearer }));
    const withHome = async <T>(
        host: HomeExecutionPolicyHost,
        work: (home: ReturnType<typeof open>) => Promise<T>,
    ): Promise<T> => {
        const home = open(host.endpoint);
        try {
            if (await home.admitHome() !== host.home_id) {
                throw new Error("This Project Host no longer identifies as its registered Home.");
            }
            return await work(home);
        } finally {
            await home.revokeHomeAdmission().catch(() => {});
        }
    };
    return {
        read: (host) => withHome(host, async (home) => parseHomeExecutionPolicy(await home.homeExecutionPolicy())),
        set: (host, change, idempotencyKey) => withHome(host, async (home) =>
            parseHomeExecutionPolicy(await home.setHomeExecutionPolicy(change, idempotencyKey))),
    };
}
