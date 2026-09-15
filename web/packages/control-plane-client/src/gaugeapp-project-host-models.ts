import { arrayOf, booleanValue, integerValue, invalidModel, nullable, objectValue, oneOf, shape, stringValue, type ModelReader } from "./gaugeapp-model-validation";

const identity: ModelReader<string> = (value, path) => {
    const text = stringValue(value, path);
    return text.trim() ? text : invalidModel(path);
};
const capacity = shape({ storage_bytes: integerValue, concurrent_agents: integerValue });
const policy = shape({ version: integerValue, tenant_id: stringValue, isolated_workspace_enabled: booleanValue, max_attempt_nanos_usd: integerValue });
const common = shape({
    id: identity, home_id: identity, name: identity, endpoint: stringValue,
    kind: oneOf("local", "registered", "cloud"),
    lifecycle: oneOf("provisioning", "active", "suspended", "retention", "deleted", "revoked"),
    state: oneOf("live", "indeterminate", "unreachable"), repair_hint: nullable(stringValue),
    projects: nullable(arrayOf(shape({ id: identity, name: stringValue }))),
});
const profile = shape({ available: booleanValue, reason: nullable(stringValue) });
const execution = shape({
    freshness: identity,
    profiles: shape({ durable_workflow: profile, isolated_workspace: shape({
        available: booleanValue, reason: nullable(stringValue), enabled_by_tenant_policy: booleanValue,
        metering: shape({ kind: oneOf("usage"), reservation_nanos_usd: nullable(integerValue), nanos_usd_per_second: nullable(integerValue) }),
    }) }),
    queue: nullable(shape({ total: integerValue })),
    compute: shape({ state: identity, active_attempts: nullable(integerValue) }),
    usage: nullable(shape({ billable_nanos_usd: integerValue, charged_nanos_usd: integerValue, wall_millis: integerValue })),
});
const managed = shape({ region: nullable(identity), capacity, retention_until: nullable(integerValue), managed_policy: policy, execution });
export function parseProjectHost(value: unknown, path: string) {
    const host = common(value, path);
    switch (host.kind) {
        case "local": return { ...host, kind: host.kind };
        case "registered": return { ...host, kind: host.kind };
        case "cloud": {
            const details = managed(value, path);
            if (details.managed_policy.version !== 1) return invalidModel(`${path}.managed_policy.version`);
            if (details.execution.freshness !== "home-admitted" && (details.execution.usage !== null || details.execution.queue !== null || details.execution.compute.active_attempts !== null))
                return invalidModel(`${path}.execution`);
            return { ...host, kind: host.kind, ...details };
        }
    }
}
export type ProjectHost = ReturnType<typeof parseProjectHost>;

const enrollment = shape({ available: booleanValue, reason: nullable(stringValue), region: nullable(identity), capacity: nullable(capacity) });
export function parseProjectHostsModel(value: unknown, path = "model") {
    const source = objectValue(value, path);
    const homes = arrayOf(parseProjectHost)(source.homes, `${path}.homes`);
    const managed_enrollment = enrollment(source.managed_enrollment, `${path}.managed_enrollment`);
    if (new Set(homes.map((host) => host.id)).size !== homes.length) return invalidModel(`${path}.homes`);
    if (managed_enrollment.available && (!managed_enrollment.region || !managed_enrollment.capacity || managed_enrollment.reason !== null))
        return invalidModel(`${path}.managed_enrollment`);
    if (!managed_enrollment.available && !managed_enrollment.reason?.trim()) return invalidModel(`${path}.managed_enrollment.reason`);
    return { homes, managed_enrollment };
}
export type ProjectHostsModel = ReturnType<typeof parseProjectHostsModel>;
