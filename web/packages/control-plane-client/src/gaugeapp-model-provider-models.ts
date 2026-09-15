import { arrayOf, booleanValue, integerValue, invalidModel, nullable, objectValue, oneOf, shape, stringValue, type ModelReader } from "./gaugeapp-model-validation";

// Metadata only. Reject unknown fields here, including accidental credentials;
// errors name a schema location, never the unknown field or its value.
const closed = <T extends Record<string, ModelReader<unknown>>>(fields: T): ReturnType<typeof shape<T>> => {
    const read = shape(fields);
    return (value, path) => {
        const input = objectValue(value, path);
        if (Object.keys(input).some((key) => !Object.hasOwn(fields, key))) return invalidModel(path);
        return read(input, path);
    };
};
const identity: ModelReader<string> = (value, path) => {
    const result = stringValue(value, path);
    return result.trim() ? result : invalidModel(path);
};
const exact = (max: bigint): ModelReader<string> => (value, path) => {
    const result = stringValue(value, path);
    if (!/^(0|[1-9][0-9]*)$/.test(result) || result.length > 39 || BigInt(result) > max) return invalidModel(path);
    return result;
};
const u64 = exact(18446744073709551615n);
const u128 = exact(340282366920938463463374607431768211455n);
const currency: ModelReader<string> = (value, path) => {
    const result = stringValue(value, path);
    return /^[A-Z]{3}$/.test(result) ? result : invalidModel(path);
};
const unique = <T>(values: readonly T[], key: (value: T) => string, path: string): readonly T[] =>
    new Set(values.map(key)).size === values.length ? values : invalidModel(path);
const uniqueArray = <T>(read: ModelReader<T>, key: (value: T) => string): ModelReader<readonly T[]> =>
    (value, path) => unique(arrayOf(read)(value, path), key, path);
const execution = oneOf("private_broker", "public_direct");
const policy = closed({ models: uniqueArray(identity, (value) => value), execution_classes: uniqueArray(execution, (value) => value) });
const money = closed({ currency, micros: u64 });
const caps = closed({ tokens: nullable(u64), money: nullable(money) });
const readTotals = closed({ tokens: u128, money: uniqueArray(closed({ currency, micros: u128 }), (value) => value.currency), unknown_money: booleanValue });
const totals = (value: unknown, path: string) => {
    const result = readTotals(value, path);
    if (result.tokens !== "0" && !result.money.length && !result.unknown_money) return invalidModel(`${path}.unknown_money`);
    return result;
};
const usage = closed({ measured: totals, reserved: totals, accounted_at_bound: totals, unknown_outcomes: u64 });
const member = closed({ kind: oneOf("member"), id: identity });
const project = closed({ kind: oneOf("project"), authority: identity, id: identity });
const subject = (value: unknown, path: string) => {
    const input = objectValue(value, path);
    return input.kind === "member" ? member(input, path) : project(input, path);
};
const version = closed({ id: identity, phase: oneOf("awaiting_secret", "sealed", "verified", "activated", "failed", "cancelled", "expired"), material: oneOf("unobserved", "held", "erasure_pending", "erased"), expires_at: u64,
    verification: nullable(closed({ check: oneOf("model_catalog_read"), observed_at: u64 })) });
const endpoint: ModelReader<string> = (value, path) => {
    const result = identity(value, path);
    try {
        const parsed = new URL(result);
        if (parsed.protocol !== "https:" || !parsed.hostname || parsed.username || parsed.password || parsed.search || parsed.hash) return invalidModel(path);
    } catch { return invalidModel(path); }
    return result;
};
const connection = closed({ id: identity, name: identity, provider: identity, endpoint, authentication: oneOf("api_key", "organization_oauth"), status: oneOf("pending", "active", "suspended", "revoked", "erased"),
    current_version: nullable(identity), erasure_requested: booleanValue, overrun_pending: booleanValue, policy, versions: uniqueArray(version, (value) => value.id) });
const grant = closed({ id: identity, connection: identity, subject, revision: u64, status: oneOf("active", "suspended", "revoked"), policy,
    audiences: uniqueArray(oneOf("member", "external_participant", "service", "public_session"), (value) => value), caps, usage });
const binding = closed({ authority: identity, organization: identity, environment: identity });
const providerOption = closed({ provider: identity, endpoint, authentication: oneOf("api_key", "organization_oauth"), verification_check: nullable(oneOf("model_catalog_read")), policy });
const available = closed({ availability: oneOf("available"), binding, management_revision: u64, as_of: u64,
    period: closed({ year: u64, month: integerValue }), connections: uniqueArray(connection, (value) => value.id), grants: uniqueArray(grant, (value) => value.id),
    default_model: nullable(closed({ connection: identity, model: identity, available: booleanValue })),
    setup: closed({ api_key_intake: booleanValue, providers: arrayOf(providerOption) }) });
const unavailable = closed({ availability: oneOf("unavailable"), reason: oneOf("not_configured", "authority_unavailable") });

export function parseModelProvidersModel(value: unknown, path = "model") {
    const input = objectValue(value, path);
    if (input.availability === "unavailable") return unavailable(input, path);
    const model = available(input, path);
    if (model.as_of === "0" || BigInt(model.period.year) < 1970n || model.period.month < 1 || model.period.month > 12) return invalidModel(`${path}.period`);
    const connections = new Map(model.connections.map((row) => [row.id, row]));
    for (const row of model.connections) {
        for (const version of row.versions) {
            if (version.verification && (["awaiting_secret", "sealed"].includes(version.phase) || version.verification.observed_at === "0" || BigInt(version.verification.observed_at) > BigInt(model.as_of) || BigInt(version.verification.observed_at) >= BigInt(version.expires_at))) return invalidModel(`${path}.connections.versions.verification`);
        }
        const current = row.versions.find((version) => version.id === row.current_version);
        if (!row.versions.length || (row.current_version !== null && (!current || current.phase !== "activated"))) return invalidModel(`${path}.connections.current_version`);
        if (row.status === "pending" && row.current_version !== null) return invalidModel(`${path}.connections.status`);
        if ((row.status === "active" || row.status === "suspended") && (!current || current.material !== "held" || row.erasure_requested)) return invalidModel(`${path}.connections.status`);
        if (row.status === "erased" && (!row.erasure_requested || row.versions.some((version) => version.material !== "erased"))) return invalidModel(`${path}.connections.status`);
    }
    for (const row of model.grants) {
        if (!connections.has(row.connection) || row.revision === "0" || !row.policy.models.length || !row.policy.execution_classes.length || !row.audiences.length) return invalidModel(`${path}.grants`);
        if (row.subject.kind === "member" && (row.audiences.length !== 1 || row.audiences[0] !== "member" || row.policy.execution_classes.includes("public_direct"))) return invalidModel(`${path}.grants.subject`);
        if (row.usage.accounted_at_bound.tokens !== "0" && row.usage.unknown_outcomes === "0") return invalidModel(`${path}.grants.usage.unknown_outcomes`);
    }
    if (model.default_model) {
        const row = connections.get(model.default_model.connection);
        if (!row) return invalidModel(`${path}.default_model.connection`);
        const ready = row.status === "active" && !row.erasure_requested && row.policy.models.includes(model.default_model.model) && row.policy.execution_classes.length > 0;
        if (model.default_model.available !== ready) return invalidModel(`${path}.default_model.available`);
    }
    return model;
}
export type ModelProvidersModel = ReturnType<typeof parseModelProvidersModel>;

export function modelProvidersUnavailableReason(reason: "not_configured" | "authority_unavailable"): string {
    return reason === "not_configured"
        ? "This GaugeDesk service has no organization credential store configured."
        : "The organization credential service is unavailable. Try again when it reconnects.";
}
