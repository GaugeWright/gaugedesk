import type { RouteJson } from "./control-plane-transport";
import { gaugeAppRoutes } from "./gaugeapp";
import { parseModelProvidersModel } from "./gaugeapp-model-provider-models";

export interface OrganizationProviderCandidate {
    readonly binding: { readonly authority: string; readonly organization: string; readonly environment: string };
    readonly connection: string;
    readonly version: string;
}
const record = (value: unknown): Record<string, unknown> => {
    if (!value || typeof value !== "object" || Array.isArray(value)) throw Error("The credential service returned an incompatible response.");
    return value as Record<string, unknown>;
};
const only = (value: Record<string, unknown>, fields: readonly string[]) => {
    if (Object.keys(value).length !== fields.length || Object.keys(value).some((key) => !fields.includes(key))) throw Error("The credential service returned an incompatible response.");
};

/** A transient ceremony, not a GaugeApp command. Only identifiers cross Hub.
 * Raw bytes go straight to the issuer with the short-lived ticket, without the
 * account bearer, cookies, redirects, caches or local persistence. */
export async function submitOrganizationProviderSecret(
    json: RouteJson,
    candidate: OrganizationProviderCandidate,
    secret: string,
    options: { readonly signal: AbortSignal; readonly fetcher?: typeof fetch },
) {
    const bytes = new TextEncoder().encode(secret);
    try {
        if (!bytes.length || bytes.length > 65536) throw Error("Enter an API key of at most 64 KiB.");
        options.signal.throwIfAborted();
        const route = gaugeAppRoutes.administration.providerIntake;
        const ticket = record(await json(route.method, route.path, {
            organization: candidate.binding.organization, connection: candidate.connection, version: candidate.version,
        }));
        only(ticket, ["v", "upload_url", "ticket", "expires_at"]);
        if (ticket.v !== 1 || typeof ticket.upload_url !== "string" || typeof ticket.ticket !== "string"
            || ticket.ticket.length > 8192 || !/^[0-9a-f]+\.[0-9a-f]{64}$/.test(ticket.ticket)
            || typeof ticket.expires_at !== "number" || !Number.isSafeInteger(ticket.expires_at) || ticket.expires_at <= 0) {
            throw Error("The credential service returned an incompatible upload ticket.");
        }
        const url = new URL(ticket.upload_url);
        const loopback = url.hostname === "127.0.0.1" || url.hostname === "[::1]";
        const upload = gaugeAppRoutes.administration.providerCredential;
        if ((url.protocol !== "https:" && !(url.protocol === "http:" && loopback))
            || url.username || url.password || url.search || url.hash || url.pathname !== upload.path) {
            throw Error("The credential service returned an unsafe upload destination.");
        }
        options.signal.throwIfAborted();
        const response = await (options.fetcher ?? fetch)(url.toString(), {
            method: upload.method, headers: { "Content-Type": "application/octet-stream", Authorization: `Bearer ${ticket.ticket}` },
            body: bytes, credentials: "omit", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer", signal: options.signal,
        });
        if (!response.ok) {
            // Never echo an arbitrary body from a credential-bearing request.
            throw Error(response.status === 401 ? "The upload expired. Try again."
                : response.status === 403 ? "You no longer have permission to manage this connection."
                    : response.status === 409 ? "The candidate changed or already contains a different key. Refresh before continuing."
                        : "The key could not be uploaded. Check the connection and try again.");
        }
        let responseValue: unknown;
        try { responseValue = await response.json(); }
        catch { throw Error("The credential service returned an incompatible response."); }
        const result = record(responseValue);
        only(result, ["v", "binding", "page"]);
        const binding = record(result.binding);
        only(binding, ["authority", "organization", "environment"]);
        if (result.v !== 1 || Object.entries(candidate.binding).some(([key, value]) => binding[key] !== value)) {
            throw Error("The upload returned a different organization binding.");
        }
        const model = parseModelProvidersModel(result.page);
        if (model.availability !== "available" || Object.entries(candidate.binding).some(([key, value]) => model.binding[key as keyof typeof model.binding] !== value)) {
            throw Error("The upload returned a different organization binding.");
        }
        return model;
    } finally { bytes.fill(0); }
}

/** Ask the credential authority to perform its advertised candidate check.
 * This request contains identifiers only and returns only the refreshed page. */
export async function verifyOrganizationProviderCandidate(
    json: RouteJson,
    candidate: OrganizationProviderCandidate,
) {
    const route = gaugeAppRoutes.administration.providerVerify;
    const result = record(await json(route.method, route.path, {
        organization: candidate.binding.organization, connection: candidate.connection, version: candidate.version,
    }));
    only(result, ["v", "binding", "page"]);
    const binding = record(result.binding);
    only(binding, ["authority", "organization", "environment"]);
    if (result.v !== 1 || Object.entries(candidate.binding).some(([key, value]) => binding[key] !== value)) {
        throw Error("Verification returned a different organization binding.");
    }
    const model = parseModelProvidersModel(result.page);
    if (model.availability !== "available" || Object.entries(candidate.binding).some(([key, value]) => model.binding[key as keyof typeof model.binding] !== value)) {
        throw Error("Verification returned a different organization binding.");
    }
    return model;
}
