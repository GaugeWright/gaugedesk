import type { RouteJson } from "./control-plane-transport";
import type { RouteEventStream } from "./browser-route-json";
import type { AccountDeviceLink, AccountGaugeAppPageId } from "./gaugeapp-account-models";
import { parseGaugeAppPage, type AccountGaugeAppPage, type AdministrationGaugeAppPage, type AdministrationGaugeAppPageId, type CommercialGaugeAppPage, type ProjectHostsPage, type ModelProvidersPage } from "./gaugeapp-page-models";
import type { CommercialGaugeAppPageId } from "./gaugeapp-commercial-models";
import { arrayOf, booleanValue, integerValue, invalidModel, objectValue, oneOf, shape, stringValue, type ModelReader } from "./gaugeapp-model-validation";
export type { AccountDeviceLink, ProviderConnectionModel, ProviderConnectionsPageModel } from "./gaugeapp-account-models";

export type GaugeAppKind = "account-settings" | "administration" | "commercial-operations";
export type GaugeAppClient = "desktop" | "web" | "agent";
export interface GaugeAppScope {
    readonly kind: "person" | "tenant" | "provider-tenant";
    readonly id: string;
}
export interface GaugeAppPageGrant {
    readonly id: string;
    readonly read_model: string;
    readonly version: number;
    readonly resource_basis: string;
    readonly freshness: string;
    readonly availability: "available" | "unavailable";
    readonly commands: readonly string[];
}
export interface GaugeAppCommandGrant {
    readonly id: string;
    readonly capability: string;
    readonly review: "immediate" | "human";
}
export interface GaugeAppSession {
    readonly id: string;
    readonly generation: string;
    readonly app: GaugeAppKind;
    readonly scope: GaugeAppScope;
    readonly actor: string;
    readonly capabilities: readonly string[];
    readonly pages: readonly GaugeAppPageGrant[];
    readonly commands: readonly GaugeAppCommandGrant[];
    readonly update_cursor: string;
}
export interface GaugeAppPageModel<TModel = unknown> {
    readonly app: GaugeAppKind;
    readonly scope: GaugeAppScope;
    readonly id: string;
    readonly read_model: string;
    readonly version: number;
    readonly resource_basis: string;
    readonly freshness: string;
    readonly model: TModel;
}
export interface GaugeAppCommandEnvelope<TPayload = unknown> {
    readonly session_id: string;
    readonly generation: string;
    readonly app: GaugeAppKind;
    readonly scope: GaugeAppScope;
    readonly page_id: string;
    readonly command_id: string;
    readonly expected_basis: string;
    readonly idempotency_key: string;
    readonly payload: TPayload;
    readonly client: GaugeAppClient;
}
export interface GaugeAppReceipt {
    readonly id: string;
    readonly session_id: string;
    readonly generation: string;
    readonly app: GaugeAppKind;
    readonly scope: GaugeAppScope;
    readonly page_id: string;
    readonly command_id: string;
    readonly expected_basis: string;
    readonly status: "proposed" | "applying" | "applied" | "rejected" | "conflict";
}
export interface GaugeAppCommandResult<TResult = unknown> {
    readonly receipt: GaugeAppReceipt;
    /** Ceremony/output material which the authority intentionally shows once.
     * It is never reconstructed from a receipt replay or browser state. */
    readonly result?: TResult;
}
export interface AccountDeviceLinkAuthorization {
    readonly delegation: {
        readonly subkey: string;
        readonly authority_root: string;
        readonly expiry: number;
        readonly signature: readonly number[];
    };
    readonly sealed_key: {
        readonly ephemeral_pubkey: string;
        readonly ciphertext: string;
    };
}
export interface AccountDeviceLinkStatus {
    readonly link: AccountDeviceLink;
    readonly account_root: string;
    readonly authorization: AccountDeviceLinkAuthorization | null;
    readonly completion_challenge: string | null;
    readonly terminal: boolean;
}
export interface GaugeAppProposal {
    readonly id: string;
    readonly app: GaugeAppKind;
    readonly scope: GaugeAppScope;
    readonly actor: string;
    readonly page_id: string;
    readonly command_id: string;
    readonly expected_basis: string;
    readonly payload: unknown;
    readonly client: GaugeAppClient;
    readonly status: "proposed" | "applying" | "applied" | "rejected" | "conflict";
    readonly reviewed_by?: string | null;
    readonly receipt_id: string;
}
export interface GaugeAppAgentProposal {
    readonly page_id: string;
    readonly command_id: string;
    readonly expected_basis: string;
    readonly payload: unknown;
}
export interface GaugeAppAgentTurn {
    readonly message: string;
    readonly proposals: readonly GaugeAppAgentProposal[];
}
export interface GaugeAppAgentStopResult {
    readonly stopped: boolean;
}
export interface GaugeAppAgentErasureReceipt {
    readonly thread_id: string;
    readonly generation: number;
}
export type GaugeAppAgentLiveEvent =
    | { readonly type: "started" }
    | { readonly type: "text"; readonly delta: string }
    | { readonly type: "tool"; readonly tool: string; readonly call_id: string }
    | { readonly type: "tool-result"; readonly call_id: string; readonly ok: boolean }
    | { readonly type: "settled" | "stopped" | "failed" };
export interface GaugeAppAgentLiveFrame {
    readonly cursor: string;
    readonly thread_id: string;
    readonly turn_id: string;
    readonly sequence: number;
    readonly event: GaugeAppAgentLiveEvent;
}
export interface GaugeAppAgentMessage {
    readonly id: string;
    readonly thread_id: string;
    readonly app: GaugeAppKind;
    readonly scope: GaugeAppScope;
    readonly actor: string;
    readonly sequence: number;
    readonly role: "user" | "assistant";
    readonly text: string;
    readonly proposals: readonly GaugeAppAgentProposal[];
}
export interface GaugeAppAgentThread {
    /** Stable across authorization epochs for one exact person/App/scope. */
    readonly id: string;
    /** Opaque resume position for the next transcript read. */
    readonly cursor: string;
    readonly messages: readonly GaugeAppAgentMessage[];
}
export interface GaugeAppUpdateSnapshot {
    readonly cursor: string;
    readonly invalidations: readonly {
        readonly page_id: string;
        readonly resource_basis: string;
    }[];
}

const nonEmptyString: ModelReader<string> = (value, path) => {
    const parsed = stringValue(value, path);
    return parsed.length > 0 ? parsed : invalidModel(path);
};
const updateSnapshot = shape({
    cursor: nonEmptyString,
    invalidations: arrayOf(shape({
        page_id: nonEmptyString,
        resource_basis: nonEmptyString,
    })),
});

export function parseGaugeAppUpdateSnapshot(value: unknown): GaugeAppUpdateSnapshot {
    return updateSnapshot(value, "updates");
}

type GaugeAppRoute = { readonly method: "GET" | "POST"; readonly path: string };
/** Kept literal and named for the repository's textual client/supply gate. */
const controlPlaneOperation = <M extends GaugeAppRoute["method"], P extends string>(method: M, path: P) => ({ method, path });

/** Explicit literal routes are checked against the product route contract. */
export const gaugeAppRoutes = {
    "account-settings": {
        session: controlPlaneOperation("POST", "/gaugeapps/account-settings/sessions"),
        page: controlPlaneOperation("GET", "/gaugeapps/account-settings/pages/:id"),
        command: controlPlaneOperation("POST", "/gaugeapps/account-settings/commands"),
        providerSecret: controlPlaneOperation("POST", "/gaugeapps/account-settings/provider-connections/secrets"),
        deviceLinkClaim: controlPlaneOperation("POST", "/gaugeapps/account-settings/device-links/claim"),
        deviceLinkRead: controlPlaneOperation("GET", "/gaugeapps/account-settings/device-links/:id"),
        deviceLinkComplete: controlPlaneOperation("POST", "/gaugeapps/account-settings/device-links/:id/complete"),
        consumerOidcLink: controlPlaneOperation("POST", "/auth/account/consumer-oidc/link/start"),
        consumerOidcAvatar: controlPlaneOperation("POST", "/auth/account/consumer-oidc/avatar/start"),
        proposals: controlPlaneOperation("GET", "/gaugeapps/account-settings/proposals"),
        review: controlPlaneOperation("POST", "/gaugeapps/account-settings/proposals/:id/review"),
        agentRead: controlPlaneOperation("GET", "/gaugeapps/account-settings/agent/messages"),
        agentEvents: controlPlaneOperation("GET", "/gaugeapps/account-settings/agent/events"),
        agentSend: controlPlaneOperation("POST", "/gaugeapps/account-settings/agent/messages"),
        agentStop: controlPlaneOperation("POST", "/gaugeapps/account-settings/agent/stop"),
        agentErase: controlPlaneOperation("POST", "/gaugeapps/account-settings/agent/erase"),
        updates: controlPlaneOperation("GET", "/gaugeapps/account-settings/updates"),
    },
    administration: {
        ssoCredential: controlPlaneOperation("POST", "/gaugeapps/administration/enterprise-identity/credential"),
        providerIntake: controlPlaneOperation("POST", "/gaugeapps/administration/model-providers/intake"),
        providerVerify: controlPlaneOperation("POST", "/gaugeapps/administration/model-providers/verify"),
        providerCredential: controlPlaneOperation("POST", "/v1/model-providers/credential"),
        session: controlPlaneOperation("POST", "/gaugeapps/administration/sessions"),
        page: controlPlaneOperation("GET", "/gaugeapps/administration/pages/:id"),
        command: controlPlaneOperation("POST", "/gaugeapps/administration/commands"),
        proposals: controlPlaneOperation("GET", "/gaugeapps/administration/proposals"),
        review: controlPlaneOperation("POST", "/gaugeapps/administration/proposals/:id/review"),
        agentRead: controlPlaneOperation("GET", "/gaugeapps/administration/agent/messages"),
        agentEvents: controlPlaneOperation("GET", "/gaugeapps/administration/agent/events"),
        agentSend: controlPlaneOperation("POST", "/gaugeapps/administration/agent/messages"),
        agentStop: controlPlaneOperation("POST", "/gaugeapps/administration/agent/stop"),
        agentErase: controlPlaneOperation("POST", "/gaugeapps/administration/agent/erase"),
        updates: controlPlaneOperation("GET", "/gaugeapps/administration/updates"),
    },
    "commercial-operations": {
        session: controlPlaneOperation("POST", "/gaugeapps/commercial-operations/sessions"),
        page: controlPlaneOperation("GET", "/gaugeapps/commercial-operations/pages/:id"),
        command: controlPlaneOperation("POST", "/gaugeapps/commercial-operations/commands"),
        proposals: controlPlaneOperation("GET", "/gaugeapps/commercial-operations/proposals"),
        review: controlPlaneOperation("POST", "/gaugeapps/commercial-operations/proposals/:id/review"),
        agentRead: controlPlaneOperation("GET", "/gaugeapps/commercial-operations/agent/messages"),
        agentEvents: controlPlaneOperation("GET", "/gaugeapps/commercial-operations/agent/events"),
        agentSend: controlPlaneOperation("POST", "/gaugeapps/commercial-operations/agent/messages"),
        agentStop: controlPlaneOperation("POST", "/gaugeapps/commercial-operations/agent/stop"),
        agentErase: controlPlaneOperation("POST", "/gaugeapps/commercial-operations/agent/erase"),
        updates: controlPlaneOperation("GET", "/gaugeapps/commercial-operations/updates"),
    },
} as const;

export const gaugeAppKinds: readonly GaugeAppKind[] = [
    "account-settings", "administration", "commercial-operations",
];

export const accountAuthorizationRoutes = {
    start: controlPlaneOperation("POST", "/auth/account/authorization/start"),
    finish: controlPlaneOperation("POST", "/auth/account/authorization/finish"),
} as const;

export interface AccountAuthorizationCeremony {
    readonly ceremony_id: string;
    readonly public_key: unknown;
}

export async function startAccountAuthorization(
    json: RouteJson,
    operation: string,
): Promise<AccountAuthorizationCeremony> {
    return await json(
        accountAuthorizationRoutes.start.method,
        accountAuthorizationRoutes.start.path,
        { operation },
    ) as AccountAuthorizationCeremony;
}

export async function finishAccountAuthorization(
    json: RouteJson,
    ceremonyId: string,
    credential: Readonly<Record<string, unknown>>,
): Promise<string> {
    const value = await json(
        accountAuthorizationRoutes.finish.method,
        accountAuthorizationRoutes.finish.path,
        { ceremony_id: ceremonyId, credential },
    ) as { readonly authorization_proof?: unknown };
    if (typeof value.authorization_proof !== "string" || !value.authorization_proof) {
        throw new Error("Fresh authorization response is malformed");
    }
    return value.authorization_proof;
}

const bind = (path: string, id: string) => path.replace(":id", encodeURIComponent(id));
const sessionQuery = (session: GaugeAppSession) => new URLSearchParams({
    session: session.id,
    generation: session.generation,
    scope: session.scope.id,
});

export async function openGaugeApp(
    json: RouteJson,
    app: GaugeAppKind,
    scope?: GaugeAppScope,
): Promise<GaugeAppSession> {
    const route = gaugeAppRoutes[app].session;
    const value = await json(route.method, route.path, scope ? { scope } : {});
    return (value as { readonly session: GaugeAppSession }).session;
}

export function readGaugeAppPage(json: RouteJson, session: GaugeAppSession, pageId: "project-hosts"): Promise<ProjectHostsPage>;
export function readGaugeAppPage(json: RouteJson, session: GaugeAppSession, pageId: "model-providers"): Promise<ModelProvidersPage>;
export function readGaugeAppPage<P extends AdministrationGaugeAppPageId>(
    json: RouteJson,
    session: GaugeAppSession,
    pageId: P,
): Promise<AdministrationGaugeAppPage<P>>;
export function readGaugeAppPage<P extends AccountGaugeAppPageId>(
    json: RouteJson,
    session: GaugeAppSession,
    pageId: P,
): Promise<AccountGaugeAppPage<P>>;
export function readGaugeAppPage<P extends CommercialGaugeAppPageId>(
    json: RouteJson,
    session: GaugeAppSession,
    pageId: P,
): Promise<CommercialGaugeAppPage<P>>;
export function readGaugeAppPage(
    json: RouteJson,
    session: GaugeAppSession,
    pageId: string,
): Promise<GaugeAppPageModel>;
export async function readGaugeAppPage(
    json: RouteJson,
    session: GaugeAppSession,
    pageId: string,
): Promise<GaugeAppPageModel> {
    const route = gaugeAppRoutes[session.app].page;
    const value = await json(route.method, `${bind(route.path, pageId)}?${sessionQuery(session)}`);
    const response = value as { readonly page?: unknown } | null;
    return parseGaugeAppPage(response?.page, session.app, pageId, session.scope);
}

export async function submitGaugeAppCommand(
    json: RouteJson,
    envelope: GaugeAppCommandEnvelope,
): Promise<GaugeAppCommandResult> {
    const route = gaugeAppRoutes[envelope.app].command;
    const value = await json(route.method, route.path, envelope, { idempotencyKey: envelope.idempotency_key });
    return value as GaugeAppCommandResult;
}

export async function submitAccountProviderSecret(
    json: RouteJson,
    envelope: GaugeAppCommandEnvelope,
    secret: string,
): Promise<GaugeAppCommandResult<{ readonly connection_id: string; readonly verification: "unverified" }>> {
    if (envelope.app !== "account-settings" || ![
        "provider-connection.api-key.add",
        "provider-connection.compatible.add",
    ].includes(envelope.command_id)) {
        throw new Error("The sealed provider route accepts Account Settings credential links only.");
    }
    const route = gaugeAppRoutes["account-settings"].providerSecret;
    return await json(route.method, route.path, { envelope, secret }, {
        idempotencyKey: envelope.idempotency_key,
    }) as GaugeAppCommandResult<{ readonly connection_id: string; readonly verification: "unverified" }>;
}

export async function submitOrganizationSsoCredential(
    json: RouteJson,
    envelope: GaugeAppCommandEnvelope,
    secret?: string,
): Promise<GaugeAppCommandResult<{
    readonly kind: "enterprise-identity-credential";
    readonly connection_revision: string;
    readonly client_secret_configured: boolean;
}>> {
    if (envelope.app !== "administration" || ![
        "enterprise-identity.connection.credential.set",
        "enterprise-identity.connection.credential.remove",
    ].includes(envelope.command_id)) {
        throw new Error("The sealed enterprise identity route accepts organization OIDC credentials only.");
    }
    const route = gaugeAppRoutes.administration.ssoCredential;
    const body = secret === undefined ? { envelope } : { envelope, secret };
    return await json(route.method, route.path, body, {
        idempotencyKey: envelope.idempotency_key,
    }) as GaugeAppCommandResult<{
        readonly kind: "enterprise-identity-credential";
        readonly connection_revision: string;
        readonly client_secret_configured: boolean;
    }>;
}

async function providerAuthorizationUrl(json: RouteJson, route: { readonly method: string; readonly path: string }): Promise<string> {
    const value = await json(route.method, route.path) as { readonly authorization_url?: unknown };
    if (typeof value.authorization_url !== "string" || !/^https:\/\//.test(value.authorization_url)) {
        throw new Error("The account service did not return a valid provider authorization URL.");
    }
    return value.authorization_url;
}

export async function startConsumerOidcLink(json: RouteJson): Promise<string> {
    return providerAuthorizationUrl(json, gaugeAppRoutes["account-settings"].consumerOidcLink);
}

/** Begin the person's explicit re-fetch of their photo from the provider
 * already linked to their account (DR-0195 §3). The provider round trip is the
 * point: the photo's URL changes when the photo does, so none is kept. */
export async function startConsumerOidcAvatar(json: RouteJson): Promise<string> {
    return providerAuthorizationUrl(json, gaugeAppRoutes["account-settings"].consumerOidcAvatar);
}

export async function claimAccountDeviceLink(
    json: RouteJson,
    claim: {
        readonly id?: string;
        readonly human_code?: string;
        readonly label: string;
        readonly kind: "computer" | "phone" | "tablet";
        readonly subkey_pubkey: string;
    },
    idempotencyKey: string,
): Promise<AccountDeviceLinkStatus> {
    const route = gaugeAppRoutes["account-settings"].deviceLinkClaim;
    return await json(route.method, route.path, claim, { idempotencyKey }) as AccountDeviceLinkStatus;
}

export async function readAccountDeviceLink(
    json: RouteJson,
    id: string,
): Promise<AccountDeviceLinkStatus> {
    const route = gaugeAppRoutes["account-settings"].deviceLinkRead;
    return await json(route.method, bind(route.path, id)) as AccountDeviceLinkStatus;
}

export async function completeAccountDeviceLink(
    json: RouteJson,
    id: string,
    completion: { readonly account_key_proof: string; readonly signature: string },
    idempotencyKey: string,
): Promise<AccountDeviceLinkStatus> {
    const route = gaugeAppRoutes["account-settings"].deviceLinkComplete;
    return await json(route.method, bind(route.path, id), completion, { idempotencyKey }) as AccountDeviceLinkStatus;
}

export async function prepareGaugeAppProposal(
    json: RouteJson,
    envelope: GaugeAppCommandEnvelope,
): Promise<GaugeAppReceipt> {
    if (envelope.client !== "agent") throw new Error("Only a GaugeApp agent can prepare a proposal.");
    const route = gaugeAppRoutes[envelope.app].proposals;
    const value = await json(route.method, route.path, envelope, { idempotencyKey: envelope.idempotency_key });
    return (value as { readonly receipt: GaugeAppReceipt }).receipt;
}

export async function listGaugeAppProposals(
    json: RouteJson,
    session: GaugeAppSession,
): Promise<readonly GaugeAppProposal[]> {
    const route = gaugeAppRoutes[session.app].proposals;
    const value = await json(route.method, `${route.path}?${sessionQuery(session)}`);
    return (value as { readonly proposals: readonly GaugeAppProposal[] }).proposals;
}

export async function reviewGaugeAppProposal(
    json: RouteJson,
    session: GaugeAppSession,
    proposalId: string,
    decision: "accept" | "reject",
    idempotencyKey: string,
    client: Exclude<GaugeAppClient, "agent"> = "web",
    authorizationProof?: string,
): Promise<{ readonly receipt: GaugeAppReceipt; readonly proposal: GaugeAppProposal | null; readonly result?: unknown }> {
    const route = gaugeAppRoutes[session.app].review;
    return await json(route.method, bind(route.path, proposalId), {
        session_id: session.id,
        generation: session.generation,
        app: session.app,
        scope: session.scope,
        decision,
        client,
        ...(authorizationProof ? { authorization_proof: authorizationProof } : {}),
    }, { idempotencyKey }) as { readonly receipt: GaugeAppReceipt; readonly proposal: GaugeAppProposal | null; readonly result?: unknown };
}

export async function sendGaugeAppAgentMessage(
    json: RouteJson,
    session: GaugeAppSession,
    message: string,
    idempotencyKey: string,
): Promise<GaugeAppAgentTurn> {
    const route = gaugeAppRoutes[session.app].agentSend;
    const value = await json(route.method, route.path, {
        session_id: session.id,
        generation: session.generation,
        scope: session.scope,
        idempotency_key: idempotencyKey,
        message,
    }, { idempotencyKey });
    return (value as { readonly turn: GaugeAppAgentTurn }).turn;
}

export async function stopGaugeAppAgentTurn(
    json: RouteJson,
    session: GaugeAppSession,
): Promise<boolean> {
    const route = gaugeAppRoutes[session.app].agentStop;
    const value = await json(route.method, route.path, {
        session_id: session.id,
        generation: session.generation,
        scope: session.scope,
    });
    return (value as GaugeAppAgentStopResult).stopped;
}

export async function eraseGaugeAppAgentTranscript(
    json: RouteJson,
    session: GaugeAppSession,
    idempotencyKey: string,
): Promise<GaugeAppAgentErasureReceipt> {
    const route = gaugeAppRoutes[session.app].agentErase;
    const value = await json(route.method, route.path, {
        session_id: session.id,
        generation: session.generation,
        scope: session.scope,
        idempotency_key: idempotencyKey,
    }, { idempotencyKey });
    return (value as { readonly erasure: GaugeAppAgentErasureReceipt }).erasure;
}

export async function listGaugeAppAgentMessages(
    json: RouteJson,
    session: GaugeAppSession,
    after?: string,
): Promise<GaugeAppAgentThread> {
    const route = gaugeAppRoutes[session.app].agentRead;
    const query = sessionQuery(session);
    if (after) query.set("after", after);
    const value = await json(route.method, `${route.path}?${query}`);
    return (value as { readonly thread: GaugeAppAgentThread }).thread;
}

const liveEventKind = oneOf(
    "started", "text", "tool", "tool-result", "settled", "stopped", "failed",
);

export function parseGaugeAppAgentLiveFrame(value: unknown): GaugeAppAgentLiveFrame {
    const source = objectValue(value, "agent-event");
    const rawEvent = objectValue(source.event, "agent-event.event");
    const type = liveEventKind(rawEvent.type, "agent-event.event.type");
    let event: GaugeAppAgentLiveEvent;
    switch (type) {
        case "text":
            event = { type, delta: stringValue(rawEvent.delta, "agent-event.event.delta") };
            break;
        case "tool":
            event = {
                type,
                tool: nonEmptyString(rawEvent.tool, "agent-event.event.tool"),
                call_id: nonEmptyString(rawEvent.call_id, "agent-event.event.call_id"),
            };
            break;
        case "tool-result":
            event = {
                type,
                call_id: nonEmptyString(rawEvent.call_id, "agent-event.event.call_id"),
                ok: booleanValue(rawEvent.ok, "agent-event.event.ok"),
            };
            break;
        default:
            event = { type };
    }
    return {
        cursor: nonEmptyString(source.cursor, "agent-event.cursor"),
        thread_id: nonEmptyString(source.thread_id, "agent-event.thread_id"),
        turn_id: nonEmptyString(source.turn_id, "agent-event.turn_id"),
        sequence: integerValue(source.sequence, "agent-event.sequence"),
        event,
    };
}

export function subscribeGaugeAppAgentEvents(
    events: RouteEventStream,
    session: GaugeAppSession,
    onFrame: (frame: GaugeAppAgentLiveFrame) => void,
    after?: string,
    onOpen?: () => void,
    onClose?: () => void,
): () => void {
    const query = sessionQuery(session);
    if (after) query.set("after", after);
    const route = gaugeAppRoutes[session.app].agentEvents;
    return events(`${route.path}?${query}`, (data) => {
        let value: unknown;
        try {
            value = JSON.parse(data);
        } catch {
            return;
        }
        onFrame(parseGaugeAppAgentLiveFrame(value));
    }, onOpen, onClose);
}

export async function readGaugeAppUpdates(
    json: RouteJson,
    session: GaugeAppSession,
    after = session.update_cursor,
): Promise<GaugeAppUpdateSnapshot> {
    const query = sessionQuery(session);
    query.set("after", after);
    const route = gaugeAppRoutes[session.app].updates;
    const snapshot = parseGaugeAppUpdateSnapshot(await json(route.method, `${route.path}?${query}`));
    const admittedPages = new Set(session.pages.map((page) => page.id));
    if (snapshot.invalidations.some((item) => !admittedPages.has(item.page_id))) {
        return invalidModel("updates.invalidations[].page_id");
    }
    return snapshot;
}
