import type { RouteJson } from "./control-plane-transport";

export type ManagementEnvironmentKind = "hub" | "administration" | "vend";
export type ManagementEnvironmentClient = "browser" | "edit" | "agent" | "cli";
export interface ManagementEnvironmentScope { readonly kind: "person" | "tenant" | "provider-tenant"; readonly id: string; }
export interface ManagementDocumentGrant {
    readonly id: string; readonly path: string; readonly schema: string;
    readonly revision: string; readonly freshness: string; readonly readable: boolean;
    readonly editable: boolean; readonly commands: readonly string[];
}
export interface ManagementCommandGrant { readonly id: string; readonly capability: string; readonly review: "immediate" | "human"; }
export interface ManagementEnvironmentSession {
    readonly id: string; readonly environment: ManagementEnvironmentKind;
    readonly scope: ManagementEnvironmentScope; readonly actor: string;
    readonly capabilities: readonly string[]; readonly documents: readonly ManagementDocumentGrant[];
    readonly commands: readonly ManagementCommandGrant[];
}
export interface ManagementDocumentProjection {
    readonly id: string; readonly path: string; readonly schema: string;
    readonly revision: string; readonly freshness: string; readonly content: unknown;
}
export interface ManagementCommandEnvelope {
    readonly session_id: string; readonly environment: ManagementEnvironmentKind;
    readonly scope: ManagementEnvironmentScope; readonly document_id: string;
    readonly command_id: string; readonly base_revision: string; readonly payload: unknown;
    readonly client: ManagementEnvironmentClient;
}
export interface ManagementEnvironmentReceipt {
    readonly id: string; readonly session_id: string; readonly environment: ManagementEnvironmentKind;
    readonly scope: ManagementEnvironmentScope; readonly document_id: string;
    readonly command_id: string; readonly base_revision: string;
    readonly status: "proposed" | "applied" | "rejected" | "conflict";
}
export interface ManagementEnvironmentChange {
    readonly id: string; readonly environment: ManagementEnvironmentKind;
    readonly scope: ManagementEnvironmentScope; readonly actor: string;
    readonly document_id: string; readonly command_id: string;
    readonly base_revision: string; readonly payload: unknown;
    readonly client: ManagementEnvironmentClient;
    readonly status: "proposed" | "applied" | "rejected" | "conflict";
    readonly reviewed_by?: string | null; readonly receipt_id: string;
}
export interface ManagementAgentProposal {
    readonly document_id: string;
    readonly command_id: string;
    readonly base_revision: string;
    readonly payload: unknown;
}
export interface ManagementAgentTurn {
    readonly message: string;
    readonly proposals: readonly ManagementAgentProposal[];
}
export interface ManagementAgentMessage {
    readonly id: string;
    readonly session_id: string;
    readonly environment: ManagementEnvironmentKind;
    readonly scope: ManagementEnvironmentScope;
    readonly actor: string;
    readonly sequence: number;
    readonly role: "user" | "assistant";
    readonly text: string;
}

type ManagementRoute = { readonly method: "GET" | "POST"; readonly path: string };

function controlPlaneOperation<M extends ManagementRoute["method"], P extends string>(
    method: M,
    path: P,
): { readonly method: M; readonly path: P } {
    return { method, path };
}

/** Every route each Environment answers, written out per Environment.
 *
 * The repetition is load-bearing and must stay. `scripts/check-client-calls.mjs`
 * matches the literal paths a client asks for against the routes the control
 * plane actually serves, and it is textual by design — "cheap enough to run on
 * every commit and blunt enough that nobody has to maintain it". Deriving these
 * paths from the Environment name reads better and takes all of them out of
 * that check's sight, so a client asking for a path nobody serves would once
 * again compile, typecheck, ship, and fail when a person clicks the thing.
 *
 * Adding an Environment means adding a block here. `managementRouteNames` and
 * its test are what stop that block from being quietly incomplete. */
export const managementRoutes = {
    hub: {
        session: controlPlaneOperation("POST", "/environments/hub/sessions"),
        document: controlPlaneOperation("GET", "/environments/hub/documents/:id"),
        command: controlPlaneOperation("POST", "/environments/hub/commands"),
        changes: controlPlaneOperation("GET", "/environments/hub/changes"),
        agentRead: controlPlaneOperation("GET", "/environments/hub/agent/messages"),
        agentSend: controlPlaneOperation("POST", "/environments/hub/agent/messages"),
        review: controlPlaneOperation("POST", "/environments/hub/changes/:id/review"),
    },
    administration: {
        session: controlPlaneOperation("POST", "/environments/administration/sessions"),
        document: controlPlaneOperation("GET", "/environments/administration/documents/:id"),
        command: controlPlaneOperation("POST", "/environments/administration/commands"),
        changes: controlPlaneOperation("GET", "/environments/administration/changes"),
        agentRead: controlPlaneOperation("GET", "/environments/administration/agent/messages"),
        agentSend: controlPlaneOperation("POST", "/environments/administration/agent/messages"),
        review: controlPlaneOperation("POST", "/environments/administration/changes/:id/review"),
        propose: controlPlaneOperation("POST", "/environments/administration/changes"),
    },
    vend: {
        session: controlPlaneOperation("POST", "/environments/vend/sessions"),
        document: controlPlaneOperation("GET", "/environments/vend/documents/:id"),
        command: controlPlaneOperation("POST", "/environments/vend/commands"),
        changes: controlPlaneOperation("GET", "/environments/vend/changes"),
        agentRead: controlPlaneOperation("GET", "/environments/vend/agent/messages"),
        agentSend: controlPlaneOperation("POST", "/environments/vend/agent/messages"),
        review: controlPlaneOperation("POST", "/environments/vend/changes/:id/review"),
    },
} as const;

type CommonManagementRoute =
    | "session" | "document" | "command" | "changes" | "review"
    | "agentRead" | "agentSend";

/** The operations every Environment must declare. Exported so a test can hold
 * the table to it: a kind added with a route missing fails there rather than at
 * the moment someone presses the control it belongs to. */
export const managementRouteNames: readonly CommonManagementRoute[] = [
    "session", "document", "command", "changes", "review",
    "agentRead", "agentSend",
];

/** The Environments this client can address. Exported for the same reason. */
export const managementEnvironmentKinds: readonly ManagementEnvironmentKind[] = [
    "hub", "administration", "vend",
];

function managementRoute(
    environment: ManagementEnvironmentKind,
    route: CommonManagementRoute,
): ManagementRoute {
    return managementRoutes[environment][route];
}

function bindRoute(route: ManagementRoute, id: string): string {
    return route.path.replace(":id", encodeURIComponent(id));
}

export async function openManagementEnvironment(json: RouteJson, environment: ManagementEnvironmentKind, scope?: ManagementEnvironmentScope): Promise<ManagementEnvironmentSession> {
    const route = managementRoute(environment, "session");
    const value = await json(route.method, route.path, scope ? { scope } : {});
    return (value as { session: ManagementEnvironmentSession }).session;
}
export async function readManagementDocument(json: RouteJson, session: ManagementEnvironmentSession, documentId: string): Promise<ManagementDocumentProjection> {
    const query = new URLSearchParams({ session: session.id, scope: session.scope.id });
    const route = managementRoute(session.environment, "document");
    const value = await json(route.method, `${bindRoute(route, documentId)}?${query}`);
    return (value as { document: ManagementDocumentProjection }).document;
}
export async function submitManagementCommand(json: RouteJson, envelope: ManagementCommandEnvelope, idempotencyKey: string): Promise<ManagementEnvironmentReceipt> {
    const route = managementRoute(envelope.environment, "command");
    const value = await json(route.method, route.path, envelope, { idempotencyKey });
    return (value as { receipt: ManagementEnvironmentReceipt }).receipt;
}
export async function proposeManagementDocumentChange(
    json: RouteJson,
    input: { readonly session: ManagementEnvironmentSession; readonly documentId: string; readonly baseRevision: string; readonly content: unknown; readonly client: ManagementEnvironmentClient },
    idempotencyKey: string,
): Promise<ManagementEnvironmentReceipt> {
    // The session already states, per document, whether its literal form may be
    // edited. Refusing by Environment name was a proxy for that fact, and a
    // coarser one: it admitted every document in Administration and no document
    // anywhere else, while the grant marks exactly four Administration documents
    // editable. The grant is server-declared, so this refuses the same cases and
    // the ones the name check could not see.
    //
    // A fail-fast guard, not the authority: the serving side owns enforcement,
    // and a client cannot hold that for it.
    const grant = input.session.documents.find((document) => document.id === input.documentId);
    if (!grant?.editable) {
        throw new Error(`Document ${input.documentId} is not editable in this session.`);
    }
    const routes = managementRoutes[input.session.environment];
    if (!("propose" in routes)) {
        throw new Error(
            `The ${input.session.environment} control plane serves no literal-change route.`,
        );
    }
    const route = routes.propose;
    const value = await json(route.method, route.path, {
        session_id: input.session.id, environment: input.session.environment, scope: input.session.scope,
        document_id: input.documentId, base_revision: input.baseRevision, content: input.content, client: input.client,
    }, { idempotencyKey });
    return (value as { receipt: ManagementEnvironmentReceipt }).receipt;
}

export async function listManagementChanges(json: RouteJson, session: ManagementEnvironmentSession): Promise<readonly ManagementEnvironmentChange[]> {
    const query = new URLSearchParams({ session: session.id, scope: session.scope.id });
    const route = managementRoute(session.environment, "changes");
    const value = await json(route.method, `${route.path}?${query}`);
    return (value as { changes: readonly ManagementEnvironmentChange[] }).changes;
}

export async function sendManagementAgentMessage(
    json: RouteJson,
    session: ManagementEnvironmentSession,
    message: string,
): Promise<ManagementAgentTurn> {
    const route = managementRoute(session.environment, "agentSend");
    const value = await json(route.method, route.path, {
        session_id: session.id,
        scope: session.scope,
        message,
    });
    return (value as { turn: ManagementAgentTurn }).turn;
}

export async function listManagementAgentMessages(
    json: RouteJson,
    session: ManagementEnvironmentSession,
): Promise<readonly ManagementAgentMessage[]> {
    const query = new URLSearchParams({ session: session.id, scope: session.scope.id });
    const route = managementRoute(session.environment, "agentRead");
    const value = await json(route.method, `${route.path}?${query}`);
    return (value as { transcript: readonly ManagementAgentMessage[] }).transcript;
}

export async function reviewManagementChange(
    json: RouteJson,
    session: ManagementEnvironmentSession,
    changeId: string,
    decision: "accept" | "reject",
    idempotencyKey: string,
    client: ManagementEnvironmentClient = "browser",
): Promise<{ readonly receipt: ManagementEnvironmentReceipt; readonly change: ManagementEnvironmentChange; readonly result?: unknown }> {
    const route = managementRoute(session.environment, "review");
    return await json(route.method, bindRoute(route, changeId), {
        session_id: session.id, environment: session.environment, scope: session.scope, decision, client,
    }, { idempotencyKey }) as { readonly receipt: ManagementEnvironmentReceipt; readonly change: ManagementEnvironmentChange; readonly result?: unknown };
}
