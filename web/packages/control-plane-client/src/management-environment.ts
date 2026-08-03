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

const managementRoutes = {
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

type CommonManagementRoute = "session" | "document" | "command" | "changes" | "agentRead" | "agentSend" | "review";

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
    if (input.session.environment !== "administration") {
        throw new Error("literal document changes are available only in Administration");
    }
    const route = managementRoutes.administration.propose;
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
