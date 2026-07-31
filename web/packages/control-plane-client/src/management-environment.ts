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

const root = (environment: ManagementEnvironmentKind) => `/environments/${encodeURIComponent(environment)}`;

export async function openManagementEnvironment(json: RouteJson, environment: ManagementEnvironmentKind, scope?: ManagementEnvironmentScope): Promise<ManagementEnvironmentSession> {
    const value = await json("POST", `${root(environment)}/sessions`, scope ? { scope } : {});
    return (value as { session: ManagementEnvironmentSession }).session;
}
export async function readManagementDocument(json: RouteJson, session: ManagementEnvironmentSession, documentId: string): Promise<ManagementDocumentProjection> {
    const query = new URLSearchParams({ session: session.id, scope: session.scope.id });
    const value = await json("GET", `${root(session.environment)}/documents/${encodeURIComponent(documentId)}?${query}`);
    return (value as { document: ManagementDocumentProjection }).document;
}
export async function submitManagementCommand(json: RouteJson, envelope: ManagementCommandEnvelope, idempotencyKey: string): Promise<ManagementEnvironmentReceipt> {
    const value = await json("POST", `${root(envelope.environment)}/commands`, envelope, { idempotencyKey });
    return (value as { receipt: ManagementEnvironmentReceipt }).receipt;
}
export async function proposeManagementDocumentChange(
    json: RouteJson,
    input: { readonly session: ManagementEnvironmentSession; readonly documentId: string; readonly baseRevision: string; readonly content: unknown; readonly client: ManagementEnvironmentClient },
    idempotencyKey: string,
): Promise<ManagementEnvironmentReceipt> {
    const value = await json("POST", `${root(input.session.environment)}/changes`, {
        session_id: input.session.id, environment: input.session.environment, scope: input.session.scope,
        document_id: input.documentId, base_revision: input.baseRevision, content: input.content, client: input.client,
    }, { idempotencyKey });
    return (value as { receipt: ManagementEnvironmentReceipt }).receipt;
}

export async function listManagementChanges(json: RouteJson, session: ManagementEnvironmentSession): Promise<readonly ManagementEnvironmentChange[]> {
    const query = new URLSearchParams({ session: session.id, scope: session.scope.id });
    const value = await json("GET", `${root(session.environment)}/changes?${query}`);
    return (value as { changes: readonly ManagementEnvironmentChange[] }).changes;
}

export async function sendManagementAgentMessage(
    json: RouteJson,
    session: ManagementEnvironmentSession,
    message: string,
): Promise<ManagementAgentTurn> {
    const value = await json("POST", `${root(session.environment)}/agent/messages`, {
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
    const value = await json("GET", `${root(session.environment)}/agent/messages?${query}`);
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
    return await json("POST", `${root(session.environment)}/changes/${encodeURIComponent(changeId)}/review`, {
        session_id: session.id, environment: session.environment, scope: session.scope, decision, client,
    }, { idempotencyKey }) as { readonly receipt: ManagementEnvironmentReceipt; readonly change: ManagementEnvironmentChange; readonly result?: unknown };
}
