import type { RouteJson } from "./control-plane-transport";

export interface TokenWrightScope { readonly kind: string; readonly id: string }
export interface TokenWrightDocumentGrant {
    readonly id: string;
    readonly path: string;
    readonly schema: string;
    readonly revision: string;
    readonly freshness: string;
    readonly readable: boolean;
    readonly editable: boolean;
    readonly commands: readonly string[];
}
export interface TokenWrightSession {
    readonly id: string;
    readonly environment: "tokenwright";
    readonly scope: TokenWrightScope;
    readonly actor: string;
    readonly capabilities: readonly string[];
    readonly documents: readonly TokenWrightDocumentGrant[];
    readonly commands: readonly { readonly id: string; readonly capability: string; readonly review: "immediate" | "human" }[];
}
export interface TokenWrightReceipt {
    readonly id: string;
    readonly session_id: string;
    readonly environment: "tokenwright";
    readonly scope: TokenWrightScope;
    readonly document_id: string;
    readonly command_id: string;
    readonly base_revision: string;
    readonly status: "proposed" | "applied" | "rejected" | "conflict";
}
export interface TokenWrightDocumentProjection {
    readonly id: string;
    readonly path: string;
    readonly schema: string;
    readonly revision: string;
    readonly freshness: string;
    readonly content: unknown;
}
export interface TokenWrightCommandEnvelope {
    readonly session_id: string;
    readonly environment: "tokenwright";
    readonly scope: TokenWrightScope;
    readonly document_id: string;
    readonly command_id: string;
    readonly base_revision: string;
    readonly payload: unknown;
    readonly client: "browser" | "edit" | "agent" | "cli";
}

type TokenWrightRoute = { readonly method: "GET" | "POST"; readonly path: string };
/** Kept literal and named for the repository's textual client/supply gate. */
const controlPlaneOperation = <M extends TokenWrightRoute["method"], P extends string>(method: M, path: P) => ({ method, path });

export const tokenWrightRoutes = {
    session: controlPlaneOperation("POST", "/environments/tokenwright/sessions"),
    document: controlPlaneOperation("GET", "/environments/tokenwright/documents/:id"),
    command: controlPlaneOperation("POST", "/environments/tokenwright/commands"),
    changes: controlPlaneOperation("GET", "/environments/tokenwright/changes"),
    review: controlPlaneOperation("POST", "/environments/tokenwright/changes/:id/review"),
    propose: controlPlaneOperation("POST", "/environments/tokenwright/changes"),
    audit: controlPlaneOperation("GET", "/environments/tokenwright/audit"),
} as const;

const bind = (path: string, id: string) => path.replace(":id", encodeURIComponent(id));

export async function submitTokenWrightCommand(
    json: RouteJson,
    envelope: TokenWrightCommandEnvelope,
    idempotencyKey: string,
): Promise<TokenWrightReceipt> {
    const value = await json("POST", tokenWrightRoutes.command.path, envelope, { idempotencyKey });
    return (value as { readonly receipt: TokenWrightReceipt }).receipt;
}

export async function proposeTokenWrightDocumentChange(
    json: RouteJson,
    input: {
        readonly session: TokenWrightSession;
        readonly documentId: string;
        readonly baseRevision: string;
        readonly content: unknown;
    },
    idempotencyKey: string,
): Promise<TokenWrightReceipt> {
    const grant = input.session.documents.find((document) => document.id === input.documentId);
    if (!grant?.editable) throw new Error(`Document ${input.documentId} is not editable in this session.`);
    const value = await json("POST", tokenWrightRoutes.propose.path, {
        session_id: input.session.id,
        environment: "tokenwright",
        scope: input.session.scope,
        document_id: input.documentId,
        base_revision: input.baseRevision,
        content: input.content,
        client: "edit",
    }, { idempotencyKey });
    return (value as { readonly receipt: TokenWrightReceipt }).receipt;
}

export async function openTokenWrightEnvironment(
    json: RouteJson,
    scope?: TokenWrightScope,
): Promise<TokenWrightSession> {
    const value = await json("POST", tokenWrightRoutes.session.path, scope ? { scope } : {});
    return (value as { readonly session: TokenWrightSession }).session;
}

export async function readTokenWrightDocument(
    json: RouteJson,
    session: TokenWrightSession,
    id: string,
): Promise<TokenWrightDocumentProjection> {
    const query = new URLSearchParams({ session: session.id, scope: session.scope.id });
    const value = await json("GET", `${bind(tokenWrightRoutes.document.path, id)}?${query}`);
    return (value as { readonly document: TokenWrightDocumentProjection }).document;
}
