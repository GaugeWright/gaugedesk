import type { WorkbenchTransport } from "./control-plane-workbench";

/** Retain this exact value before submitting intent. It conveys no authority.
 * Recovery addresses its original Home, even after a project moves. */
export interface NativeFileRequestIdentity {
    readonly home: string;
    readonly issuer: string;
    readonly scope: string;
    readonly request_id: string;
}

export type NativeFileActionView = "command" | "execution" | "saved";

export interface NativeFileActor { readonly home: string; readonly actor: string }

export interface NativeFileSavedContent {
    readonly identity: NativeFileRequestIdentity;
    readonly cut: string;
    readonly content: string;
    readonly content_hash: string;
    readonly merged: boolean;
    readonly observer: string;
    readonly restrictions: Readonly<Record<string, unknown>>;
}

/** Historical accepted bytes only. This neither reads the working copy nor
 * grants permission to reuse the returned content in another action. */
export async function readNativeFileSavedContent(transport: WorkbenchTransport,
    retained: NativeFileRequestIdentity, cut: string): Promise<NativeFileSavedContent> {
    const identity = parseNativeFileRequestIdentity(retained);
    if (typeof cut !== "string" || !cut.trim()) throw new Error("An exact saved cut is required");
    const query = new URLSearchParams({ ...identity, cut });
    const value = await transport.json("GET", `/file-actions/saved-content?${query}`);
    if (!object(value) || value.cut !== cut || typeof value.content !== "string"
        || typeof value.content_hash !== "string" || !value.content_hash.trim()
        || typeof value.merged !== "boolean" || typeof value.observer !== "string"
        || !value.observer.trim() || !object(value.restrictions)) {
        throw new Error("Native saved content is unavailable");
    }
    const observed = parseNativeFileRequestIdentity(value.identity);
    if (observed.home !== identity.home || observed.issuer !== identity.issuer
        || observed.scope !== identity.scope || observed.request_id !== identity.request_id) {
        throw new Error("Native saved content belongs to another request");
    }
    return Object.freeze({ identity, cut, content: value.content, content_hash: value.content_hash,
        merged: value.merged, observer: value.observer, restrictions: value.restrictions });
}

/** Identity observation only. Submission must still fence a later sign-in change. */
export async function observeNativeFileActor(transport: WorkbenchTransport, expectedHome: string): Promise<NativeFileActor> {
    const value = await transport.json("GET", "/file-actions/actor");
    if (!object(value) || Object.keys(value).sort().join(",") !== "actor,home"
        || value.home !== expectedHome || typeof value.home !== "string" || !value.home.trim()
        || typeof value.actor !== "string" || !value.actor.trim()) {
        throw new Error("Verified native file actor is unavailable");
    }
    return Object.freeze({ home: value.home, actor: value.actor });
}

export interface NativeFileSaveSubmission {
    readonly expected_actor: string;
    readonly chat: string;
    readonly path: string;
    readonly base_cut: string;
    readonly content: string;
    readonly dispatch_request_id: string;
}

/** Command admission is distinct from dispatch authorization and from Saved. */
export interface NativeFileSaveReceipt {
    readonly actor: string;
    readonly identity: NativeFileRequestIdentity;
    readonly admission: "admitted";
    readonly replayed: boolean;
    readonly dispatch_request_id: string;
    readonly dispatch: { readonly state: "unavailable" }
        | { readonly state: "authorized"; readonly grant_ref: string; readonly replayed: boolean };
}

/** Evidence stays in the owner's wire shape. This transport does not infer a
 * successful save from an HTTP response, absent runtime history or empty facts. */
export interface NativeFileActionObservation {
    readonly identity: NativeFileRequestIdentity;
    readonly view: NativeFileActionView;
    readonly observer: string;
    readonly restrictions: Readonly<Record<string, unknown>>;
    readonly evidence: unknown;
}

function object(value: unknown): value is Record<string, unknown> {
    return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function parseNativeFileRequestIdentity(value: unknown): NativeFileRequestIdentity {
    if (!object(value) || Object.keys(value).sort().join(",") !== "home,issuer,request_id,scope"
        || [value.home, value.issuer, value.scope, value.request_id]
            .some((part) => typeof part !== "string" || !part.trim())) {
        throw new Error("Native file request identity is unavailable");
    }
    return Object.freeze({
        home: value.home as string,
        issuer: value.issuer as string,
        scope: value.scope as string,
        request_id: value.request_id as string,
    });
}

/** A read before submission, not a way to refresh an uncertain request.
 * The caller chooses the key and must retain the returned identity before any
 * submit call. The selected transport must address expectedHome. */
export async function prepareNativeFileSaveRequest(
    transport: WorkbenchTransport,
    expectedHome: string,
    chat: string,
    path: string,
    requestId: string,
): Promise<NativeFileRequestIdentity> {
    const query = new URLSearchParams({ path, request_id: requestId });
    const value = await transport.json("GET", `/chats/${encodeURIComponent(chat)}/file-actions/request?${query}`);
    const identity = parseNativeFileRequestIdentity(value);
    if (identity.home !== expectedHome || identity.request_id !== requestId) {
        throw new Error("Native file request identity does not match the selected Home and request");
    }
    return identity;
}

/** Read only from the transport addressing identity.home. No new key or current
 * chat/project scope is derived, and a failed read never triggers submission. */
export async function observeNativeFileRequest(
    transport: WorkbenchTransport,
    retained: NativeFileRequestIdentity,
    view: NativeFileActionView,
): Promise<NativeFileActionObservation> {
    const identity = parseNativeFileRequestIdentity(retained);
    const query = new URLSearchParams({ ...identity });
    const value = await transport.json("GET", `/file-actions/requests/${view}?${query}`);
    if (!object(value) || value.view !== view || typeof value.observer !== "string"
        || !value.observer.trim() || !object(value.restrictions) || !("evidence" in value)) {
        throw new Error("Native file request observation is unavailable");
    }
    const observed = parseNativeFileRequestIdentity(value.identity);
    if (observed.home !== identity.home || observed.issuer !== identity.issuer
        || observed.scope !== identity.scope || observed.request_id !== identity.request_id) {
        throw new Error("Native file observation belongs to another request");
    }
    if ((view === "saved" && !Array.isArray(value.evidence))
        || (view === "command" && !object(value.evidence))
        || (view === "execution" && (!object(value.evidence)
            || !object(value.evidence.command) || !("runtime" in value.evidence)))) {
        throw new Error("Native file request evidence is unavailable");
    }
    return Object.freeze({ identity, view, observer: value.observer,
        restrictions: value.restrictions, evidence: value.evidence });
}

/** Both identities must already be retained by the caller. This sends once to
 * the original Home; a refusal, lost response or unavailable dispatch never
 * generates another key, retries the effect, or reports Saved. */
export async function submitNativeFileSave(
    transport: WorkbenchTransport,
    retained: NativeFileRequestIdentity,
    input: NativeFileSaveSubmission,
): Promise<NativeFileSaveReceipt> {
    const identity = parseNativeFileRequestIdentity(retained);
    if ([input.expected_actor, input.chat, input.path, input.base_cut, input.dispatch_request_id]
        .some((value) => typeof value !== "string" || !value.trim()) || typeof input.content !== "string") {
        throw new Error("Retained save intent and dispatch identity are required");
    }
    const body = { identity, expected_actor: input.expected_actor, path: input.path, base_cut: input.base_cut,
        content: input.content, dispatch_request_id: input.dispatch_request_id };
    const value = await transport.json("POST", `/chats/${encodeURIComponent(input.chat)}/file-actions/save`,
        body, { idempotencyKey: identity.request_id });
    if (!object(value) || value.actor !== input.expected_actor || value.admission !== "admitted" || typeof value.replayed !== "boolean"
        || value.dispatch_request_id !== body.dispatch_request_id || !object(value.dispatch)) {
        throw new Error("Save submission evidence is unavailable; inspect the original request");
    }
    const observed = parseNativeFileRequestIdentity(value.identity);
    if (observed.home !== identity.home || observed.issuer !== identity.issuer
        || observed.scope !== identity.scope || observed.request_id !== identity.request_id) {
        throw new Error("Save submission belongs to another request");
    }
    let dispatch: NativeFileSaveReceipt["dispatch"];
    if (value.dispatch.state === "unavailable") {
        dispatch = Object.freeze({ state: "unavailable" });
    } else if (value.dispatch.state === "authorized" && typeof value.dispatch.grant_ref === "string"
        && value.dispatch.grant_ref.trim() && typeof value.dispatch.replayed === "boolean") {
        dispatch = Object.freeze({ state: "authorized", grant_ref: value.dispatch.grant_ref,
            replayed: value.dispatch.replayed });
    } else {
        throw new Error("Save dispatch evidence is unavailable; inspect the original request");
    }
    return Object.freeze({ identity, actor: input.expected_actor, admission: "admitted", replayed: value.replayed,
        dispatch_request_id: body.dispatch_request_id, dispatch });
}
