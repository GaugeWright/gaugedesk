import {
    browserRouteEventStream,
    browserRouteJson,
    browserRouteRequest,
} from "./browser-route-json";
import type { HomeId, ProjectId } from "./control-plane-domain";
import type { RouteJson } from "./control-plane-transport";
import { isSecureControlPlaneEndpoint } from "./control-plane-transport";
import type { WorkbenchTransport } from "./control-plane-workbench";
import { placementVerified } from "./directory-module";
import { parseOpaqueHomeRoute, type OpaqueHomeRoute } from "./home-routing";
import type { SharedProjectPin, SharedRouteWire } from "./shared-project-routes";
import { openTunnel, tunnelAvailable } from "./tunnel-module";
import { browserTunnelSocket, tunnelRouteJson } from "./tunnel-route-json";

export interface HomeInvitationPreview {
    /** The account it is for; empty for an email invitation still pending. */
    readonly authority: string;
    /** The address an email invitation is for (DR-0332). */
    readonly email?: string;
    readonly project: ProjectId;
    readonly homeId: HomeId;
    readonly endpoint: string;
}

interface HomeInvitationEnvelope extends HomeInvitationPreview {
    readonly invitation: string;
    readonly secret: string;
    /** How a Home with no endpoint is reached (DR-0370): its relay locator,
     * signed by its host key, under the placement the project's key signed. */
    readonly relayRoute?: SharedRouteWire;
    /** The owning account's directory root, where that route is read again. */
    readonly ownerRoot?: string;
}

export interface AcceptedHomeInvitation extends HomeInvitationPreview {
    readonly admission: string;
    /** For a project on a Home reached only through its relay: the project key
     * and route to pin, so this browser keeps reaching it (DR-0370 §2). */
    readonly shared?: SharedProjectPin;
}

export interface CreatedHomeInvitation {
    readonly invite: string;
    readonly url: string;
    readonly homeId: HomeId;
    readonly project: ProjectId;
    readonly endpoint: string;
    readonly expiresAt: number;
}

function requiredString(value: unknown, field: string): string {
    if (typeof value !== "string" || !value.trim()) {
        throw new Error(`Home invitation requires ${field}`);
    }
    return value;
}

function decodeHex(value: string): string {
    if (!value || value.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(value)) {
        throw new Error("Home invitation is malformed");
    }
    const bytes = new Uint8Array(value.length / 2);
    for (let index = 0; index < bytes.length; index += 1) {
        bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
    }
    return new TextDecoder().decode(bytes);
}

function envelope(encoded: string): HomeInvitationEnvelope {
    let raw: Record<string, unknown>;
    try {
        raw = JSON.parse(decodeHex(encoded)) as Record<string, unknown>;
    } catch {
        throw new Error("Home invitation is malformed");
    }
    if (raw.version !== 1) throw new Error("Home invitation version is unsupported");
    const endpoint = (typeof raw.endpoint === "string" ? raw.endpoint.trim() : "").replace(/\/+$/, "");
    // A Home with no endpoint is reached through its relay, and the invitation
    // carries that route instead, signed under the project's own key.
    let relayRoute: SharedRouteWire | undefined;
    if (endpoint) {
        if (!isSecureControlPlaneEndpoint(endpoint)) {
            throw new Error("Home invitation uses an insecure endpoint");
        }
    } else {
        const placement = raw.placement as SharedRouteWire["placement"] | undefined;
        if (!raw.relay || typeof placement?.project_key !== "string" || !placement.project_key) {
            throw new Error("Home invitation requires endpoint");
        }
        relayRoute = {
            project: requiredString(raw.project, "project"),
            home_id: requiredString(raw.home_id, "Home"),
            endpoint: "",
            relay: raw.relay,
            placement,
        };
        // The locator's shape, before anything dials it.
        parseOpaqueHomeRoute(relayRoute, "signed");
    }
    const ownerRoot = typeof raw.owner_root === "string" && raw.owner_root.trim()
        ? raw.owner_root.trim()
        : undefined;
    const email = typeof raw.invited_email === "string" && raw.invited_email.trim()
        ? raw.invited_email
        : undefined;
    const authority = typeof raw.invited_authority === "string" ? raw.invited_authority : "";
    if (!email) requiredString(authority, "invited authority");
    return {
        invitation: requiredString(raw.invitation, "invitation"),
        authority,
        ...(email ? { email } : {}),
        project: requiredString(raw.project, "project") as ProjectId,
        homeId: requiredString(raw.home_id, "Home") as HomeId,
        endpoint,
        secret: requiredString(raw.secret, "capability"),
        ...(relayRoute ? { relayRoute } : {}),
        ...(ownerRoot ? { ownerRoot } : {}),
    };
}

/** Decode only safe invitation metadata for confirmation UI. The capability is
 * deliberately omitted so callers cannot accidentally render or persist it. */
export function parseHomeInvitation(encoded: string): HomeInvitationPreview {
    const { authority, email, project, homeId, endpoint } = envelope(encoded);
    return { authority, ...(email ? { email } : {}), project, homeId, endpoint };
}

/** The invitation's own id, which the project's pending list names it by. Not
 * a capability: it lets an inviter's page match a link it is showing to the
 * pending row they cancel. */
export function homeInvitationId(encoded: string): string {
    return envelope(encoded).invitation;
}

/** Accept directly on the owner's Home using ordinary account authentication.
 * The opaque capability is used only in this request body, never a header, log,
 * or Home registry entry. The one place it rests is the invitee's own tab
 * (sessionStorage), from arrival until it is answered, so that it survives the
 * sign-in the invitee usually has to do first (DR-0204). */
export async function acceptHomeInvitation(
    encoded: string,
    options: AcceptHomeInvitationOptions = {},
): Promise<AcceptedHomeInvitation> {
    const expected = envelope(encoded);
    if (expected.relayRoute) return acceptOverRelay(encoded, expected, expected.relayRoute, options);
    const json = browserRouteJson(expected.endpoint, { bearer: options.bearer });
    const value = (await json("POST", "/home/invitations/accept", { invite: encoded })) as {
        home_id?: unknown;
        project?: unknown;
        endpoint?: unknown;
        admission?: unknown;
    };
    const endpoint = requiredString(value.endpoint, "accepted endpoint").replace(/\/+$/, "");
    if (
        value.home_id !== expected.homeId ||
        value.project !== expected.project ||
        endpoint !== expected.endpoint ||
        typeof value.admission !== "string" ||
        !value.admission
    ) {
        throw new Error("Home invitation acceptance did not match the invitation");
    }
    return { ...parseHomeInvitation(encoded), admission: value.admission };
}

export interface AcceptHomeInvitationOptions {
    readonly bearer?: () => string | null;
    /** How a call reaches a Home through its relay; the browser tunnel unless
     * given. Injected by tests and by a native shell with its own carrier. */
    readonly relayJson?: (route: OpaqueHomeRoute, bearer: () => string | null) => RouteJson & {
        close?: () => void;
    };
    /** Check a route's placement against a project key; the wasm module's,
     * strictly, unless given. */
    readonly placementVerified?: (route: unknown, projectKey: string) => Promise<boolean>;
}

/** The browser tunnel to a relay-only Home, carrying the account's bearer. */
function tunnelJson(route: OpaqueHomeRoute, bearer: () => string | null): RouteJson & { close(): void } {
    const relay = route.relay;
    if (!relay || !tunnelAvailable()) {
        throw new Error("this browser cannot reach a computer through the relay");
    }
    const url = `${relay.endpoint}/v1/relay/${relay.handle}`;
    return tunnelRouteJson({
        open: async () => {
            const { tunnel, handshake } = await openTunnel(relay);
            return { tunnel, socket: await browserTunnelSocket(url, handshake) };
        },
        bearer,
        // One call; the pool opens the working sessions afterwards.
        sessions: 1,
    });
}

/**
 * Accept on a Home reached only through its relay (DR-0370, DR-0451).
 *
 * The invitation names the project's key and carries a route that key placed;
 * nothing is dialed until the placement and the locator it vouches for hold
 * against that key. The Home's relay names the accepting account from the
 * bearer, and answers with the locator it is reached by now, which is kept
 * only if it holds against the same key.
 */
async function acceptOverRelay(
    encoded: string,
    expected: HomeInvitationEnvelope,
    carried: SharedRouteWire,
    options: AcceptHomeInvitationOptions,
): Promise<AcceptedHomeInvitation> {
    const projectKey = carried.placement?.project_key as string;
    const verify = options.placementVerified ?? placementVerified;
    if (!(await verify(carried, projectKey))) {
        throw new Error("Home invitation's route is not signed by its project's key");
    }
    const bearer = options.bearer ?? (() => null);
    const json = (options.relayJson ?? tunnelJson)(parseOpaqueHomeRoute(carried, "signed"), bearer);
    let value: Record<string, unknown>;
    try {
        value = (await json("POST", "/home/invitations/accept", { invite: encoded })) as Record<string, unknown>;
    } finally {
        json.close?.();
    }
    const endpoint = typeof value.endpoint === "string" ? value.endpoint : "";
    if (
        value.home_id !== expected.homeId ||
        value.project !== expected.project ||
        endpoint !== "" ||
        typeof value.admission !== "string" ||
        !value.admission
    ) {
        throw new Error("Home invitation acceptance did not match the invitation");
    }
    const answered: SharedRouteWire | null = value.relay && value.placement
        ? {
            project: expected.project,
            home_id: expected.homeId,
            endpoint: "",
            relay: value.relay,
            placement: value.placement as SharedRouteWire["placement"],
        }
        : null;
    const current = answered
        && (answered.placement?.project_key === projectKey)
        && (await verify(answered, projectKey))
        ? answered
        : carried;
    const ownerRoot = typeof value.owner_root === "string" && value.owner_root
        ? value.owner_root
        : expected.ownerRoot;
    return {
        ...parseHomeInvitation(encoded),
        admission: value.admission,
        shared: {
            project: expected.project,
            homeId: expected.homeId,
            projectKey,
            ...(ownerRoot ? { ownerRoot } : {}),
            route: current,
        },
    };
}

/** Owner/admin command. This uses the already-admitted Home transport. It
 * names exactly one recipient: an account chosen from the organization, or an
 * email address the accepting account must hold verified (DR-0332). A Home
 * reached only through its relay is sent no endpoint, and its invitation
 * carries its relay route instead; a Home nobody can reach says so itself. */
export async function createHomeInvitation(
    json: RouteJson,
    input: ({ readonly authority: string; readonly email?: undefined }
        | { readonly email: string; readonly authority?: undefined }) & {
        readonly project: ProjectId;
        readonly endpoint: string;
        readonly role?: "member" | "viewer";
    },
): Promise<CreatedHomeInvitation> {
    const endpoint = input.endpoint.trim().replace(/\/+$/, "");
    const value = (await json("POST", "/home/invitations", {
        ...(input.email !== undefined ? { email: input.email } : { authority: input.authority }),
        project: input.project,
        endpoint,
        role: input.role ?? "member",
    })) as Record<string, unknown>;
    const parsed = parseHomeInvitation(requiredString(value.invite, "invite"));
    const url = requiredString(value.url, "URL");
    const addressed = input.email !== undefined
        ? parsed.email === input.email.trim().toLowerCase()
        : parsed.authority === input.authority;
    if (
        !addressed ||
        parsed.project !== input.project ||
        parsed.endpoint !== endpoint ||
        typeof value.expires_at !== "number"
    ) {
        throw new Error("created Home invitation response is malformed");
    }
    return {
        invite: value.invite as string,
        url,
        homeId: parsed.homeId,
        project: parsed.project,
        endpoint: parsed.endpoint,
        expiresAt: value.expires_at,
    };
}

/** Ask the account service to email an email invitation's link to the
 * address it is for, naming the inviter by their verified address (DR-0332).
 * Resolves to the address it was sent to. */
export async function emailHomeInvitation(json: RouteJson, invite: string): Promise<string> {
    const value = (await json("POST", "/account/project-invitations/email", { invite })) as {
        sent_to?: unknown;
    };
    return requiredString(value?.sent_to, "the address it was sent to");
}

/** An invitation still waiting to be accepted. It names whom it is for and
 * never carries its link, which the Home does not keep (DR-0332). */
export interface PendingHomeInvitation {
    readonly id: string;
    /** The account an invitation chosen from the organization is for. */
    readonly authority: string;
    /** The address an email invitation is for. */
    readonly email: string | null;
    readonly role: string;
    readonly expiresAt: number;
}

/** The project's pending invitations, for whoever may invite to it. */
export async function listPendingHomeInvitations(
    json: RouteJson,
    project: ProjectId,
): Promise<PendingHomeInvitation[]> {
    const value = (await json(
        "GET",
        `/home/projects/${encodeURIComponent(project)}/invitations`,
    )) as { invitations?: unknown };
    if (!Array.isArray(value?.invitations)) return [];
    return value.invitations.flatMap((raw): PendingHomeInvitation[] => {
        const row = (raw ?? {}) as Record<string, unknown>;
        if (typeof row.id !== "string" || !row.id || typeof row.expires_at !== "number") return [];
        const email = typeof row.email === "string" && row.email ? row.email : null;
        const authority = typeof row.authority === "string" ? row.authority : "";
        if (!email && !authority) return [];
        return [{
            id: row.id,
            authority,
            email,
            role: typeof row.role === "string" ? row.role : "member",
            expiresAt: row.expires_at,
        }];
    });
}

/** Withdraw a pending invitation; its link then admits no one. */
export async function cancelHomeInvitation(json: RouteJson, id: string): Promise<void> {
    await json("POST", `/home/invitations/${encodeURIComponent(id)}/cancel`, {});
}

/** A fresh link for a pending invitation. The earlier link stops working. */
export async function resendHomeInvitation(
    json: RouteJson,
    id: string,
): Promise<CreatedHomeInvitation> {
    const value = (await json(
        "POST",
        `/home/invitations/${encodeURIComponent(id)}/resend`,
        {},
    )) as Record<string, unknown>;
    const parsed = parseHomeInvitation(requiredString(value.invite, "invite"));
    if (typeof value.expires_at !== "number") {
        throw new Error("resent Home invitation response is malformed");
    }
    return {
        invite: value.invite as string,
        url: requiredString(value.url, "URL"),
        homeId: parsed.homeId,
        project: parsed.project,
        endpoint: parsed.endpoint,
        expiresAt: value.expires_at,
    };
}

/** Construct an admitted target transport from a just-accepted invitation. */
export function acceptedHomeTransport(
    accepted: AcceptedHomeInvitation,
    bearer: () => string | null,
): WorkbenchTransport {
    const auth = { bearer, homeAdmission: () => accepted.admission };
    return {
        base: accepted.endpoint,
        json: browserRouteJson(accepted.endpoint, auth),
        request: browserRouteRequest(accepted.endpoint, auth),
        events: browserRouteEventStream(accepted.endpoint, auth),
    };
}
