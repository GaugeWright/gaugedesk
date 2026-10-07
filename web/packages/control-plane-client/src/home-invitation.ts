import {
    browserRouteEventStream,
    browserRouteJson,
    browserRouteRequest,
} from "./browser-route-json";
import type { HomeId, ProjectId } from "./control-plane-domain";
import type { RouteJson } from "./control-plane-transport";
import { isSecureControlPlaneEndpoint } from "./control-plane-transport";
import type { WorkbenchTransport } from "./control-plane-workbench";

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
}

export interface AcceptedHomeInvitation extends HomeInvitationPreview {
    readonly admission: string;
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
    const endpoint = requiredString(raw.endpoint, "endpoint").replace(/\/+$/, "");
    if (!isSecureControlPlaneEndpoint(endpoint)) {
        throw new Error("Home invitation uses an insecure endpoint");
    }
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
    };
}

/** Decode only safe invitation metadata for confirmation UI. The capability is
 * deliberately omitted so callers cannot accidentally render or persist it. */
export function parseHomeInvitation(encoded: string): HomeInvitationPreview {
    const { authority, email, project, homeId, endpoint } = envelope(encoded);
    return { authority, ...(email ? { email } : {}), project, homeId, endpoint };
}

/** Accept directly on the owner's Home using ordinary account authentication.
 * The opaque capability is used only in this request body, never a header, log,
 * or Home registry entry. The one place it rests is the invitee's own tab
 * (sessionStorage), from arrival until it is answered, so that it survives the
 * sign-in the invitee usually has to do first (DR-0204). */
export async function acceptHomeInvitation(
    encoded: string,
    options: { readonly bearer?: () => string | null } = {},
): Promise<AcceptedHomeInvitation> {
    const expected = envelope(encoded);
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

/** What a Home with no endpoint of its own — a desktop reached only through
 * the relay — says when asked to share a project. Its relay admits only the
 * accounts signed in on that computer, not a project's invited members
 * (DR-0332, WS-587), so an invitation it minted could never be accepted. The
 * Home's own refusal carries the same words. */
export const RELAY_ONLY_INVITATION =
    "this project is on a computer that others reach only through the relay, which does not "
    + "yet admit invited people; move the project to a hosted Home to share it";

/** Inviting to a project whose Home has no endpoint to give the invitee. */
export class RelayOnlyHomeInvitationError extends Error {
    constructor() {
        super(RELAY_ONLY_INVITATION);
        this.name = "RelayOnlyHomeInvitationError";
    }
}

/** Owner/admin command. This uses the already-admitted Home transport. It
 * names exactly one recipient: an account chosen from the organization, or an
 * email address the accepting account must hold verified (DR-0332). */
export async function createHomeInvitation(
    json: RouteJson,
    input: ({ readonly authority: string; readonly email?: undefined }
        | { readonly email: string; readonly authority?: undefined }) & {
        readonly project: ProjectId;
        readonly endpoint: string;
        readonly role?: "member" | "viewer";
    },
): Promise<CreatedHomeInvitation> {
    if (!input.endpoint.trim()) throw new RelayOnlyHomeInvitationError();
    const value = (await json("POST", "/home/invitations", {
        ...(input.email !== undefined ? { email: input.email } : { authority: input.authority }),
        project: input.project,
        endpoint: input.endpoint,
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
        parsed.endpoint !== input.endpoint.replace(/\/+$/, "") ||
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
