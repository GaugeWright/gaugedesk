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
    readonly authority: string;
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
    return {
        invitation: requiredString(raw.invitation, "invitation"),
        authority: requiredString(raw.invited_authority, "invited authority"),
        project: requiredString(raw.project, "project") as ProjectId,
        homeId: requiredString(raw.home_id, "Home") as HomeId,
        endpoint,
        secret: requiredString(raw.secret, "capability"),
    };
}

/** Decode only safe invitation metadata for confirmation UI. The capability is
 * deliberately omitted so callers cannot accidentally render or persist it. */
export function parseHomeInvitation(encoded: string): HomeInvitationPreview {
    const { authority, project, homeId, endpoint } = envelope(encoded);
    return { authority, project, homeId, endpoint };
}

/** Accept directly on the owner's Home using ordinary account authentication.
 * The opaque capability is used only in this request body, never a header, log,
 * Home registry entry, or browser storage value. */
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

/** Owner/admin command. This uses the already-admitted Home transport. */
export async function createHomeInvitation(
    json: RouteJson,
    input: {
        readonly authority: string;
        readonly project: ProjectId;
        readonly endpoint: string;
        readonly role?: "member" | "viewer";
    },
): Promise<CreatedHomeInvitation> {
    const value = (await json("POST", "/home/invitations", {
        authority: input.authority,
        project: input.project,
        endpoint: input.endpoint,
        role: input.role ?? "member",
    })) as Record<string, unknown>;
    const parsed = parseHomeInvitation(requiredString(value.invite, "invite"));
    const url = requiredString(value.url, "URL");
    if (
        parsed.authority !== input.authority ||
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
