import type { RouteJson } from "./control-plane-transport";
import type { HomeId, ProjectId } from "./control-plane-domain";
import {
    parseOpaqueHomeRoutes,
    type OpaqueHomeRoute,
    type OpaqueRelayLocator,
} from "./home-routing";

export type AccountHomeKind = "local" | "registered" | "cloud";
export interface AccountHome {
    readonly id: HomeId;
    readonly kind: AccountHomeKind;
    readonly endpoint: string;
    readonly relay?: OpaqueRelayLocator | null;
}

export async function accountHomes(
    json: RouteJson,
): Promise<{ homes: AccountHome[]; selectedHome: HomeId | null }> {
    const value = (await json("GET", "/account/homes")) as {
        homes?: {
            id?: unknown;
            kind?: unknown;
            endpoint?: unknown;
            relay?: unknown;
        }[];
        selected_home?: unknown;
    };
    const homes = (value.homes ?? []).map((home) => {
        if (
            typeof home.id !== "string" ||
            !home.id ||
            typeof home.endpoint !== "string" ||
            !["local", "registered", "cloud"].includes(String(home.kind))
        ) {
            throw new Error("account Home response is malformed");
        }
        const parsed = parseOpaqueHomeRoutes({
            routes: [{
                project: "account-home",
                home_id: home.id,
                endpoint: home.endpoint,
                relay: home.relay,
            }],
        })[0]!;
        return {
            id: home.id as HomeId,
            kind: home.kind as AccountHomeKind,
            endpoint: parsed.endpoint,
            ...(parsed.relay ? { relay: parsed.relay } : {}),
        };
    });
    return {
        homes,
        selectedHome: typeof value.selected_home === "string"
            ? (value.selected_home as HomeId)
            : null,
    };
}

export async function accountRegisterHome(
    json: RouteJson,
    home: AccountHome,
    selected = false,
): Promise<void> {
    await json("POST", "/account/homes", {
        id: home.id,
        kind: home.kind,
        endpoint: home.endpoint,
        ...(home.relay ? {
            relay: {
                endpoint: home.relay.endpoint,
                handle: home.relay.handle,
                proof: home.relay.proof,
                route_epoch: home.relay.routeEpoch,
                home_fingerprint: home.relay.homeFingerprint,
            },
        } : {}),
        selected,
    });
}

export async function accountSelectHome(json: RouteJson, home: HomeId): Promise<void> {
    await json("PUT", "/account/homes/selected", { home_id: home });
}

export async function accountUnregisterHome(json: RouteJson, home: HomeId): Promise<void> {
    await json("DELETE", `/account/homes/${encodeURIComponent(home)}`);
}

export async function accountHomeRoutes(json: RouteJson): Promise<OpaqueHomeRoute[]> {
    return parseOpaqueHomeRoutes(await json("GET", "/account/home-routes"));
}

export async function accountPublishHomeRoute(
    json: RouteJson,
    route: OpaqueHomeRoute,
): Promise<void> {
    await json("POST", "/account/home-routes", {
        project: route.project,
        home_id: route.homeId,
        endpoint: route.endpoint,
        ...(route.relay ? {
            relay: {
                endpoint: route.relay.endpoint,
                handle: route.relay.handle,
                proof: route.relay.proof,
                route_epoch: route.relay.routeEpoch,
                home_fingerprint: route.relay.homeFingerprint,
            },
        } : {}),
    });
}

export async function accountDeleteHomeRoute(json: RouteJson, project: ProjectId): Promise<void> {
    await json("DELETE", `/account/home-routes/${encodeURIComponent(project)}`);
}

/** A device in the account's trusted-devices registry (ACCT-1). */
export interface AccountDevice {
    readonly id: string;
    readonly label: string;
    readonly status: string;
    /** Seconds since Unix epoch. Zero means the account record predates this fact. */
    readonly enrolledAt: number;
}

/** Parse the device projection defensively: a malformed or legacy date never
 * becomes a fictional enrollment time. */
export function parseAccountDevice(value: unknown): AccountDevice {
    const device = (value ?? {}) as Record<string, unknown>;
    return {
        id: typeof device.id === "string" ? device.id : "",
        label: typeof device.label === "string" ? device.label : "",
        status: typeof device.status === "string" ? device.status : "",
        enrolledAt: typeof device.enrolled_at === "number" && Number.isFinite(device.enrolled_at)
            ? Math.max(0, Math.floor(device.enrolled_at))
            : 0,
    };
}
/** A linked LLM provider — provider name only, never the token. */
export interface LinkedProvider {
    readonly provider: string;
    readonly linked: boolean;
}
export type ManagedPlanStatus = "active" | "suspended" | "lapsed";
export interface ManagedInferencePlan {
    readonly plan: string;
    readonly status: ManagedPlanStatus;
    readonly included_tokens: number;
}
export interface ManagedUsageSummary {
    readonly runs: number;
    readonly input_tokens: number;
    readonly output_tokens: number;
    readonly total_tokens: number;
    readonly included_tokens: number;
    readonly overage_tokens: number;
}
export interface ManagedInferenceBilling {
    readonly plan: ManagedInferencePlan | null;
    /** Stable authority-bound reference used when this plan funds a public release. */
    readonly funding_ref: string | null;
    readonly usage: ManagedUsageSummary;
}

export async function accountDevices(json: RouteJson): Promise<AccountDevice[]> {
    const o = (await json("GET", "/account/devices")) as { devices?: unknown };
    return Array.isArray(o?.devices) ? o.devices.map(parseAccountDevice) : [];
}

export async function accountRevokeDevice(json: RouteJson, id: string): Promise<void> {
    await json("POST", `/account/devices/${encodeURIComponent(id)}/revoke`);
}

/** An out-of-band device-enrollment ticket (ACCT-1, ADR 0055): the rendezvous session,
 *  the account root the new device pins, and the broker both legs dial. Carries no secret —
 *  the trust anchor is the SAS compare + the root-signed delegation. */
export interface EnrollmentTicket {
    readonly session: string;
    readonly account_root: string;
    readonly broker: string;
}

/** One enrollment leg's live status: its phase and the 6-char SAS to compare out-of-band
 *  (never the account key, which crosses only as sealed ciphertext — INV-10). */
export interface EnrollmentStatus {
    readonly phase: string;
    readonly sas: string | null;
    readonly error: string | null;
}

export interface MachineControllerInvitation {
    readonly version: 1;
    readonly invitationId: string;
    readonly secret: string;
    readonly machine: string;
    readonly endpoint: string;
    readonly expiresAt: number;
}

export interface MachineControllerRequest {
    readonly requestId: string;
    readonly device: string;
    readonly publicKey: string;
    readonly label: string;
    readonly proved: true;
    readonly expiresAt: number;
}

export interface MachineController {
    readonly id: string;
    readonly machine: string;
    readonly device: string;
    readonly publicKey: string;
    readonly label: string;
    readonly status: "active" | "revoked";
    readonly enrolledAt: number;
}

export async function mintMachineControllerInvitation(
    json: RouteJson,
    endpoint: string,
): Promise<MachineControllerInvitation> {
    return json("POST", "/mobile/enrollment/invitations", { endpoint }) as Promise<
        MachineControllerInvitation
    >;
}

export async function listMachineControllerRequests(
    json: RouteJson,
): Promise<MachineControllerRequest[]> {
    const response = await json("GET", "/mobile/enrollment/requests") as {
        requests: MachineControllerRequest[];
    };
    return response.requests;
}

export async function approveMachineController(
    json: RouteJson,
    requestId: string,
): Promise<void> {
    await json("POST", `/mobile/enrollment/requests/${encodeURIComponent(requestId)}/approve`, {});
}

export async function rejectMachineController(
    json: RouteJson,
    requestId: string,
): Promise<void> {
    await json("POST", `/mobile/enrollment/requests/${encodeURIComponent(requestId)}/reject`, {});
}

export async function listMachineControllers(json: RouteJson): Promise<MachineController[]> {
    const response = await json("GET", "/mobile/controllers") as {
        controllers: MachineController[];
    };
    return response.controllers;
}

export async function revokeMachineController(
    json: RouteJson,
    controllerId: string,
): Promise<void> {
    await json("POST", `/mobile/controllers/${encodeURIComponent(controllerId)}/revoke`, {});
}

/** Holder: start the enrollment host leg; returns the ticket to show (QR + code). */
export async function enrollHost(json: RouteJson): Promise<EnrollmentTicket> {
    const o = (await json("POST", "/account/devices/enroll/host")) as { ticket: EnrollmentTicket };
    return o.ticket;
}

/** Holder: poll a host leg's phase + SAS after showing the ticket. */
export async function enrollHostStatus(json: RouteJson, session: string): Promise<EnrollmentStatus> {
    return (await json(
        "GET",
        `/account/devices/enroll/host/${encodeURIComponent(session)}`,
    )) as EnrollmentStatus;
}

/** Holder: the human confirmed the SAS matches the new device's — authorize. */
export async function enrollAuthorize(json: RouteJson, session: string): Promise<void> {
    await json("POST", "/account/devices/enroll/authorize", { session });
}

/** New device: consume a ticket and start the join leg; returns the session to poll. */
export async function enrollJoin(json: RouteJson, ticket: EnrollmentTicket): Promise<string> {
    const o = (await json("POST", "/account/devices/enroll/join", { ticket })) as {
        session: string;
    };
    return o.session;
}

/** New device: poll a join leg's phase + SAS (compare with the holder's, then wait). */
export async function enrollJoinStatus(json: RouteJson, session: string): Promise<EnrollmentStatus> {
    return (await json(
        "GET",
        `/account/devices/enroll/join/${encodeURIComponent(session)}`,
    )) as EnrollmentStatus;
}

export async function accountSettings(json: RouteJson): Promise<Record<string, string>> {
    const o = (await json("GET", "/account/settings")) as { settings: Record<string, string> };
    return o.settings;
}

export async function accountSetSetting(
    json: RouteJson,
    key: string,
    value: string,
): Promise<void> {
    await json("PUT", `/account/settings/${encodeURIComponent(key)}`, { value });
}

export async function accountCredentials(json: RouteJson): Promise<LinkedProvider[]> {
    const o = (await json("GET", "/account/credentials")) as { credentials: LinkedProvider[] };
    return o.credentials;
}

export async function accountLinkCredential(
    json: RouteJson,
    provider: string,
    token: string,
    baseUrl?: string,
): Promise<void> {
    // `base_url` is the OpenAI-compatible endpoint for `openai-generic` (ADR 0083),
    // ignored server-side for the fixed-host providers.
    await json("POST", "/account/credentials", { provider, token, base_url: baseUrl });
}

export async function accountUnlinkCredential(json: RouteJson, provider: string): Promise<void> {
    await json("DELETE", `/account/credentials/${encodeURIComponent(provider)}`);
}

export async function accountManagedInference(json: RouteJson): Promise<ManagedInferenceBilling> {
    return (await json("GET", "/account/managed-inference")) as ManagedInferenceBilling;
}

export async function accountSetManagedInference(
    json: RouteJson,
    plan: ManagedInferencePlan,
): Promise<void> {
    await json("POST", "/account/managed-inference", plan);
}

/** The BYOK providers pinned in one project's coordination scope (LLM-2, ADR 0062) — a
 *  per-project override of the account default; provider names only, never the token. */
export async function projectCredentials(
    json: RouteJson,
    project: string,
): Promise<LinkedProvider[]> {
    const o = (await json("GET", `/projects/${encodeURIComponent(project)}/credentials`)) as {
        credentials: LinkedProvider[];
    };
    return o.credentials;
}

/** Pin a provider's BYOK token for one project (sealed server-side, SEC-4). `baseUrl`
 *  is the OpenAI-compatible endpoint for an `openai-generic` pin (ADR 0083). */
export async function linkProjectCredential(
    json: RouteJson,
    project: string,
    provider: string,
    token: string,
    baseUrl?: string,
): Promise<void> {
    await json("POST", `/projects/${encodeURIComponent(project)}/credentials`, {
        provider,
        token,
        base_url: baseUrl,
    });
}

/** Drop a project's pin, so the project falls back to the account default again. */
export async function unlinkProjectCredential(
    json: RouteJson,
    project: string,
    provider: string,
): Promise<void> {
    await json(
        "DELETE",
        `/projects/${encodeURIComponent(project)}/credentials/${encodeURIComponent(provider)}`,
    );
}

/** Codex OAuth (LLM-1, ADR 0062): whether a credential is present in
 *  GaugeDesk's sealed account store and until when (the token is never returned). */
export interface CodexDeviceLogin {
    loginId: string;
    verificationUrl: string;
    userCode: string;
    status: "pending" | "cancelling" | "linked" | "failed" | "cancelled";
    error: string | null;
}

export interface CodexStatus {
    linked: boolean;
    expires: number | null;
    expired: boolean;
    login: CodexDeviceLogin | null;
}

export type CodexLoginStart =
    | { mode: "browser"; url: string }
    | { mode: "device"; login: CodexDeviceLogin };

function deviceLogin(value: unknown): CodexDeviceLogin | null {
    const o = value as Record<string, unknown> | null;
    if (!o || typeof o.login_id !== "string" || typeof o.verification_url !== "string") {
        return null;
    }
    return {
        loginId: o.login_id,
        verificationUrl: o.verification_url,
        userCode: typeof o.user_code === "string" ? o.user_code : "",
        status: (typeof o.status === "string" ? o.status : "failed") as CodexDeviceLogin["status"],
        error: typeof o.error === "string" ? o.error : null,
    };
}

export async function codexStatus(json: RouteJson): Promise<CodexStatus> {
    const o = (await json("GET", "/account/oauth/openai-codex")) as {
        linked?: boolean;
        expires?: number | null;
        expired?: boolean;
        login?: unknown;
    };
    return {
        linked: Boolean(o.linked),
        expires: o.expires ?? null,
        expired: Boolean(o.expired),
        login: deviceLogin(o.login),
    };
}

/** Whether a first-run user must connect an LLM credential before the runtime can
 *  run a turn (ADR 0075 Phase 0). False under the scripted fake agent (dev/e2e),
 *  so the first-run overlay never gates a no-credential test run. Defaults to
 *  `true` (gate on) if the call fails — fail toward showing the setup step. */
export async function onboardingStatus(json: RouteJson): Promise<{ credentialRequired: boolean }> {
    const o = (await json("GET", "/account/onboarding-status")) as { credential_required?: boolean };
    return { credentialRequired: o.credential_required !== false };
}

/** The model a turn runs when the chat pins nothing (LLM-1): the engine's resolved
 *  no-pin default. `model` is null when the resolved provider has no default model
 *  (it then requires an explicit pin). Lets the picker name its "Default" row. */
export async function defaultModel(
    json: RouteJson,
): Promise<{ provider: string; model: string | null }> {
    const o = (await json("GET", "/account/default-model")) as {
        provider?: string;
        model?: string | null;
    };
    return { provider: o.provider ?? "", model: o.model ?? null };
}

/** Start the codex OAuth link; returns the authorize URL to open in a browser. The
 *  server's helper runs the callback server and writes the credential on success —
 *  poll {@link codexStatus} to see it land. */
export async function codexLoginStart(json: RouteJson): Promise<CodexLoginStart> {
    const o = (await json("POST", "/account/oauth/openai-codex/start", {})) as {
        mode?: string;
        url?: string;
        login?: unknown;
    };
    if (o.mode === "browser" && typeof o.url === "string") {
        return { mode: "browser", url: o.url };
    }
    const login = deviceLogin(o.login);
    if (o.mode === "device" && login) return { mode: "device", login };
    throw new Error("OpenAI sign-in returned an unsupported login response");
}

/** Cancel the authenticated person's active hosted device-code attempt. Local
 * browser login does not expose a cancellation endpoint. */
export async function codexLoginCancel(json: RouteJson): Promise<void> {
    await json("POST", "/account/oauth/openai-codex/cancel", {});
}
