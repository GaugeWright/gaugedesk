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

/**
 * The hub's route table.
 *
 * **Temporary carve-out (DESK-5c).** ADR 0131 §3 says a client that has not
 * verified the account root's signature must refuse a route's certificate pin,
 * and this table is exactly the unsigned source that rule is about. The refusal
 * is implemented and tested in `home-routing.ts`; it is not applied *here* yet,
 * because no client can currently verify the signed directory record, and
 * flipping this before that lands would silently strip the locators native
 * mobile depends on and take working Homes offline.
 *
 * Removing this argument is the last step of DESK-5c, once clients read and
 * verify the signed record. It is deliberately spelled out rather than left as
 * a default so it cannot be mistaken for the intended posture.
 */
export async function accountHomeRoutes(json: RouteJson): Promise<OpaqueHomeRoute[]> {
    return parseOpaqueHomeRoutes(await json("GET", "/account/home-routes"), "signed");
}

/** Which root signs this account's directory record, and where it lives. */
export interface AccountDirectory {
    readonly rootPubkey: string;
    readonly origin: string;
}

/**
 * Read the account's directory projection (DESK-5f, ADR 0133 §1).
 *
 * A browser cannot reach the root-signed record without this, because the
 * directory is addressed *by* the root key — with no key there is no path to
 * fetch. `null` when the account has published none, which is ordinary rather
 * than exceptional: nobody has run a desktop with library sync on. A caller
 * degrades to endpoint-only reachability there.
 *
 * What comes back is **not** authenticated. Anyone holding the person's bearer
 * can write this record, so the value's whole weight rests on the reader pinning
 * it on first sight and refusing a later change (ADR 0132 §2).
 */
export async function accountDirectory(json: RouteJson): Promise<AccountDirectory | null> {
    let value: unknown;
    try {
        value = await json("GET", "/account/directory");
    } catch {
        // A hub too old to serve it, or an account with none. Both mean the
        // same thing to a caller — no signed record to read — and neither is a
        // reason to fail an account that works without one.
        return null;
    }
    const record = value as { root_pubkey?: unknown; origin?: unknown } | null;
    const rootPubkey = typeof record?.root_pubkey === "string" ? record.root_pubkey.trim() : "";
    if (!rootPubkey) return null;
    const origin = typeof record?.origin === "string" ? record.origin.trim() : "";
    return { rootPubkey, origin: origin.replace(/\/+$/, "") };
}

/**
 * Record reachability an **invitation** delivered into this person's own
 * account. It is deliberately not general route authorship: the serving Home
 * authors the routes for the projects it holds (ADR 0131 §1), and it cannot
 * write into a *different* person's account scope, so accepting an invitation
 * is the one place a client records where a project lives.
 *
 * A relay locator is refused here. A locator carries a certificate pin, and a
 * pin is only as trustworthy as its author (ADR 0131 §3) — a page has no
 * standing to assert one. An invitation therefore delivers an endpoint, whose
 * TLS the browser validates against the public CA set, and nothing a forger
 * would gain from.
 */
export async function accountPublishHomeRoute(
    json: RouteJson,
    route: OpaqueHomeRoute,
): Promise<void> {
    if (route.relay) {
        throw new Error("a client may not publish a Home certificate pin");
    }
    await json("POST", "/account/home-routes", {
        project: route.project,
        home_id: route.homeId,
        endpoint: route.endpoint,
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

// ---------------------------------------------------------------------------
// Desktop → Hub account sign-in: the native device handoff's client half
// (ADR 0123, LOGIN-2). The local control plane custodies the session; these
// routes carry only the one-time code and non-secret projections.

/** Non-secret projection of the desktop's Hub account session. `available` is
 *  false where the runtime has no Hub configured (the UI shows its local-only
 *  wording instead of a sign-in button). */
export interface HubSessionStatus {
    available: boolean;
    linked: boolean;
    person: string | null;
    expires: number | null;
    expired: boolean;
    /** The Hub-minted trusted-device id this session is bound to (LOGIN-3). */
    device: string | null;
}

function hubSessionStatusFrom(value: unknown): HubSessionStatus {
    const o = value as Record<string, unknown> | null;
    return {
        available: Boolean(o?.available),
        linked: Boolean(o?.linked),
        person: typeof o?.person === "string" && o.person ? o.person : null,
        expires: typeof o?.expires === "number" ? o.expires : null,
        expired: Boolean(o?.expired),
        device: typeof o?.device === "string" && o.device ? o.device : null,
    };
}

export async function hubSessionStatus(json: RouteJson): Promise<HubSessionStatus> {
    return hubSessionStatusFrom(await json("GET", "/account/hub-session"));
}

/** Begin the native handoff: the control plane mints and holds the verifier and
 *  returns the Hub login URL to open in the system browser. The flow completes
 *  when the OS deep-links `gaugewright://auth/callback#code=…` back and the code
 *  is posted via {@link hubSessionCallback}. */
export async function hubSessionStart(json: RouteJson): Promise<{ url: string }> {
    const o = (await json("POST", "/account/hub-session/start", {})) as { url?: string };
    if (typeof o.url !== "string" || !o.url) {
        throw new Error("account sign-in returned no login URL");
    }
    return { url: o.url };
}

/** Deliver the deep-linked one-time code; the control plane redeems it with its
 *  held verifier and seals the session. Returns the resulting status. */
export async function hubSessionCallback(
    json: RouteJson,
    code: string,
): Promise<HubSessionStatus> {
    return hubSessionStatusFrom(await json("POST", "/account/hub-session/callback", { code }));
}

/** What the signed-in account can reach (the ADR 0114 composition), read
 *  through the local control plane's Hub proxy: the person, their registered
 *  Homes, and the opaque project-to-Home routes. The bearer stays sealed in
 *  the control plane — this route carries only non-secret projections. */
export interface HubSessionReach {
    person: string;
    device: string;
    homes: AccountHome[];
    routes: OpaqueHomeRoute[];
}

export async function hubSessionReach(json: RouteJson): Promise<HubSessionReach> {
    const o = (await json("GET", "/account/hub-session/reach")) as Record<string, unknown> | null;
    const homesEnvelope = (o?.homes ?? null) as { homes?: unknown } | null;
    const rawHomes = Array.isArray(homesEnvelope?.homes) ? homesEnvelope.homes : [];
    const homes = rawHomes.flatMap((home) => {
        const h = home as Record<string, unknown> | null;
        if (!h || typeof h.id !== "string" || typeof h.endpoint !== "string") return [];
        return [{
            id: h.id as HomeId,
            kind: (typeof h.kind === "string" ? h.kind : "registered") as AccountHomeKind,
            endpoint: h.endpoint,
            // The reach view connects by endpoint; the relay locator is not
            // carried through this display projection.
            relay: null,
        } satisfies AccountHome];
    });
    let routes: OpaqueHomeRoute[] = [];
    try {
        routes = parseOpaqueHomeRoutes(o?.routes ?? { routes: [] });
    } catch {
        // A partial Hub answer (or none) yields an empty reach, not an error.
    }
    return {
        person: typeof o?.person === "string" ? o.person : "",
        device: typeof o?.device === "string" ? o.device : "",
        homes,
        routes,
    };
}

/** Sign out of the GaugeWright account on this desktop. Idempotent. */
export async function hubSessionSignOut(json: RouteJson): Promise<void> {
    await json("POST", "/account/hub-session/logout", {});
}

/** Parse the one-time code out of an OS-delivered native sign-in deep link
 *  (`gaugewright://auth/callback#code=…`). `null` for every other URL — the
 *  caller routes those to the invite path unchanged. Pure, for tests. */
export function parseNativeHandoffCode(url: string): string | null {
    if (!url.startsWith("gaugewright://auth/callback")) return null;
    const hash = url.indexOf("#");
    if (hash < 0) return null;
    const params = new URLSearchParams(url.slice(hash + 1));
    const code = params.get("code");
    return code && code.trim() ? code.trim() : null;
}
