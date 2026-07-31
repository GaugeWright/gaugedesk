import type { RouteJson } from "./control-plane-transport";

/** A facility the person (or a tenant) holds — the attach/revoke unit of hosted
 *  functionality (ADR 0077 §7). Provider-agnostic; `config` is opaque here. */
export interface AccountFacility {
    readonly id: string;
    /** `library_sync` | `cloud_backup` | `hosted_home_node` | `registered_host`. */
    readonly kind: string;
    /** `person` (account-level, follows you) | `tenant` (billed to the tenant). */
    readonly owner: string;
    /** `active` | `suspended` | `revoked` — only `active` opens a connection. */
    readonly status: string;
    readonly displayName: string;
}

/** A tenant in the person's switcher (ADR 0077 §9). `personal` marks the
 *  auto-provisioned tenant-of-one — the Console shows it as your own space, not "your org." */
export interface AccountTenant {
    readonly id: string;
    readonly displayName: string;
    readonly role: string;
    readonly personal: boolean;
    /** Server-derived from the tenant's durable consultant/provider kind. */
    readonly providerCommercial: boolean;
}

/** A metadata-only pointer to a pending tenant invitation. The directory owns
 * the invitation; this account projection contains no email, member id, project,
 * invitation secret, or Home endpoint. */
export interface AccountInvitation {
    readonly tenantId: string;
    readonly displayName: string;
    readonly role: string;
}

/** The safe label for the method that authenticated this current browser session.
 * This is not a durable linked-method, recovery, or custody projection. */
export interface AccountSignInMethod {
    readonly method: string;
    readonly label: string;
}

/** Parse one facility record (total: degrades field-by-field, never throws). */
export function parseFacility(v: unknown): AccountFacility {
    const o = (v ?? {}) as Record<string, unknown>;
    return {
        id: typeof o.id === "string" ? o.id : "",
        kind: typeof o.kind === "string" ? o.kind : "library_sync",
        owner: typeof o.owner === "string" ? o.owner : "person",
        status: typeof o.status === "string" ? o.status : "active",
        displayName: typeof o.display_name === "string" ? o.display_name : "",
    };
}

/** Parse one tenant switcher entry (total; never throws). */
export function parseTenant(v: unknown): AccountTenant {
    const o = (v ?? {}) as Record<string, unknown>;
    return {
        id: typeof o.id === "string" ? o.id : "",
        displayName: typeof o.display_name === "string" ? o.display_name : "",
        role: typeof o.role === "string" ? o.role : "",
        personal: o.personal === true,
        providerCommercial: o.provider_commercial === true,
    };
}

/** Parse a pending tenant invitation (total; never throws). */
export function parseInvitation(v: unknown): AccountInvitation {
    const o = (v ?? {}) as Record<string, unknown>;
    return {
        tenantId: typeof o.tenant_id === "string" ? o.tenant_id : "",
        displayName: typeof o.display_name === "string" ? o.display_name : "",
        role: typeof o.role === "string" ? o.role : "",
    };
}

/** Parse the current authenticated sign-in method (total; never throws). */
export function parseAccountSignInMethod(v: unknown): AccountSignInMethod {
    const o = (v ?? {}) as Record<string, unknown>;
    return {
        method: typeof o.method === "string" ? o.method : "",
        label: typeof o.label === "string" ? o.label : "",
    };
}

/** The person's account-level facilities (`GET /account/facilities`). */
export async function accountFacilities(json: RouteJson): Promise<AccountFacility[]> {
    const o = (await json("GET", "/account/facilities")) as { facilities?: unknown[] };
    return Array.isArray(o?.facilities) ? o.facilities.map(parseFacility) : [];
}

/** The current tenant's facility-section metadata. Configuration and opaque
 * handles remain with each facility's owning service. */
export async function tenantFacilities(
    json: RouteJson,
    tenant: string,
): Promise<AccountFacility[]> {
    const o = (await json(
        "GET",
        `/account/tenants/${encodeURIComponent(tenant)}/facilities`,
    )) as { facilities?: unknown[] };
    return Array.isArray(o?.facilities) ? o.facilities.map(parseFacility) : [];
}

/** What `accountAttachFacility` needs; `kind`/`displayName`/`config` are optional. */
export interface AttachFacilityInput {
    id: string;
    kind?: string;
    displayName?: string;
    config?: unknown;
}

/** Attach or update one account-level facility (`POST /account/facilities`). */
export async function accountAttachFacility(
    json: RouteJson,
    input: AttachFacilityInput,
): Promise<AccountFacility> {
    const body: Record<string, unknown> = { id: input.id };
    if (input.kind !== undefined) body.kind = input.kind;
    if (input.displayName !== undefined) body.display_name = input.displayName;
    if (input.config !== undefined) body.config = input.config;
    const o = (await json("POST", "/account/facilities", body)) as { facility?: unknown };
    return parseFacility(o?.facility);
}

/** Detach (revoke) one account-level facility (`DELETE /account/facilities/:id`). */
export async function accountDetachFacility(json: RouteJson, id: string): Promise<void> {
    await json("DELETE", `/account/facilities/${encodeURIComponent(id)}`);
}

/** Publish this device's current sealed account projection through the active
 * library-sync facility. The server owns head discovery, signing, and replay
 * fencing; the browser never handles a root key or ciphertext. */
export async function accountPublishLibrarySync(json: RouteJson): Promise<void> {
    await json("POST", "/account/library-sync");
}

export interface LibrarySyncPullResult {
    readonly found: boolean;
    readonly merged: number;
}

/** Pull and merge the latest root-signed sealed account projection. */
export async function accountPullLibrarySync(
    json: RouteJson,
): Promise<LibrarySyncPullResult> {
    const value = (await json("POST", "/account/library-sync/pull")) as Record<string, unknown>;
    return {
        found: value?.found === true,
        merged: typeof value?.merged === "number" && Number.isFinite(value.merged)
            ? Math.max(0, Math.floor(value.merged))
            : 0,
    };
}

/** The person's tenant switcher (`GET /account/tenants`). */
export async function accountTenants(json: RouteJson): Promise<AccountTenant[]> {
    const o = (await json("GET", "/account/tenants")) as { tenants?: unknown[] };
    return Array.isArray(o?.tenants) ? o.tenants.map(parseTenant) : [];
}

/** Pending workspace invitations for the signed-in person (`GET /account/invitations`). */
export async function accountInvitations(json: RouteJson): Promise<AccountInvitation[]> {
    const o = (await json("GET", "/account/invitations")) as { invitations?: unknown[] };
    return Array.isArray(o?.invitations) ? o.invitations.map(parseInvitation) : [];
}

/** Accept one exact tenant invitation. The browser sends only the tenant id;
 * membership role and activation are derived and authorized by the Hub. */
export async function acceptAccountInvitation(
    json: RouteJson,
    tenantId: string,
): Promise<AccountTenant> {
    const o = (await json(
        "POST",
        `/account/invitations/${encodeURIComponent(tenantId)}/accept`,
    )) as { tenant?: unknown };
    return parseTenant(o?.tenant);
}

/** The method that authenticated the current browser session (`GET /auth/session`). */
export async function accountSignInMethod(json: RouteJson): Promise<AccountSignInMethod> {
    return parseAccountSignInMethod(await json("GET", "/auth/session"));
}

/** Create an organization tenant with the caller as its only active owner. */
export async function createOrganization(
    json: RouteJson,
    displayName: string,
): Promise<AccountTenant> {
    const o = (await json("POST", "/account/tenants", {
        display_name: displayName,
    })) as { tenant?: unknown };
    return parseTenant(o?.tenant);
}
