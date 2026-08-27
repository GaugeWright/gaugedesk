import type { RouteJson } from "@gaugewright/control-plane-client";
import {
    readPlacementPolicy,
    type PlacementPolicy,
} from "@gaugewright/control-plane-client";

export type { PlacementPolicy } from "@gaugewright/control-plane-client";

/** Stable server-derived Administration capabilities (`ADMIN-ENV-2`). The two
 *  owner-only capabilities (`manage_org_lifecycle`, `grant_privileged_roles`) and the
 *  read-only `auditor` role's `view_audit` are the ADR 0149 separation-of-duties
 *  split; these names mirror `crate::core::rbac::Capability::as_str`. */
export type AdminCapability =
    | "manage_org_lifecycle"
    | "grant_privileged_roles"
    | "edit_org_settings"
    | "manage_members"
    | "configure_sso"
    | "configure_provisioning"
    | "view_audit"
    | "configure_security"
    | "manage_billing";

export type AdminAgentTool =
    | "admin.files.list"
    | "admin.files.read"
    | "admin.homes.query"
    | "admin.changes.propose"
    | "question.ask";

/** Fail-closed server projection for the Admin Session's non-chat abilities. */
export interface AdminAgentCapabilities {
    readonly message_attachments: boolean;
    readonly additional_tools: boolean;
    readonly tools: readonly AdminAgentTool[];
}

export interface AdminCapabilityDiscovery {
    readonly capabilities: readonly AdminCapability[];
    readonly agent: AdminAgentCapabilities;
}

/** Org profile + defaults (B10). */
export interface OrgSettings {
    readonly display_name: string;
    readonly verified_domains: string[];
    readonly default_region?: string | null;
    readonly kind: "client" | "consultant";
}
/** A directory member (B11). */
export interface Member {
    readonly id: string;
    readonly authority: string;
    readonly email: string;
    readonly role: string;
    readonly status: string;
    readonly managed_by_scim: boolean;
}
/** Which id-token claims carry the ABAC attributes the verifier maps (B12 / `ID-3`).
 *  All optional — unset falls back to the `GAUGEDESK_OIDC_*_CLAIM` env knob, else
 *  unmapped (subject defaults to `sub`). */
export interface SsoClaimMapping {
    readonly subject_claim?: string | null;
    readonly roles_claim?: string | null;
    readonly region_claim?: string | null;
    readonly tenant_claim?: string | null;
}
/** The SP-side values an admin pastes into their IdP to connect us (`ONB-1`). */
export interface IntegrationDetails {
    readonly base_url: string;
    readonly oidc: { readonly redirect_uri: string; readonly login_url: string };
    readonly saml: {
        readonly sp_entity_id: string;
        readonly acs_url: string;
        readonly metadata_url: string;
        readonly status: string;
    };
    readonly scim: { readonly base_url: string };
}
/** SSO connection (B12). */
export interface SsoConnection {
    readonly protocol: string;
    readonly issuer: string;
    readonly audiences: string[];
    readonly metadata: string;
    readonly enforce_sso: boolean;
    /** How id-token claims map onto ABAC attributes (`ID-3`). */
    readonly claim_mapping?: SsoClaimMapping;
}
/** Security policy (B15). */
export interface SecurityPolicy {
    readonly require_mfa: boolean;
    readonly session_lifetime_secs: number;
    readonly idle_timeout_secs: number;
    readonly residency_region?: string | null;
    /** Minimum audit-retention guarantee in days (AUD-3); `0`/unset ⇒ the published default
     *  (365). A promise floor — the log is kept forever — not a delete policy. */
    readonly audit_retention_min_days?: number;
    /** Whether this org accepts auto-upgrades of archetypes its placements use (UX-9, ADR
     *  0062). Default false — an archetype owner's auto preference falls back to manual here. */
    readonly allow_auto_upgrade?: boolean;
}
/** The org's archetype-approval policy (ADR 0063): the org-level default projects inherit
 *  for whether adding an archetype requires owner approval. */
export interface ArchetypeApprovalPolicy {
    readonly require_approval: boolean;
}
/** Org deployment placement policy (DEPLOY-2): admissible `(operator, attested)` modes for
 *  engagements touching this org's data. Restrict-only; empty `allowed_operators` = all. */
/** Organization client/session compatibility floor (`ITGOV-4`). */
export interface SoftwarePolicy {
    readonly minimum_version: string;
    readonly minimum_protocol: number;
    readonly allowed_channels: ReadonlyArray<"stable" | "beta" | "dev">;
    readonly grace_until_unix_ms?: number | null;
}
/** Billing/seat state (B16). `billing.update` replaces the whole record, so every
 *  field is required on the wire — an omitted `managed_inference` would drop the
 *  org-funded subscription rather than preserve it. `null` is how it is cleared. */
export interface Billing {
    readonly plan: string;
    readonly seats: number;
    readonly managed_inference: {
        readonly plan: string;
        readonly status: "active" | "suspended" | "lapsed";
        readonly included_tokens: number;
    } | null;
}
export interface ManagedUsageSummary {
    readonly runs: number;
    readonly input_tokens: number;
    readonly output_tokens: number;
    readonly total_tokens: number;
    readonly included_tokens: number;
    readonly overage_tokens: number;
}
/** One audit-timeline entry (B14). */
export interface AdminAuditEntry {
    readonly actor: string;
    readonly action: string;
    readonly target: string;
}

/** An admitted member-to-project access grant (`ENTSEC-2`). */
export interface MemberGrant {
    readonly id: string;
    readonly authority: string;
    readonly project_id: string;
}

/** Result of walking and, when present, checkpoint-verifying the audit chain. */
export interface AuditIntegrity {
    readonly ok: boolean;
    readonly entries: number;
    readonly head: string;
    readonly broken_at: number | null;
    readonly anchored: boolean;
}

export type AuditExportFormat = "csv" | "json";

export interface AuditExport {
    readonly format: AuditExportFormat;
    readonly body: string;
    readonly contentType: string;
    readonly filename: string;
}

export interface AdminPlacementProjection {
    readonly id: string;
    readonly archetype_id: string;
    readonly archetype_name: string;
    readonly version: number;
    readonly current_version: number;
    readonly upgrade_available: boolean;
    readonly pending: boolean;
}

export interface AdminProjectProjection {
    readonly id: string;
    readonly name: string;
    readonly network_isolated: boolean;
    readonly placements: AdminPlacementProjection[];
}

export interface AdminMachineExecutionProfile {
    readonly available: boolean;
    readonly enabled_by_tenant_policy?: boolean;
    readonly capabilities: readonly string[];
    readonly compute_state: string;
    readonly metering: {
        readonly kind: "included" | "usage" | "unavailable";
        readonly reservation_nanos_usd?: number | null;
        readonly nanos_usd_per_second?: number | null;
    };
    readonly reason?: string | null;
}

export interface AdminMachineExecutionProjection {
    readonly freshness: string;
    readonly selection_policy: "exact_capability_match_no_fallback";
    readonly profiles: {
        readonly durable_workflow: AdminMachineExecutionProfile;
        readonly isolated_workspace: AdminMachineExecutionProfile;
        readonly dedicated_compute: AdminMachineExecutionProfile;
    };
    readonly queue: {
        readonly total: number;
        readonly by_phase: Readonly<Record<string, number>>;
        readonly by_profile: Readonly<Record<string, number>>;
    };
    readonly compute: {
        readonly state: string;
        readonly active_attempts: number;
        readonly wake: "on_demand";
        readonly idle_behavior?: string;
    };
    readonly usage: {
        readonly billable_nanos_usd: number;
        readonly charged_nanos_usd: number;
        readonly wall_millis: number;
    };
    readonly failures: readonly {
        readonly command_id: string;
        readonly profile: string;
        readonly phase: string;
        readonly attempt: number;
        readonly observed_at: number;
    }[];
}

/** One target-admitted Home projection. A non-live state carries no projects. */
export interface AdminHomeProjection {
    readonly id: string;
    readonly kind: "local" | "registered" | "cloud";
    readonly endpoint: string;
    readonly state: "live" | "stale" | "partial" | "redacted" | "indeterminate" | "unreachable" | "identity_mismatch";
    /** Commercial/operational lifecycle is distinct from target-admitted
     * inventory freshness. Present for managed machines only. */
    readonly lifecycle?: "provisioning" | "active" | "suspended" | "retention" | "deleted";
    readonly repair_hint: string | null;
    readonly projects: AdminProjectProjection[];
    /** Home-admitted managed execution status; present only for managed Machines. */
    readonly execution?: AdminMachineExecutionProjection;
}

export interface EnterpriseAdminApi {
    adminCapabilities(): Promise<AdminCapabilityDiscovery>;
    adminIntegration(): Promise<IntegrationDetails>;
    adminTestSso(s: SsoConnection): Promise<{ ok: boolean; detail: string }>;
    exportAdministrationAudit(
        format: AuditExportFormat,
        filters?: { readonly actor?: string; readonly action?: string },
    ): Promise<AuditExport>;
}

export async function adminCapabilities(json: RouteJson): Promise<AdminCapabilityDiscovery> {
    const value = (await json("GET", "/admin/capabilities")) as {
        capabilities?: AdminCapability[];
        agent?: Partial<AdminAgentCapabilities>;
    };
    return {
        capabilities: Array.isArray(value.capabilities) ? value.capabilities : [],
        agent: {
            message_attachments: value.agent?.message_attachments === true,
            additional_tools: value.agent?.additional_tools === true,
            tools: Array.isArray(value.agent?.tools) ? value.agent.tools : [],
        },
    };
}

/** Active-member read consumed by the enrolled workbench before engagement admission. */
export function placementPolicy(json: RouteJson): Promise<PlacementPolicy> {
    return readPlacementPolicy(json);
}

/** One live session in the IT roster (ITGOV-2): the active member's authority + how long
 *  since first-seen (`age_ms`) / last-seen (`idle_ms`). Never carries a bearer. */
export interface Session {
    readonly authority: string;
    readonly age_ms: number;
    readonly idle_ms: number;
    readonly client: {
        readonly version?: string | null;
        readonly protocol?: number | null;
        readonly channel?: string | null;
        readonly platform?: string | null;
    };
    readonly software_status: "unmanaged" | "current" | "warning" | "blocked";
    readonly software_reason: string;
}

/** The SP-side integration values an admin pastes into their IdP (`ONB-1`). */
export async function adminIntegration(json: RouteJson): Promise<IntegrationDetails> {
    return (await json("GET", "/admin/integration")) as IntegrationDetails;
}

/** Live OIDC discovery+JWKS reachability test of a connection (`ONB-3`); not stored. */
export async function adminTestSso(
    json: RouteJson,
    s: SsoConnection,
): Promise<{ ok: boolean; detail: string }> {
    return (await json("POST", "/admin/sso/test", s)) as { ok: boolean; detail: string };
}
