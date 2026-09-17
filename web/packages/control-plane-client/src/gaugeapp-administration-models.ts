import {
    arrayOf, booleanValue, integerValue, invalidModel, jsonValue, nullable,
    objectValue, oneOf, shape, stringValue, type GaugeAppJsonValue, type ModelReader,
} from "./gaugeapp-model-validation";
import { parseManagedInferenceUsage, parseSubscriptionBilling, type SubscriptionBilling } from "./gaugeapp-account-models";

const strings = arrayOf(stringValue);
const recordOp = oneOf("upsert", "tombstone");

const organizationPrincipal = shape({
    id: stringValue, authority: stringValue, email: stringValue, label: stringValue,
});
export const parseOrganizationModel = nullable(shape({
    display_name: stringValue,
    kind: oneOf("client", "consultant"),
    owner: nullable(organizationPrincipal),
    ownership_candidates: arrayOf(shape({
        id: stringValue, authority: stringValue, email: stringValue, label: stringValue,
        role: stringValue,
    })),
    // A pending row carries the exact record to publish; a verified one carries
    // null rather than a stale challenge, so the page cannot render proof
    // instructions for a domain that no longer needs them.
    domains: arrayOf(shape({
        domain: stringValue,
        status: oneOf("verified", "pending"),
        challenge: nullable(shape({
            record_name: stringValue, record_type: stringValue, value: stringValue,
        })),
    })),
}));
export type OrganizationPageV1 = ReturnType<typeof parseOrganizationModel>;

export const parseOrganizationSession = shape({
    id: stringValue,
    person: shape({ authority: stringValue, label: stringValue }),
    client_label: stringValue,
    client: shape({
        version: nullable(stringValue), protocol: nullable(integerValue),
        channel: nullable(stringValue), platform: nullable(stringValue),
    }),
    state: oneOf("active", "recovery_only"),
    software_status: oneOf("unmanaged", "current", "warning", "blocked"),
    software_reason: stringValue,
    first_seen_unix_ms: integerValue,
    last_seen_unix_ms: integerValue,
    age_ms: integerValue,
    idle_ms: integerValue,
    current: booleanValue,
});
export type OrganizationSession = ReturnType<typeof parseOrganizationSession>;

const parseAdministrationProjectReference = shape({
    id: stringValue,
    name: stringValue,
    is_personal: booleanValue,
    home_id: stringValue,
});
export const parseAdministrationProject = shape({
    id: stringValue,
    name: stringValue,
    authority: stringValue,
    is_personal: booleanValue,
    home: shape({
        id: stringValue,
        label: stringValue,
        state: oneOf("active", "suspended", "retention", "unavailable"),
    }),
    access_grants: integerValue,
    agent_placements: integerValue,
    pending_placements: integerValue,
    work_targets: integerValue,
    network_isolated: booleanValue,
    freshness: oneOf("home-live", "home-stale", "home-unreachable"),
});
export type AdministrationProject = ReturnType<typeof parseAdministrationProject>;

export const parseOrganizationMember = shape({
    id: stringValue,
    op: recordOp,
    org_id: stringValue,
    authority: stringValue,
    email: stringValue,
    role: stringValue,
    status: oneOf("invited", "active", "deprovisioned"),
    managed_by_scim: booleanValue,
    team: nullable(stringValue),
});
export type OrganizationMember = ReturnType<typeof parseOrganizationMember>;

export const parsePeopleModel = shape({
    members: arrayOf(parseOrganizationMember),
    invitations: arrayOf(shape({
        id: stringValue, email: stringValue, role: stringValue, team: nullable(stringValue),
        status: oneOf("pending", "accepted", "declined", "cancelled", "expired"),
        issued_at_ms: integerValue, expires_at_ms: integerValue,
    })),
    grants: arrayOf(shape({
        id: stringValue, op: recordOp, authority: stringValue, project_id: stringValue,
    })),
    projects: arrayOf(parseAdministrationProjectReference),
    sessions: arrayOf(parseOrganizationSession),
    invitation_delivery: oneOf("one-time-link"),
});
export type PeoplePageV1 = ReturnType<typeof parsePeopleModel>;

export const parseOrganizationSessionsModel = shape({ sessions: arrayOf(parseOrganizationSession) });
export type OrganizationSessionsPageV1 = ReturnType<typeof parseOrganizationSessionsModel>;

const claimMapping = shape({
    subject_claim: nullable(stringValue), email_claim: nullable(stringValue), roles_claim: nullable(stringValue),
    region_claim: nullable(stringValue), tenant_claim: nullable(stringValue),
});
const enterpriseIdentityModel = shape({
    verified_domains: strings,
    sso: nullable(shape({
        id: stringValue, revision: stringValue,
        protocol: oneOf("oidc", "saml"), issuer: stringValue, audiences: strings,
        enforce_sso: booleanValue, claim_mapping: claimMapping, metadata_configured: booleanValue,
        client_secret_configured: booleanValue,
    })),
    browser_test: nullable(shape({
        id: stringValue,
        connection_id: stringValue,
        connection_revision: stringValue,
        protocol: oneOf("oidc", "saml"),
        subject: stringValue,
        mapped_roles: strings,
        mapped_region: nullable(stringValue),
        mapped_tenant: nullable(stringValue),
        tested_at_ms: integerValue,
    })),
    admission_mode: nullable(oneOf("invited-only", "verified-domain-jit", "scim")),
    current_owner: shape({
        is_owner: booleanValue,
        passkey_session: booleanValue,
        subject_linked: booleanValue,
    }),
    enforcement: shape({
        required: booleanValue,
        ready: booleanValue,
        connection_configured: booleanValue,
        domain_verified: booleanValue,
        browser_test_current: booleanValue,
        admission_configured: booleanValue,
        owner_subject_linked: booleanValue,
        owner_recovery_ready: booleanValue,
        second_owner_present: booleanValue,
    }),
    integration: shape({
        base_url: stringValue,
        oidc: shape({ redirect_uri: stringValue, login_url: stringValue }),
        saml: shape({ sp_entity_id: stringValue, acs_url: stringValue, metadata_url: stringValue }),
        scim: shape({ base_url: stringValue }),
    }),
    scim: shape({
        credential_configured: booleanValue,
        base_url: stringValue,
        status: shape({
            last_sync_at_ms: nullable(integerValue),
            errors: arrayOf(shape({
                operation: oneOf("provision", "update", "deprovision"),
                subject: nullable(stringValue),
                code: oneOf("invalid-user-name", "unsupported-change", "unknown-user", "seat-capacity"),
                observed_at_ms: integerValue,
            })),
        }),
    }),
    group_mappings: arrayOf(shape({
        id: stringValue, op: recordOp, group: stringValue, role: stringValue, team: nullable(stringValue),
    })),
});
export const parseEnterpriseIdentityModel: ModelReader<ReturnType<typeof enterpriseIdentityModel>> = (value, path) => {
    const parsed = enterpriseIdentityModel(value, path);
    const test = parsed.browser_test;
    const connection = parsed.sso;
    if (test && (!connection
        || test.connection_id !== connection.id
        || test.connection_revision !== connection.revision
        || test.protocol !== connection.protocol)) return invalidModel(`${path}.browser_test`);
    return parsed;
};
export type EnterpriseIdentityPageV1 = ReturnType<typeof parseEnterpriseIdentityModel>;

const securityPolicy = shape({
    id: stringValue, op: recordOp, require_mfa: booleanValue,
    session_lifetime_secs: integerValue, idle_timeout_secs: integerValue,
    residency_region: nullable(stringValue), audit_retention_min_days: integerValue,
    allow_auto_upgrade: booleanValue,
});
export const parseOrganizationPolicyModel = shape({
    resource: shape({ rules: arrayOf(jsonValue) }),
    security: nullable(securityPolicy),
    placement: shape({
        require_attested: booleanValue,
        allowed_operators: arrayOf(oneOf("local", "counterparty", "neutral")),
    }),
    archetype_approval: shape({ require_approval: booleanValue }),
});
export type OrganizationPolicyPageV1 = ReturnType<typeof parseOrganizationPolicyModel>;

/// The sessions this policy reaches, as `organization-sessions.read-affected`
/// declares on this page. A narrower row than the Sessions page projects: it
/// carries who and what, and none of the timing an administrator reading a
/// policy has no use for. Only `warning` and `blocked` appear, because
/// `unmanaged` and `current` are exactly the sessions the policy does not
/// affect.
export const parseSoftwarePolicyAffectedSession = shape({
    id: stringValue,
    person: shape({ authority: stringValue, label: stringValue }),
    client_label: stringValue,
    client: shape({
        version: nullable(stringValue), protocol: nullable(integerValue),
        channel: nullable(stringValue), platform: nullable(stringValue),
    }),
    software_status: oneOf("warning", "blocked"),
    software_reason: stringValue,
    current: booleanValue,
});

export const parseSoftwarePolicyModel = shape({
    minimum_version: stringValue,
    minimum_protocol: integerValue,
    allowed_channels: arrayOf(oneOf("stable", "beta", "dev")),
    grace_until_unix_ms: nullable(integerValue),
    affected_sessions: arrayOf(parseSoftwarePolicyAffectedSession),
});
export type SoftwarePolicyPageV1 = ReturnType<typeof parseSoftwarePolicyModel>;

export const parseAdministrationProjectsModel = shape({
    state: oneOf("live", "unavailable"),
    reason: nullable(stringValue),
    can_create: booleanValue,
    home: nullable(shape({
        id: stringValue,
        label: stringValue,
        state: oneOf("active", "suspended", "retention", "unavailable"),
    })),
    projects: arrayOf(parseAdministrationProject),
});
export type AdministrationProjectsPageV1 = ReturnType<typeof parseAdministrationProjectsModel>;

const managedPlan = shape({
    plan: stringValue, status: oneOf("active", "suspended", "lapsed"), included_tokens: integerValue,
});
const billingRecord = nullable(shape({
    id: stringValue, op: recordOp, plan: stringValue, seats: integerValue,
    managed_inference: nullable(managedPlan),
}));
const billingContact = nullable(shape({
    id: stringValue, op: recordOp, name: stringValue, email: stringValue,
}));
const tenantService = shape({
    id: oneOf("commercial-operations", "enterprise-controls"),
    status: oneOf("not-added", "active", "removal-scheduled", "ended"),
    accepted_at_ms: nullable(integerValue),
    removal_effective_at_ms: nullable(integerValue),
});
const billingBase = shape({
    billing: billingRecord, billing_contact: billingContact,
    seats_used: integerValue, managed_usage: parseManagedInferenceUsage,
    services: arrayOf(tenantService),
});
export type AdministrationBillingPageV1 = ReturnType<typeof billingBase> & (
    { readonly cloud: SubscriptionBilling } | { readonly cloud?: never }
);
export const parseAdministrationBillingModel: ModelReader<AdministrationBillingPageV1> = (value, path) => {
    const source = objectValue(value, path);
    const base = billingBase(source, path);
    if (base.services.length !== 2
        || new Set(base.services.map(service => service.id)).size !== 2) return invalidModel(`${path}.services`);
    for (const service of base.services) {
        if ((service.status === "not-added" && (service.accepted_at_ms !== null || service.removal_effective_at_ms !== null))
            || (service.status === "active" && (service.accepted_at_ms === null || service.removal_effective_at_ms !== null))
            || (service.status === "removal-scheduled" && (service.accepted_at_ms === null || service.removal_effective_at_ms === null))
            || (service.status === "ended" && (service.accepted_at_ms === null || service.removal_effective_at_ms === null))) {
            return invalidModel(`${path}.services.${service.id}`);
        }
    }
    if (!Object.hasOwn(source, "cloud")) return base;
    return { ...base, cloud: parseSubscriptionBilling(source.cloud, `${path}.cloud`) };
};

const backupFacility = shape({
    id: stringValue, op: recordOp,
    kind: oneOf("cloud_backup"),
    owner: oneOf("tenant"),
    status: oneOf("provisioning", "active", "suspended", "retention", "deleted", "revoked"),
    display_name: stringValue,
    config: shape({ schedule_days: integerValue, retention_days: integerValue }),
});
const localBackups = shape({ backups: arrayOf(jsonValue), recovery_recipients: arrayOf(jsonValue) });
const cloudBackups = shape({
    facility: nullable(backupFacility),
    project_host: nullable(shape({
        id: stringValue,
        name: stringValue,
        home_id: stringValue,
        facility_status: oneOf("provisioning", "active", "suspended", "retention", "deleted", "revoked"),
        home_lifecycle: nullable(oneOf("active", "suspended", "retention", "erased")),
    })),
    recipients: arrayOf(shape({ id: stringValue, label: stringValue, public_key: stringValue })),
    points: arrayOf(shape({ handle: stringValue, created_at: integerValue, bytes: integerValue })),
    restore_receivers: arrayOf(shape({ id: stringValue, point_handle: stringValue, public_key: stringValue })),
});
export type BackupsPageV1 = ReturnType<typeof localBackups> | ReturnType<typeof cloudBackups>;
export const parseBackupsModel: ModelReader<BackupsPageV1> = (value, path) => {
    const source = objectValue(value, path);
    return Object.hasOwn(source, "facility") ? cloudBackups(source, path) : localBackups(source, path);
};

export const administrationPageModels = {
    organization: parseOrganizationModel,
    "plans-services": parseAdministrationBillingModel,
    people: parsePeopleModel,
    sessions: parseOrganizationSessionsModel,
    "enterprise-identity": parseEnterpriseIdentityModel,
    projects: parseAdministrationProjectsModel,
    "organization-policy": parseOrganizationPolicyModel,
    backups: parseBackupsModel,
    "software-policy": parseSoftwarePolicyModel,
    billing: parseAdministrationBillingModel,
} satisfies Record<string, ModelReader<unknown>>;
export type AdministrationDomainPageId = keyof typeof administrationPageModels;
export type AdministrationGaugeAppPageData = {
    readonly [P in AdministrationDomainPageId]: ReturnType<(typeof administrationPageModels)[P]>;
};

// Keep policy rules typed as JSON: clients may preserve accepted rule variants
// they do not presently offer in the narrow editor without treating them as code.
export type OrganizationPolicyRule = GaugeAppJsonValue;
