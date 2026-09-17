const usage = {
    runs: 0, input_tokens: 0, output_tokens: 0, total_tokens: 0,
    included_tokens: 0, overage_tokens: 0, unattributed_runs: 0, unattributed_tokens: 0,
};

const services = [
    { id: "commercial-operations", status: "not-added", accepted_at_ms: null, removal_effective_at_ms: null },
    { id: "enterprise-controls", status: "not-added", accepted_at_ms: null, removal_effective_at_ms: null },
] as const;
const billing = { billing: null, billing_contact: null, seats_used: 0, managed_usage: usage, services };

export const administrationEmptyModels = {
    organization: {
        display_name: "Example Organization", kind: "client", owner: null,
        ownership_candidates: [], domains: [],
    },
    "plans-services": billing,
    people: {
        members: [], invitations: [], grants: [], projects: [], sessions: [],
        invitation_delivery: "one-time-link",
    },
    sessions: { sessions: [] },
    "enterprise-identity": {
        verified_domains: [], sso: null, browser_test: null,
        admission_mode: null,
        current_owner: { is_owner: false, passkey_session: false, subject_linked: false },
        enforcement: {
            required: false, ready: false, connection_configured: false,
            domain_verified: false, browser_test_current: false,
            admission_configured: false, owner_subject_linked: false,
            owner_recovery_ready: false, second_owner_present: false,
        },
        integration: {
            base_url: "https://desk.example.test",
            oidc: {
                redirect_uri: "https://desk.example.test/auth/callback",
                login_url: "https://desk.example.test/auth/login",
            },
            saml: {
                sp_entity_id: "https://desk.example.test/saml/metadata",
                acs_url: "https://desk.example.test/auth/saml/acs",
                metadata_url: "https://desk.example.test/saml/metadata",
            },
            scim: { base_url: "https://desk.example.test/scim/v2" },
        },
        scim: {
            credential_configured: false,
            base_url: "https://desk.example.test/scim/v2",
            status: { last_sync_at_ms: null, errors: [] },
        },
        group_mappings: [],
    },
    projects: {
        state: "live", reason: null, can_create: true,
        home: { id: "home-local", label: "This Project Host", state: "active" },
        projects: [],
    },
    "organization-policy": {
        resource: { rules: [] }, security: null,
        placement: { require_attested: false, allowed_operators: [] },
        archetype_approval: { require_approval: false },
    },
    backups: { backups: [], recovery_recipients: [] },
    "software-policy": {
        minimum_version: "", minimum_protocol: 0, allowed_channels: [],
        grace_until_unix_ms: null,
        // One warned session rather than none: an empty list would let a model
        // that carries no sessions at all pass the same assertion, which is the
        // hole this field was added to close.
        affected_sessions: [{
            id: "session-warned",
            person: { authority: "authority:member", label: "member@example.test" },
            client_label: "GaugeDesk desktop",
            client: { version: "0.4.1", protocol: 3, channel: "stable", platform: "macos" },
            software_status: "warning",
            software_reason: "requires GaugeDesk 0.4.5 or newer",
            current: false,
        }],
    },
    billing,
} as const;

export const cloudBilling = {
    ...billing,
    cloud: {
        customer_linked: false,
        subscription: null,
        processor_mode: "test",
        verification: "unlinked",
        configured_plan: { name: "GaugeDesk Cloud", included_tokens: 0, checkout_available: false },
        management: { plan_change: false, seats: false, cancellation: false },
        documents: {
            invoices: [], estimate: null, refreshed_at: null,
            history_complete: false, freshness: "not-refreshed",
        },
        freshness: "processor-reconciled",
    },
} as const;

export const cloudBackups = {
    facility: null,
    project_host: null,
    recipients: [],
    points: [],
    restore_receivers: [],
} as const;
