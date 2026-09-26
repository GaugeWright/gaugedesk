import { describe, expect, expectTypeOf, it } from "vitest";
import {
    parseAdministrationBillingModel,
    parseBackupsModel,
    parseEnterpriseIdentityModel,
    parseOrganizationModel,
    parseOrganizationPolicyModel,
    parseOrganizationSession,
    parsePeopleModel,
    parseAdministrationProjectsModel,
} from "./gaugeapp-administration-models";
import { administrationEmptyModels, cloudBackups, cloudBilling } from "./gaugeapp-administration-models.fixture";

const session = {
    id: "session-a",
    person: { authority: "authority:a", label: "Ada" },
    client_label: "GaugeDesk Desktop",
    client: { version: "0.4.5", protocol: 1, channel: "stable", platform: "linux" },
    state: "active",
    software_status: "current",
    software_reason: "compatible",
    first_seen_unix_ms: 1,
    last_seen_unix_ms: 2,
    age_ms: 1,
    idle_ms: 0,
    current: true,
} as const;

describe("Administration GaugeApp models", () => {
    it("preserves an explicitly unconfigured organization without inventing identity", () => {
        expect(parseOrganizationModel(null, "model")).toBeNull();
        const model = parseOrganizationModel(administrationEmptyModels.organization, "model");
        expectTypeOf(model).toEqualTypeOf<ReturnType<typeof parseOrganizationModel>>();
    });

    it("requires every organization identity and ownership field", () => {
        const populated = {
            ...administrationEmptyModels.organization,
            owner: { id: "member-a", authority: "authority:a", email: "a@example.test", label: "Ada" },
            ownership_candidates: [{ id: "member-b", authority: "authority:b", email: "b@example.test", label: "Babbage", role: "admin" }],
            domains: [{ domain: "example.test", status: "verified", challenge: null }],
        };
        expect(parseOrganizationModel(populated, "model")?.owner?.authority).toBe("authority:a");
        expect(() => parseOrganizationModel({ ...populated, owner: { ...populated.owner, email: undefined } }, "model")).toThrow(/owner.email/);
        expect(() => parseOrganizationModel({ ...populated, domains: [{ domain: "example.test", status: "unknown", challenge: null }] }, "model")).toThrow(/status/);
    });

    it("reads a pending domain with its exact challenge and refuses a partial one", () => {
        const pending = (challenge: unknown) => ({
            ...administrationEmptyModels.organization,
            domains: [{ domain: "example.test", status: "pending", challenge }],
        });
        const challenge = {
            record_name: "_gaugewright-challenge.example.test",
            record_type: "TXT",
            value: "gaugewright-domain-verification=abc",
        };
        expect(parseOrganizationModel(pending(challenge), "model")?.domains[0].challenge).toEqual(challenge);
        // A pending row whose challenge is absent or half-built would render
        // proof instructions the administrator cannot act on, so it is not a
        // model this page accepts.
        expect(() => parseOrganizationModel(pending(undefined), "model")).toThrow(/challenge/);
        expect(() => parseOrganizationModel(pending({ ...challenge, value: undefined }), "model")).toThrow(/challenge.value/);
    });

    it("does not coerce organization-session identity, posture, build, or clocks", () => {
        expect(parseOrganizationSession(session, "session")).toEqual(session);
        for (const replacement of [
            { ...session, state: "ready" },
            { ...session, software_status: "ok" },
            { ...session, current: "true" },
            { ...session, idle_ms: -1 },
            { ...session, client: { ...session.client, protocol: "1" } },
        ]) expect(() => parseOrganizationSession(replacement, "session")).toThrow(/incompatible/);
    });

    it("requires the complete People projection and its admitted project shape", () => {
        const model = {
            ...administrationEmptyModels.people,
            members: [{ id: "member-a", op: "upsert", org_id: "tenant-a", authority: "authority:a", email: "a@example.test", role: "member", status: "active", managed_by_scim: false, team: null }],
            projects: [{ id: "project-a", name: "Research", is_personal: false, home_id: "home-a" }],
            sessions: [session],
        } as const;
        const parsed = parsePeopleModel(model, "model");
        expect(parsed.members[0]?.managed_by_scim).toBe(false);
        expect(parsed.projects[0]?.home_id).toBe("home-a");
        expect(() => parsePeopleModel({ ...model, invitation_delivery: "email" }, "model")).toThrow(/invitation_delivery/);
        expect(() => parsePeopleModel({ ...model, projects: [{ ...model.projects[0], home_id: undefined }] }, "model")).toThrow(/home_id/);
    });

    it("keeps the Projects control index summary-only and explicit about Home availability", () => {
        const project = {
            id: "project-a", name: "Research", authority: "authority:a", is_personal: false,
            home: { id: "home-a", label: "Studio Project Host", state: "active" },
            access_grants: 2, agent_placements: 3, pending_placements: 1,
            work_targets: 2, network_isolated: true, freshness: "home-live",
        } as const;
        const parsed = parseAdministrationProjectsModel({
            ...administrationEmptyModels.projects,
            projects: [project],
        }, "model");
        expect(parsed.projects[0]).toEqual(project);
        expect(parsed.projects[0]).not.toHaveProperty("placements");
        expect(() => parseAdministrationProjectsModel({
            ...administrationEmptyModels.projects,
            projects: [{ ...project, work_targets: undefined }],
        }, "model")).toThrow(/work_targets/);
        expect(parseAdministrationProjectsModel({
            state: "unavailable", reason: "Project Host unavailable", can_create: false,
            home: null, projects: [],
        }, "model").state).toBe("unavailable");
    });

    it("validates the enterprise integration values, SCIM state, and mappings", () => {
        const parsed = parseEnterpriseIdentityModel(administrationEmptyModels["enterprise-identity"], "model");
        expect(parsed.integration.saml.acs_url).toContain("/auth/saml/acs");
        const configured = {
            ...administrationEmptyModels["enterprise-identity"],
            sso: {
                id: "organization", revision: "revision-1", protocol: "oidc", issuer: "https://idp.example.test",
                audiences: ["gaugedesk"], enforce_sso: false, claim_mapping: {
                    subject_claim: "sub", email_claim: null, roles_claim: null, region_claim: null, tenant_claim: null,
                }, metadata_configured: false, client_secret_configured: false,
            },
        } as const;
        expect(parseEnterpriseIdentityModel(configured, "model").sso?.revision).toBe("revision-1");
        const tested = {
            ...configured,
            browser_test: {
                id: "ssotest-1", connection_id: "organization", connection_revision: "revision-1",
                protocol: "oidc", subject: "corporate-subject", mapped_roles: ["engineering"],
                mapped_region: null, mapped_tenant: null, tested_at_ms: 42,
            },
        } as const;
        expect(parseEnterpriseIdentityModel(tested, "model").browser_test?.subject).toBe("corporate-subject");
        expect(() => parseEnterpriseIdentityModel({ ...configured, sso: { ...configured.sso, revision: undefined } }, "model")).toThrow(/revision/);
        expect(() => parseEnterpriseIdentityModel({ ...tested, browser_test: { ...tested.browser_test, mapped_roles: [1] } }, "model")).toThrow(/mapped_roles/);
        expect(() => parseEnterpriseIdentityModel({ ...tested, browser_test: { ...tested.browser_test, connection_revision: "stale" } }, "model")).toThrow(/browser_test/);
        const broken = structuredClone(administrationEmptyModels["enterprise-identity"]) as any;
        delete broken.integration.oidc.redirect_uri;
        expect(() => parseEnterpriseIdentityModel(broken, "model")).toThrow(/redirect_uri/);
        expect(() => parseEnterpriseIdentityModel({ ...administrationEmptyModels["enterprise-identity"], scim: { credential_configured: "false", base_url: "x" } }, "model")).toThrow(/credential_configured/);
        expect(() => parseEnterpriseIdentityModel({
            ...administrationEmptyModels["enterprise-identity"],
            scim: {
                ...administrationEmptyModels["enterprise-identity"].scim,
                status: { last_sync_at_ms: null, errors: [{ operation: "provision", subject: "member@example.test", code: "provider-error", observed_at_ms: 1 }] },
            },
        }, "model")).toThrow(/code/);
    });

    it("keeps absence distinct from zero in organization policy", () => {
        const empty = parseOrganizationPolicyModel(administrationEmptyModels["organization-policy"], "model");
        expect(empty.security).toBeNull();
        const security = { id: "security", op: "upsert", require_mfa: false, session_lifetime_secs: 0, idle_timeout_secs: 0, residency_region: null, audit_retention_min_days: 0, allow_auto_upgrade: false } as const;
        expect(parseOrganizationPolicyModel({ ...administrationEmptyModels["organization-policy"], security }, "model").security?.session_lifetime_secs).toBe(0);
        expect(() => parseOrganizationPolicyModel({ ...administrationEmptyModels["organization-policy"], placement: { require_attested: false, allowed_operators: ["provider"] } }, "model")).toThrow(/allowed_operators/);
    });

    it("requires the processor-reconciled Cloud billing contract when Cloud is present", () => {
        expect(parseAdministrationBillingModel(administrationEmptyModels.billing, "model")).not.toHaveProperty("cloud");
        expect(parseAdministrationBillingModel(cloudBilling, "model").cloud?.verification).toBe("unlinked");
        expect(parseAdministrationBillingModel({
            ...cloudBilling,
            billing_contact: {
                id: "tenant-billing-contact", op: "upsert",
                name: "Ada Lovelace", email: "billing@example.test",
            },
        }, "model").billing_contact?.email).toBe("billing@example.test");
        const broken = structuredClone(cloudBilling) as any;
        delete broken.cloud.customer_linked;
        expect(() => parseAdministrationBillingModel(broken, "model")).toThrow(/customer_linked/);
        const missingContact = structuredClone(cloudBilling) as any;
        delete missingContact.billing_contact;
        expect(() => parseAdministrationBillingModel(missingContact, "model")).toThrow(/billing_contact/);
        const activeService = structuredClone(cloudBilling) as any;
        activeService.services[0] = {
            id: "commercial-operations", status: "active",
            accepted_at_ms: 1_900_000_000_000, removal_effective_at_ms: null,
        };
        expect(parseAdministrationBillingModel(activeService, "model").services[0].status).toBe("active");
        const incompleteServices = structuredClone(activeService) as any;
        incompleteServices.services.pop();
        expect(() => parseAdministrationBillingModel(incompleteServices, "model")).toThrow(/services/);
        const impossibleService = structuredClone(activeService) as any;
        impossibleService.services[0].removal_effective_at_ms = 2_000_000_000_000;
        expect(() => parseAdministrationBillingModel(impossibleService, "model")).toThrow(/commercial-operations/);
        const withDocuments = structuredClone(cloudBilling) as any;
        withDocuments.cloud.customer_linked = true;
        withDocuments.cloud.verification = "verified";
        withDocuments.cloud.subscription = {
            event_id: "evt-plan", event_created: 1, subscription_id: "sub-plan",
            customer_id: "cus-plan", price_id: "price-plan", subscription_item_id: "si-plan",
            quantity: 1, status: "active", storage_bytes: 1, concurrent_agents: 1,
            retention_secs: 1, current_period_end: 2_000_000_000,
            processor_mode: "test", verified_at: 1, cancel_at_period_end: false,
        };
        withDocuments.cloud.documents = {
            freshness: "processor-refreshed", refreshed_at: 1_900_000_000,
            history_complete: true,
            invoices: [{
                id: "in-plan", customer_id: "cus-plan", subscription_id: "sub-plan",
                processor_mode: "test", status: "paid", currency: "usd",
                total_cents: 1200, amount_due_cents: 1200, amount_paid_cents: 1200,
                amount_remaining_cents: 0, created_at: 1_900_000_000, due_at: null,
                hosted_invoice_url: "https://invoice.stripe.com/i/test",
                invoice_pdf: "https://pay.stripe.com/invoice/test/pdf",
            }],
            estimate: {
                id: "upcoming-plan", customer_id: "cus-plan", subscription_id: "sub-plan",
                processor_mode: "test", currency: "usd", total_cents: 1200,
                amount_due_cents: 1200, period_start: 1_900_000_000,
                period_end: 2_000_000_000, lines_complete: true, generated_at: 1_900_000_000,
                lines: [{ description: "GaugeDesk Plus", amount_cents: 1200, currency: "usd", period_start: 1_900_000_000, period_end: 2_000_000_000 }],
            },
        };
        expect(parseAdministrationBillingModel(withDocuments, "model").cloud?.documents.invoices[0].status).toBe("paid");
        const mismatchedEstimate = structuredClone(withDocuments);
        mismatchedEstimate.cloud.documents.estimate.subscription_id = "sub-other";
        expect(() => parseAdministrationBillingModel(mismatchedEstimate, "model")).toThrow(/documents.estimate/);
    });

    it("does not confuse local and Cloud backup inventories", () => {
        expect(parseBackupsModel(administrationEmptyModels.backups, "model")).toEqual(administrationEmptyModels.backups);
        expect(parseBackupsModel(cloudBackups, "model")).toEqual(cloudBackups);
        expect(() => parseBackupsModel({ ...cloudBackups, points: [{ handle: "point-a", created_at: 1 }] }, "model")).toThrow(/bytes/);
        expect(() => parseBackupsModel({ backups: [], recipients: [] }, "model")).toThrow(/recovery_recipients/);
        expect(() => parseBackupsModel({ ...cloudBackups, project_host: { id: "host-a", name: "Host", home_id: "home-a", facility_status: "active" } }, "model")).toThrow(/home_lifecycle/);
        expect(() => parseBackupsModel({ ...cloudBackups, facility: { id: "backup", op: "upsert", kind: "cloud_backup", owner: "tenant", status: "active", display_name: "Backups", config: { schedule_days: 1 } } }, "model")).toThrow(/retention_days/);
        expect(parseBackupsModel({ ...cloudBackups, machine_lifecycle: "active" }, "model")).toEqual(cloudBackups);
    });
});
