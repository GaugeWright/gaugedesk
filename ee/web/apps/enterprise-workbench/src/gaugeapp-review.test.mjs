import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { CLOUD_ADMIN_REVIEW_COMMANDS, REVIEW_COMMANDS, gaugeAppReviewControls, summarizeGaugeAppChange } from "./gaugeapp-review.ts";
import { providerReviewExamples } from "./model-provider-review.fixture.mjs";

test("pending external confirmation cannot be discarded or approved again", () => {
    assert.deepEqual(gaugeAppReviewControls("proposed"), { visible: true, canDiscard: true, confirmationPending: false, actionLabel: "Accept" });
    assert.deepEqual(gaugeAppReviewControls("applying"), { visible: true, canDiscard: false, confirmationPending: true, actionLabel: "Check status" });
    for (const status of ["applied", "rejected", "conflict"]) {
        const controls = gaugeAppReviewControls(status);
        assert.equal(controls.visible, false);
        assert.equal(controls.canDiscard, false);
    }
});

const policy = {
    resource: { rules: [] },
    security: { session_lifetime_secs: 86400, idle_timeout_secs: 1800, audit_retention_min_days: 365, allow_auto_upgrade: false },
    placement: { allowed_operators: ["local", "neutral"] },
    archetype_approval: { require_approval: false },
};
const software = { minimum_version: "1.0.0", minimum_protocol: 1, allowed_channels: ["stable"], grace_until_unix_ms: null };
const member = { id: "member-a", email: "member@example.invalid", role: "member", authority: "person-a", status: "active" };
const organization = { display_name: "Example", owner: { id: "owner-a", email: "owner@example.invalid" }, ownership_candidates: [member] };
const people = { members: [member], invitations: [{ id: "invite-a", email: "invite@example.invalid", role: "viewer" }], projects: [{ id: "project-a", name: "Research" }] };
const sessions = { sessions: [{ id: "session-a", label: "Desktop", current: true }, { id: "session-b", label: "Browser", current: false }] };
const client = { id: "client-a", display_name: "Example Client" };
const commercial = { clients: [{ client }], engagements: [{ id: "engagement-a", client_id: client.id, product_commercial: { listing_title: "Research Analyst" }, entitlement: "active" }] };
const prices = [
    { id: "setup", label: "Setup", kind: "one-time", currency: "usd", amount_cents: 200000, collection: "in-advance" },
    { id: "service", label: "Service", kind: "recurring", currency: "usd", amount_cents: 40000, cadence: "monthly", collection: "in-advance" },
    { id: "seats", label: "Seats", kind: "per-seat", currency: "usd", amount_cents: 3000, cadence: "annual", collection: "in-arrears", minimum_quantity: 2, maximum_quantity: 20 },
    { id: "usage", label: "Usage", kind: "metered-usage", currency: "usd", amount_cents: 3, unit: "1,000 tokens", collection: "in-arrears" },
    { id: "compute", label: "Compute", kind: "cost-plus", currency: "usd", markup_basis_points: 1525, collection: "in-arrears" },
];
const revision = {
    archetype: { id: "agent-a", name: "Research Agent", kind: "agent", version: "7", home_ref: "home-a" },
    sale_version_policy: "pinned-version", listing_title: "Research Analyst", description: "Find traceable evidence.",
    prices, delivery: "customer-project-placement",
    service_obligations: [{ id: "source-review", label: "Source review", description: "Review approved sources", cadence: "Monthly" }],
};
const terms = {
    seats: 3, discount_basis_points: 1250, price_overrides: [], term_months: 12,
    start_rule: "fixed-date", start_at_ms: 1924992000000, renewal: "annual", payment_terms_days: 15,
    valid_until_ms: 1924905600000, proposal_recipients: [{ kind: "account", account_id: "buyer-a", purpose: "Approver" }, { kind: "manual", name: "Billing", email: "billing@example.invalid", purpose: "Billing" }],
    billing_recipient: { kind: "account", account_id: "buyer-a" }, client_note: "Use the approved source set.",
};
const commerce = {
    ...commercial,
    products: [{ id: "product-a", current_revision: 9, commercial: { ...revision, listing_title: "Latest catalog revision" } }],
    engagements: [{ ...commercial.engagements[0], product_id: "product-a", product_revision: 7, terms, product_commercial: revision }],
};
const account = { profile: { account_id: "person-a", display_name: "Original name" }, invitations: [{ tenant_id: "org-a", display_name: "Example Org", role: "member" }], memberships: [{ id: "org-a", display_name: "Example Org", role: "member" }] };
const providers = { connections: [{ id: "connection-a", name: "Personal API", models: ["model-a"] }], default_model: { connection_id: "previous-connection", model: "previous-model" } };
const hosts = { homes: [{ id: "host-a", name: "Research host", kind: "cloud", lifecycle: "active", managed_policy: { isolated_workspace_enabled: false, max_attempt_nanos_usd: 0 } }],
    managed_enrollment: { available: true, region: "test-region", capacity: { storage_bytes: 10000000, concurrent_agents: 2 } } };
// Two hosts, because a handoff review that cannot name where the project comes
// from and where it goes is not a review of anything.
const handoffHosts = { homes: [
    { id: "host-a", home_id: "home-a", name: "Research host", kind: "registered", lifecycle: "active", projects: [{ id: "project-a", name: "Trial results" }] },
    { id: "host-b", home_id: "home-b", name: "Studio Mac", kind: "registered", lifecycle: "active", projects: [] },
], managed_enrollment: { available: false, region: null, capacity: null } };
const backups = {
    facility: { id: "cloud-backup", status: "active", config: { schedule_days: 1, retention_days: 30 } },
    project_host: { id: "host-a", name: "Research host", home_id: "home-a", home_lifecycle: "erased" },
    recipients: [{ id: "holder-a", label: "Owner laptop" }],
    points: [{ handle: "point-a", created_at: 1924819200, bytes: 12000 }],
};

function summary(command, payload, model, overrides = {}) {
    const [app = "administration", pageId = "people"] = REVIEW_COMMANDS[command] ?? [];
    const page = { id: pageId, version: 1, resource_basis: "basis-1", model };
    const proposal = { id: "proposal-a", app, page_id: pageId, command_id: command, expected_basis: "basis-1", payload, ...overrides };
    return summarizeGaugeAppChange(proposal, page);
}

test("a moved page never tells the user to discard an already approved change", () => {
    for (const command of ["organization.display-name.set", "unknown-extension-command"]) {
        const result = summary(command, { display_name: "New name" }, organization, { status: "applying", expected_basis: "old-basis" });
        assert.match(result.unavailable, /remains approved/);
        assert.doesNotMatch(result.unavailable, /Discard|prepare.*again/);
        assert.equal(gaugeAppReviewControls("applying").actionLabel, "Check status");
    }
});

const examples = {
    ...providerReviewExamples,
    "account.profile.set": [{ display_name: "New name" }, account],
    "account.erase": [{ confirmation: "ERASE MY ACCOUNT" }, account],
    "account.invitation.accept": [{ tenant_id: "org-a" }, account],
    "account.invitation.decline": [{ tenant_id: "org-a" }, account],
    "account.membership.leave": [{ tenant_id: "org-a" }, account],
    "provider-connection.rename": [{ id: "connection-a", label: "New provider name" }, providers],
    "provider-connection.default-model.set": [{ connection_id: "connection-a", model: "model-a" }, providers],
    "trusted-device.rename": [{ id: "device-a", label: "Phone" }, { devices: [{ id: "device-a", label: "Old phone" }] }],
    "application-settings.attention.set": [{ value: { version: 1, rules: [
        { signal: "question", attention: "badge" },
        { signal: "conflict", attention: "queue" },
        { signal: "turn-settled", attention: "mute" },
    ] } }, { preferences: { "attention.rules": { version: 1, rules: [] } } }],
    "application-settings.appearance.set": [{ value: {
        version: 1, interface_scale: "large", contrast: "high", motion: "reduced",
    } }, { preferences: { appearance: {
        version: 1, interface_scale: "standard", contrast: "standard", motion: "system",
    } } }],
    "commercial-product.create": [{ id: "product-b", revision }, commerce],
    "commercial-product.revise": [{ id: "product-a", revision }, commerce],
    "commercial-client.create": [{ id: "client-b", display_name: "New Client" }, commerce],
    "commercial-client.edit": [{ id: client.id, display_name: "Renamed Client", billing_reference: "billing-ref-a" }, commerce],
    "commercial-engagement.proposal.create": [{ id: "engagement-b", client_id: client.id, product_id: "product-a", terms }, commerce],
    "commercial-engagement.proposal.save": [{ id: "engagement-a", terms }, commerce],
    "commercial-engagement.proposal.revise": [{ id: "engagement-a", terms }, commerce],
    "commercial-engagement.proposal.send": [{ id: "engagement-a", sent_at_ms: 1924819200000 }, commerce],
    "commercial-engagement.proposal.resend": [{ id: "engagement-a", sent_at_ms: 1924819200000 }, commerce],
    "commercial-engagement.placement.link": [{ id: "engagement-a", placement_ref: "placement-a" }, commerce],
    "commercial-engagement.entitlement.activate": [{ id: "engagement-a", entitlement_ref: "entitlement-a" }, commerce],
    "commercial-engagement.invoice.issue": [{ id: "invoice-a", engagement_id: "engagement-a", billing_email: "billing@example.invalid", days_until_due: 15 }, commerce],
    "project-host.add": [{ kind: "managed", name: "Team host" }, hosts],
    "project-host.rename": [{ id: "host-a", name: "Team host" }, hosts],
    "project-host.suspend": [{ id: "host-a" }, hosts],
    "project-host.reinstate": [{ id: "host-a" }, hosts],
    "project-host.retire": [{ id: "host-a", phase: "retention" }, hosts],
    "project-host.managed-policy.set": [{ id: "host-a", isolated_workspace_enabled: true, max_attempt_nanos_usd: 1500000000 }, hosts],
    "project-home.handoff": [{ project_id: "project-a", expected_current_home_id: "home-a", target_home_id: "home-b" }, handoffHosts],
    "backups.enable": [{ schedule_days: 2, retention_days: 45 }, { ...backups, facility: null }],
    "backups.schedule.set": [{ schedule_days: 2, retention_days: 45 }, backups],
    "backups.disable": [{}, backups],
    "backups.recovery-holder.add": [{ id: "holder-b", label: "This GaugeDesk device", public_key: "public-but-not-presented" }, backups],
    "backups.recovery-holder.remove": [{ id: "holder-a" }, backups],
    "backups.point.create": [{}, backups],
    "backups.restore": [{ point_handle: "point-a" }, backups],
    "subscription.plan.change": [{ quantity: 1 }, {}],
    "subscription.seats.change": [{ quantity: 8 }, { cloud: { subscription: { quantity: 4 } } }],
    "subscription.cancellation.schedule": [{}, { cloud: { subscription: { current_period_end: 1924819200 } } }],
    "subscription.service.add": [{ service: "commercial-operations" }, { cloud: { subscription: { current_period_end: 1924819200 } } }],
    "subscription.service.remove-scheduled": [{ service: "enterprise-controls" }, { cloud: { subscription: { current_period_end: 1924819200 } } }],
    "subscription.service.remove-cancel": [{ service: "commercial-operations" }, { cloud: { subscription: { current_period_end: 1924819200 } } }],
    "project.create": [{ name: "Research" }, {}],
    "organization.display-name.set": [{ display_name: "New Example" }, organization],
    "organization.ownership.transfer": [{ id: member.id }, organization],
    "organization.delete": [{ confirmation: "Example Org" }, organization],
    "organization.domain.add": [{ domain: "example.invalid" }, organization],
    "organization.domain.verify": [{ domain: "example.invalid" }, organization],
    "organization.domain.remove": [{ domain: "example.invalid" }, organization],
    "people.invitation.create": [{ emails: ["one@example.invalid", "two@example.invalid"], role: "member", team: "team-a" }, people],
    "people.invitation.cancel": [{ id: "invite-a" }, people],
    "people.invitation.resend": [{ id: "invite-a" }, people],
    "people.role.change": [{ id: member.id, role: "viewer" }, people],
    "people.member.deactivate": [{ id: member.id }, people],
    "people.member.reactivate": [{ id: member.id }, people],
    "project-access.grant": [{ authority: "person-a", project_id: "project-a" }, people],
    "project-access.revoke": [{ authority: "person-a", project_id: "project-a" }, people],
    "organization-session.revoke": [{ id: "session-a" }, sessions],
    "enterprise-identity.connection.set": [{ protocol: "oidc", issuer: "https://idp.example.invalid", audiences: ["desk"], claim_mapping: { subject_claim: "sub", roles_claim: "roles" } }, { sso: null }],
    "enterprise-identity.admission-mode.set": [{ mode: "verified-domain-jit" }, { admission_mode: "invited-only" }],
    "enterprise-identity.owner-subject.link": [{}, {}],
    "enterprise-identity.enforcement.enable": [{}, { enforcement: { required: false } }],
    "enterprise-identity.enforcement.disable": [{}, { enforcement: { required: true } }],
    "enterprise-identity.scim-credential.issue": [{}, {}],
    "enterprise-identity.scim-credential.rotate": [{}, {}],
    "enterprise-identity.group-mapping.add": [{ group: "engineering", role: "member", team: "team-a" }, {}],
    "enterprise-identity.group-mapping.edit": [{ group: "engineering", role: "viewer", team: null }, {}],
    "enterprise-identity.group-mapping.remove": [{ group: "engineering" }, {}],
    "organization-policy.set": [{ ...policy, security: { ...policy.security, idle_timeout_secs: 3600 } }, policy],
    "software-policy.set": [{ ...software, minimum_version: "2.0.0" }, software],
    "billing.contact.set": [{ name: "Ada Lovelace", email: "billing@example.invalid" }, { billing_contact: { name: "Previous contact", email: "old@example.invalid" } }],
    "account.authenticator.remove": [{ id: "passkey-a", kind: "passkey" }, { authenticators: [{ id: "passkey-a", label: "Laptop passkey" }] }],
    "account.session.revoke-current": [{}, sessions],
    "account.session.revoke": [{ id: "session-b" }, sessions],
    "account.session.revoke-others": [{}, sessions],
    "provider-connection.revoke": [{ id: "connection-a" }, { connections: [{ id: "connection-a", label: "Personal API" }] }],
    "trusted-device.revoke": [{ id: "device-a" }, { devices: [{ id: "device-a", name: "My phone" }] }],
    "commercial-client.close": [{ id: client.id }, commercial],
    "commercial-engagement.proposal.discard": [{ id: "engagement-a" }, commercial],
    "commercial-engagement.proposal.withdraw": [{ id: "engagement-a" }, commercial],
    "commercial-engagement.entitlement.suspend": [{ id: "engagement-a" }, commercial],
    "commercial-engagement.entitlement.revoke": [{ id: "engagement-a" }, commercial],
    "commercial-engagement.close": [{ id: "engagement-a" }, commercial],
    "commercial-payments.invoice.issue": [{ id: "invoice-b", engagement_id: "engagement-a", billing_email: "billing@example.invalid", days_until_due: 30 }, commerce],
    "commercial-payments.payment.refund": [{ id: "refund-a", transaction_id: "payment-a", amount_cents: 12345, reason: "Duplicate" }, { transactions: [{ object_id: "payment-a", currency: "usd" }] }],
};

test("every supported human or agent proposal has a concrete summary example", async (t) => {
    assert.deepEqual(Object.keys(examples).sort(), Object.keys(REVIEW_COMMANDS).sort());
    for (const [command, [payload, model]] of Object.entries(examples)) {
        await t.test(command, () => {
            const result = summary(command, payload, model);
            assert.equal(result.unavailable, undefined);
            assert.ok(result.fields.length > 0, "no blind Accept");
            assert.notEqual(result.title, command);
            assert.ok(result.fields.every((field) => field.label && field.value));
        });
    }
});

test("every immediate command exposed to a management agent has a concrete review summary", () => {
    const source = readFileSync(new URL("../../../../../crates/app/src/gaugeapp_agent.rs", import.meta.url), "utf8");
    const registry = source.match(/pub const AGENT_PROPOSABLE_IMMEDIATE_COMMANDS:[\s\S]*?\n\];/)[0];
    const commands = [...registry.matchAll(/"([^"]+)"/g)].map((match) => match[1]);
    assert.ok(commands.length > 0);
    for (const command of commands) assert.ok(REVIEW_COMMANDS[command], `${command} has no review presentation`);
});

test("product review exposes every price component and included service without inventing a payable total", () => {
    const result = summary("commercial-product.revise", ...examples["commercial-product.revise"]);
    const fields = Object.fromEntries(result.fields.map(({ label, value }) => [label, value]));
    assert.equal(fields.Setup, "USD 2,000.00 once · in advance");
    assert.equal(fields.Service, "USD 400.00 / month · in advance");
    assert.equal(fields.Seats, "USD 30.00 / seat / year · in arrears · minimum 2 · maximum 20");
    assert.equal(fields.Usage, "USD 0.03 / 1,000 tokens · in arrears");
    assert.equal(fields.Compute, "USD usage cost + 15.25% · in arrears");
    assert.equal(fields["Service: Source review"], "Review approved sources · Monthly");
    assert.equal(fields["Commercial revision"], "10");
    assert.match(fields.Agent, /agent-a.*v7/);
    assert.equal(fields["Project Home"], "home-a");
    assert.match(result.note, /Existing proposals.*keep their exact commercial revision/);
    assert.ok(!Object.hasOwn(fields, "Total"));
});

test("commercial review formats processor minor units in their currency", () => {
    const jpyRevision = { ...revision, prices: [{ ...prices[0], currency: "jpy", amount_cents: 500 }] };
    const result = summary("commercial-product.revise", { id: "product-a", revision: jpyRevision }, commerce);
    assert.equal(result.fields.find((field) => field.label === "Setup").value, "JPY 500 once · in advance");
});

test("sending uses the exact pinned proposal terms, not the newer product or ignored payload fields", () => {
    const result = summary("commercial-engagement.proposal.send", { id: "engagement-a", terms: { client_note: "do-not-render" } }, commerce);
    assert.equal(result.unavailable, undefined);
    assert.equal(result.fields.find((f) => f.label === "Product").value, "Research Analyst");
    assert.equal(result.fields.find((f) => f.label === "Commercial revision").value, "7");
    assert.equal(result.fields.find((f) => f.label === "Discount").value, "12.5%");
    assert.equal(result.fields.find((f) => f.label === "Starts").value, "2031-01-01 00:00:00 UTC");
    assert.equal(result.fields.filter((f) => f.label === "Proposal recipient").length, 2);
    assert.match(result.note, /No email is sent/);
    assert.doesNotMatch(JSON.stringify(result), /Latest catalog|do-not-render/);
});

test("an explicit pricing override replaces, rather than adds to, product prices", () => {
    const result = summary("commercial-engagement.proposal.save", { id: "engagement-a", terms: { ...terms, price_overrides: [prices[0]] } }, commerce);
    assert.match(result.fields.find((f) => f.label === "Pricing").value, /Replace/);
    assert.ok(result.fields.some((f) => f.label === "Setup"));
    assert.ok(!result.fields.some((f) => f.label === "Compute"));
    assert.ok(result.fields.some((f) => f.label === "Service: Source review"));
});

test("profile, invitation, provider and device summaries follow the actual server field names", () => {
    assert.equal(summary("account.profile.set", ...examples["account.profile.set"]).fields[0].before, "Original name");
    assert.match(summary("account.invitation.accept", ...examples["account.invitation.accept"]).fields[0].value, /Example Org/);
    assert.equal(summary("trusted-device.rename", ...examples["trusted-device.rename"]).fields[1].before, "Old phone");
    const result = summary("provider-connection.default-model.set", ...examples["provider-connection.default-model.set"]);
    assert.ok(result.fields.some((f) => f.value === "previous-connection"));
    assert.ok(summary("provider-connection.default-model.set", { connection_id: "connection-a", model: "missing" }, providers).unavailable);
});

test("unknown preference payloads are never flattened into a blind approval", () => {
    for (const command of ["account.authenticator.begin-add", "trusted-device.link.accept", "provider-connection.api-key.add", "commercial-payments.connect-component.open"]) {
        assert.ok(summary(command, { secret: "do-not-render" }, {}).unavailable);
    }
});

test("device-local changes cannot be approved as hosted account preferences", () => {
    for (const command_id of ["application-settings.update-channel.set", "application-settings.keep-path.set"]) {
        assert.equal(REVIEW_COMMANDS[command_id], undefined);
        const result = summarizeGaugeAppChange({
            app: "account-settings", page_id: "application-settings", command_id,
            payload: { value: "device-local-value" },
        }, { id: "application-settings", version: 1, model: { preferences: {} } });
        assert.ok(result.unavailable);
        assert.ok(!JSON.stringify(result).includes("device-local-value"));
    }
});

test("new Administration review commands require a presentation here", () => {
    const source = readFileSync(new URL("../../../../app/src/gaugeapp_routes.rs", import.meta.url), "utf8");
    const registry = source.match(/const COMMANDS:[\s\S]*?\n\];/)[0];
    const commands = [...registry.matchAll(/CommandPolicy \{([\s\S]*?)\n    \},/g)]
        .filter((match) => /review: ReviewPolicy::Human,/.test(match[1]))
        .map((match) => match[1].match(/id: "([^"]+)"/)[1]);
    assert.deepEqual(commands.sort(), Object.keys(REVIEW_COMMANDS).filter((id) => REVIEW_COMMANDS[id][0] === "administration" && !Object.hasOwn(CLOUD_ADMIN_REVIEW_COMMANDS, id)).sort());
});

test("Project Host review uses exact targets, current policy and the declared service location", () => {
    const policy = summary("project-host.managed-policy.set", ...examples["project-host.managed-policy.set"]);
    assert.deepEqual(policy.fields.find((field) => field.label === "Maximum per-attempt reservation"), { label: "Maximum per-attempt reservation", value: "USD 1.5", before: "USD 0" });
    const add = summary("project-host.add", ...examples["project-host.add"]);
    assert.equal(add.fields.find((field) => field.label === "Service location").value, "test-region");
    assert.equal(add.fields.find((field) => field.label === "Plan capacity").value, "0.01 GB · 2 concurrent agents");
    assert.ok(summary("project-host.rename", { id: "other-host", name: "Wrong" }, hosts).unavailable);
    assert.ok(summary("project-host.add", { kind: "managed", name: "Team" }, { ...hosts, managed_enrollment: { available: false } }).unavailable);
    assert.match(summary("project-host.suspend", ...examples["project-host.suspend"]).note, /history remains readable/);
    const handoff = summary("project-home.handoff", ...examples["project-home.handoff"]);
    assert.match(handoff.fields.find((field) => field.label === "Project").value, /Trial results/);
    // The host field must carry both ends: `before` is where it leaves from.
    const host = handoff.fields.find((field) => field.label === "Project Host");
    assert.match(host.value, /Studio Mac/);
    assert.match(host.before, /Research host/);
    const retirement = summary("project-host.retire", ...examples["project-host.retire"]);
    assert.equal(retirement.title, "Retire Project Host");
    assert.match(retirement.note, /can be reinstated/);
    const erasure = summary("project-host.retire", { id: "host-a", phase: "erase" }, { ...hosts, homes: [{ ...hosts.homes[0], lifecycle: "retention" }] });
    assert.equal(erasure.title, "Erase Project Host permanently");
    assert.match(erasure.note, /cannot be undone/);
    assert.ok(summary("project-host.retire", { id: "host-a", phase: "erase" }, hosts).unavailable);
});

test("invitation review lists all recipients, role and team without claiming email delivery", () => {
    const result = summary("people.invitation.create", ...examples["people.invitation.create"]);
    assert.equal(result.fields[0].value, "one@example.invalid, two@example.invalid");
    assert.equal(result.fields[1].value, "member");
    assert.equal(result.fields[2].value, "team-a");
    assert.match(result.note, /no email is sent/i);
    const replacement = summary("people.invitation.resend", ...examples["people.invitation.resend"]);
    assert.match(replacement.fields[0].value, /invite@example.invalid/);
    assert.match(replacement.note, /Invalidate the old link/);
});

test("ownership, role and policy changes show exact current and proposed values", () => {
    const owner = summary("organization.ownership.transfer", ...examples["organization.ownership.transfer"]);
    assert.match(owner.fields[0].value, /member@example.invalid/);
    assert.match(owner.fields[1].value, /owner@example.invalid.*→ admin/);
    const deletion = summary("organization.delete", ...examples["organization.delete"]);
    assert.deepEqual(deletion.fields[0], { label: "Organization", value: "Example Org" });
    assert.match(deletion.note, /destroy its content key/);
    const role = summary("people.role.change", ...examples["people.role.change"]);
    assert.deepEqual(role.fields.find((field) => field.label === "Role"), { label: "Role", value: "viewer", before: "member" });
    const result = summary("organization-policy.set", ...examples["organization-policy.set"]);
    assert.equal(result.fields.length, 1, "unchanged policy values do not crowd the review");
    assert.deepEqual(result.fields.find((field) => field.label === "Idle timeout"), { label: "Idle timeout", value: "60 minutes", before: "30 minutes" });
    assert.ok(summary("organization-policy.set", policy, policy).unavailable);
});

test("refund review uses the processor currency and exact minor-unit amount", () => {
    const result = summary("commercial-payments.payment.refund", ...examples["commercial-payments.payment.refund"]);
    assert.equal(result.fields.find((field) => field.label === "Refund amount").value, "USD 123.45");
    assert.equal(result.fields.find((field) => field.label === "Reason").value, "Duplicate");
    const jpy = summary("commercial-payments.payment.refund", { id: "refund-jpy", transaction_id: "payment-jpy", amount_cents: 500, reason: "" }, { transactions: [{ object_id: "payment-jpy", currency: "jpy" }] });
    assert.equal(jpy.fields.find((field) => field.label === "Refund amount").value, "JPY 500");
});

test("engagement closure does not imply cancellation of independent authorities", () => {
    const result = summary("commercial-engagement.close", ...examples["commercial-engagement.close"]);
    assert.ok(result.fields.some((field) => field.value === "Research Analyst"));
    assert.match(result.note, /does not revoke.*stop a deployment.*cancel Stripe billing/);
});

test("SSO metadata is a named inspectable field and does not imply enforcement", () => {
    const result = summary("enterprise-identity.connection.set", { protocol: "saml", metadata: '<EntityDescriptor entityID="example"/>', audiences: [] }, {});
    assert.equal(result.unavailable, undefined);
    assert.equal(result.fields.find((field) => field.label === "IdP metadata XML").expanded, true);
    assert.match(result.note, /without enforcing SSO/);
});

test("unknown payload fields never become displayed data", () => {
    const result = summary("people.invitation.create", { ...examples["people.invitation.create"][0], secret: "should-not-render", nested: { token: "should-not-render" } }, people);
    assert.doesNotMatch(JSON.stringify(result), /should-not-render/);
    const holder = summary("backups.recovery-holder.add", ...examples["backups.recovery-holder.add"]);
    assert.doesNotMatch(JSON.stringify(holder), /public-but-not-presented/);
});

test("stale, wrong-page, wrong-App, unknown and incomplete proposals cannot be accepted blindly", () => {
    for (const override of [{ expected_basis: "old-basis" }, { page_id: "sessions" }, { app: "commercial-operations" }]) {
        assert.ok(summary("people.invitation.create", ...examples["people.invitation.create"], override).unavailable);
    }
    assert.ok(summary("future.secret-change", { secret: "do-not-render" }, {}).unavailable);
    assert.ok(summary("people.role.change", { id: "missing", role: "viewer" }, people).unavailable);
    assert.ok(summary("people.invitation.create", {}, people).unavailable);
    assert.ok(summary("commercial-payments.payment.refund", ...examples["commercial-payments.payment.refund"].map((value, index) => index === 0 ? { ...value, amount_cents: NaN } : value)).unavailable);
});
