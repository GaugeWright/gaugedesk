import type { GaugeAppPageModel, GaugeAppProposal } from "@gaugewright/control-plane-client";
import { ATTENTION_SIGNALS, parseAttentionRules } from "@gaugewright/workbench-ui/attention";
import { commercialMoney } from "./commercial-page-presentation.ts";
import { MODEL_PROVIDER_REVIEW_COMMANDS, summarizeProviderChange, type ProviderCommand } from "./model-provider-presentation.ts";
import { hostBytes } from "./project-host-presentation.ts";

type Data = Record<string, unknown>;

// Pure presentation of server-owned state. An approved external effect is not
// an editable proposal, even if its response is lost or its page basis moves.
export function gaugeAppReviewControls(status: GaugeAppProposal["status"]) {
    return {
        visible: status === "proposed" || status === "applying",
        canDiscard: status === "proposed",
        confirmationPending: status === "applying",
        actionLabel: status === "applying" ? "Check status" : "Accept",
    };
}

export interface ReviewField {
    readonly label: string;
    readonly value: string;
    readonly before?: string;
    readonly expanded?: boolean;
}
export interface ChangeSummary {
    readonly title: string;
    readonly fields: readonly ReviewField[];
    readonly note?: string;
    readonly unavailable?: string;
}

// Presentation only. These are not capabilities or a mutation schema. The
// admitted proposal and current page come from the server; review still uses
// that proposal's id and basis. Never stringify arbitrary payload properties.
export const CLOUD_ADMIN_REVIEW_COMMANDS = {
    ...MODEL_PROVIDER_REVIEW_COMMANDS,
    "project-host.add": ["administration", "project-hosts", "Add managed Project Host"],
    "project-host.rename": ["administration", "project-hosts", "Rename Project Host"],
    "project-host.managed-policy.set": ["administration", "project-hosts", "Change compute policy"],
    "project-host.suspend": ["administration", "project-hosts", "Suspend Project Host"],
    "project-host.reinstate": ["administration", "project-hosts", "Reinstate Project Host"],
    "project-host.retire": ["administration", "project-hosts", "Retire Project Host"],
    "backups.enable": ["administration", "backups", "Turn on backups"],
    "backups.schedule.set": ["administration", "backups", "Change backup schedule"],
    "backups.disable": ["administration", "backups", "Pause backups"],
    "backups.recovery-holder.add": ["administration", "backups", "Add recovery holder"],
    "backups.recovery-holder.remove": ["administration", "backups", "Remove recovery holder"],
    "backups.point.create": ["administration", "backups", "Create recovery point"],
    "backups.restore": ["administration", "backups", "Restore Project Host"],
    "subscription.plan.change": ["administration", "plans-services", "Change organization plan"],
    "subscription.seats.change": ["administration", "plans-services", "Change purchased seats"],
    "subscription.cancellation.schedule": ["administration", "plans-services", "Schedule plan cancellation"],
    "subscription.service.add": ["administration", "plans-services", "Add organization service"],
    "subscription.service.remove-scheduled": ["administration", "plans-services", "Schedule service removal"],
    "subscription.service.remove-cancel": ["administration", "plans-services", "Keep organization service"],
} as const;
export const REVIEW_COMMANDS = {
    ...CLOUD_ADMIN_REVIEW_COMMANDS,
    "project-home.handoff": ["administration", "project-hosts", "Move a project to another Project Host"],
    "project.create": ["administration", "projects", "Create project"],
    "organization.display-name.set": ["administration", "organization", "Change organization name"],
    "organization.ownership.transfer": ["administration", "organization", "Transfer ownership"],
    "organization.delete": ["administration", "organization", "Delete organization"],
    "organization.domain.add": ["administration", "organization", "Add domain"],
    "organization.domain.verify": ["administration", "organization", "Verify domain"],
    "organization.domain.remove": ["administration", "organization", "Remove domain"],
    "people.invitation.create": ["administration", "people", "Invite people"],
    "people.invitation.cancel": ["administration", "people", "Cancel invitation"],
    "people.invitation.resend": ["administration", "people", "Replace invitation link"],
    "people.role.change": ["administration", "people", "Change member role"],
    "people.member.deactivate": ["administration", "people", "Deactivate member"],
    "people.member.reactivate": ["administration", "people", "Reactivate member"],
    "project-access.grant": ["administration", "people", "Grant project access"],
    "project-access.revoke": ["administration", "people", "Revoke project access"],
    "organization-session.revoke": ["administration", "sessions", "Revoke organization session"],
    "enterprise-identity.connection.set": ["administration", "enterprise-identity", "Save sign-in connection"],
    "enterprise-identity.admission-mode.set": ["administration", "enterprise-identity", "Change member admission"],
    "enterprise-identity.owner-subject.link": ["administration", "enterprise-identity", "Link owner sign-in"],
    "enterprise-identity.enforcement.enable": ["administration", "enterprise-identity", "Require corporate sign-in"],
    "enterprise-identity.enforcement.disable": ["administration", "enterprise-identity", "Stop requiring corporate sign-in"],
    "enterprise-identity.scim-credential.issue": ["administration", "enterprise-identity", "Issue provisioning credential"],
    "enterprise-identity.scim-credential.rotate": ["administration", "enterprise-identity", "Rotate provisioning credential"],
    "enterprise-identity.group-mapping.add": ["administration", "enterprise-identity", "Add group mapping"],
    "enterprise-identity.group-mapping.edit": ["administration", "enterprise-identity", "Change group mapping"],
    "enterprise-identity.group-mapping.remove": ["administration", "enterprise-identity", "Remove group mapping"],
    "organization-policy.set": ["administration", "organization-policy", "Change organization policy"],
    "software-policy.set": ["administration", "software-policy", "Change software policy"],
    "billing.contact.set": ["administration", "billing", "Change billing contact"],
    "account.profile.set": ["account-settings", "account", "Change your name"],
    "account.erase": ["account-settings", "account", "Delete account"],
    "account.invitation.accept": ["account-settings", "account", "Join organization"],
    "account.invitation.decline": ["account-settings", "account", "Decline invitation"],
    "account.membership.leave": ["account-settings", "account", "Leave organization"],
    "account.authenticator.remove": ["account-settings", "account", "Remove sign-in method"],
    "account.session.revoke-current": ["account-settings", "account", "Sign out this session"],
    "account.session.revoke": ["account-settings", "account", "Sign out session"],
    "account.session.revoke-others": ["account-settings", "account", "Sign out other sessions"],
    "provider-connection.revoke": ["account-settings", "provider-connections", "Revoke provider connection"],
    "provider-connection.rename": ["account-settings", "provider-connections", "Rename connection"],
    "provider-connection.default-model.set": ["account-settings", "provider-connections", "Change default model"],
    "trusted-device.rename": ["account-settings", "trusted-devices", "Rename trusted device"],
    "trusted-device.revoke": ["account-settings", "trusted-devices", "Revoke trusted device"],
    "application-settings.attention.set": ["account-settings", "application-settings", "Change attention preference"],
    "application-settings.appearance.set": ["account-settings", "application-settings", "Change appearance preference"],
    "commercial-product.create": ["commercial-operations", "products", "Create product"],
    "commercial-product.revise": ["commercial-operations", "products", "Revise product"],
    "commercial-client.create": ["commercial-operations", "clients", "Create client"],
    "commercial-client.edit": ["commercial-operations", "clients", "Edit client"],
    "commercial-client.close": ["commercial-operations", "clients", "Close client"],
    "commercial-engagement.proposal.create": ["commercial-operations", "engagements", "Create draft proposal"],
    "commercial-engagement.proposal.save": ["commercial-operations", "engagements", "Save draft proposal"],
    "commercial-engagement.proposal.revise": ["commercial-operations", "engagements", "Revise sent proposal"],
    "commercial-engagement.proposal.send": ["commercial-operations", "engagements", "Send proposal"],
    "commercial-engagement.proposal.resend": ["commercial-operations", "engagements", "Replace proposal links"],
    "commercial-engagement.placement.link": ["commercial-operations", "engagements", "Link placement"],
    "commercial-engagement.entitlement.activate": ["commercial-operations", "engagements", "Activate engagement access"],
    "commercial-engagement.invoice.issue": ["commercial-operations", "engagements", "Issue invoice"],
    "commercial-engagement.proposal.discard": ["commercial-operations", "engagements", "Discard draft proposal"],
    "commercial-engagement.proposal.withdraw": ["commercial-operations", "engagements", "Withdraw proposal"],
    "commercial-engagement.entitlement.suspend": ["commercial-operations", "engagements", "Suspend engagement access"],
    "commercial-engagement.entitlement.revoke": ["commercial-operations", "engagements", "Revoke engagement access"],
    "commercial-engagement.close": ["commercial-operations", "engagements", "Close engagement"],
    "commercial-payments.invoice.issue": ["commercial-operations", "payments", "Issue invoice"],
    "commercial-payments.payment.refund": ["commercial-operations", "payments", "Refund payment"],
} as const;

const data = (value: unknown): Data => {
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Missing record");
    return value as Data;
};
const optionalData = (value: unknown): Data => value == null ? {} : data(value);
const string = (value: unknown): string => {
    if (typeof value !== "string" || !value.trim()) throw new Error("Missing value");
    return value.trim();
};
const optionalText = (value: unknown, fallback = "Not set"): string =>
    value == null || value === "" ? fallback : string(value);
const number = (value: unknown): number => {
    if (typeof value !== "number" || !Number.isFinite(value)) throw new Error("Missing number");
    return value;
};
const nanoDollars = (value: unknown): string => {
    const amount = number(value);
    if (!Number.isSafeInteger(amount) || amount < 0) throw new Error("Invalid compute cap");
    const digits = BigInt(amount).toString().padStart(10, "0");
    return `USD ${digits.slice(0, -9)}.${digits.slice(-9)}`.replace(/0+$/, "").replace(/\.$/, "");
};
const list = (value: unknown): unknown[] => {
    if (!Array.isArray(value)) throw new Error("Missing list");
    return value;
};
const strings = (value: unknown, empty = "None"): string => list(value).map(string).join(", ") || empty;
const enabled = (value: unknown): string => {
    if (typeof value !== "boolean") throw new Error("Missing choice");
    return value ? "Yes" : "No";
};
const stamp = (value: unknown): string => {
    const time = number(value);
    if (!time) return "Immediate";
    return new Date(time).toISOString().replace("T", " ").replace(".000Z", " UTC");
};
const recordIn = (values: unknown, id: string, key = "id"): Data => {
    const result = list(values).map(data).find((value) => value[key] === id);
    if (!result) throw new Error("Target is no longer in the page");
    return result;
};
const label = (record: Data, id: string): string => {
    const name = [record.email, record.label, record.display_name, record.name, record.authority]
        .find((value) => typeof value === "string" && value.trim());
    return name && name !== id ? `${string(name)} (${id})` : id;
};

const choice = (value: unknown, labels: Readonly<Record<string, string>>): string => {
    const key = string(value);
    if (!Object.hasOwn(labels, key)) throw new Error("Unknown choice");
    return labels[key];
};
// Descriptions, not a second pricing engine: never calculate a payable total
// here. The settlement authority owns quantities, rounding and charge basis.
const priceFields = (values: unknown): ReviewField[] => list(values).map((value) => {
    const price = data(value);
    const currency = string(price.currency).toUpperCase();
    const money = () => commercialMoney(number(price.amount_cents), currency);
    const cadence = () => choice(price.cadence, { monthly: "month", annual: "year" });
    let amount: string;
    switch (price.kind) {
        case "one-time": amount = `${money()} once`; break;
        case "recurring": amount = `${money()} / ${cadence()}`; break;
        case "per-seat": amount = `${money()} / seat / ${cadence()}`; break;
        case "metered-usage": amount = `${money()} / ${string(price.unit)}`; break;
        case "cost-plus": amount = `${currency} usage cost + ${number(price.markup_basis_points) / 100}%`; break;
        default: throw new Error("Unknown price kind");
    }
    const parts = [amount, choice(price.collection, { "in-advance": "in advance", "in-arrears": "in arrears" })];
    if (price.cadence != null && price.kind !== "recurring" && price.kind !== "per-seat") parts.push(`per ${cadence()}`);
    if (price.unit && price.kind !== "metered-usage") parts.push(`unit: ${string(price.unit)}`);
    if (price.minimum_quantity != null) parts.push(`minimum ${number(price.minimum_quantity)}`);
    if (price.maximum_quantity != null) parts.push(`maximum ${number(price.maximum_quantity)}`);
    return { label: string(price.label), value: parts.join(" · ") };
});
const serviceFields = (values: unknown): ReviewField[] => {
    const services = list(values ?? []).map(data);
    return services.length ? services.map((service) => ({
        label: `Service: ${string(service.label)}`,
        value: [optionalText(service.description, ""), optionalText(service.cadence, "")].filter(Boolean).join(" · ") || "Included",
    })) : [{ label: "Services included", value: "None" }];
};
const recipient = (value: unknown): string => {
    const record = data(value);
    const identity = record.kind === "account" ? `Account ${string(record.account_id)}`
        : record.kind === "manual" ? `${string(record.name)} <${string(record.email)}>`
            : (() => { throw new Error("Unknown recipient kind"); })();
    return record.purpose ? `${identity} · ${string(record.purpose)}` : identity;
};
const delivery = (value: unknown): string => choice(value, {
    "provider-hosted-panel": "Provider-hosted Panel access",
    "customer-project-placement": "Placement in a customer project",
});
const termsFields = (value: unknown, product: Data): ReviewField[] => {
    const terms = data(value);
    const overrides = list(terms.price_overrides ?? []);
    return [
        { label: "Pricing", value: overrides.length ? "Replace product prices with these charges" : "Use this product revision's prices" },
        ...priceFields(overrides.length ? overrides : product.prices),
        { label: "Seats", value: terms.seats == null ? "Not set" : String(number(terms.seats)) },
        { label: "Discount", value: `${number(terms.discount_basis_points ?? 0) / 100}%` },
        { label: "Term", value: terms.term_months == null ? "No fixed term" : `${number(terms.term_months)} months` },
        { label: "Starts", value: terms.start_rule === "fixed-date" ? stamp(terms.start_at_ms)
            : choice(terms.start_rule, { "on-acceptance": "On acceptance" }) },
        { label: "Renewal", value: choice(terms.renewal, { none: "None", "month-to-month": "Month to month", annual: "Annual" }) },
        { label: "Payment terms", value: `${number(terms.payment_terms_days ?? 30)} days` },
        { label: "Valid through", value: stamp(terms.valid_until_ms) },
        ...list(terms.proposal_recipients).map((value) => ({ label: "Proposal recipient", value: recipient(value) })),
        { label: "Billing recipient", value: recipient(terms.billing_recipient) },
        { label: "Client note", value: optionalText(terms.client_note, "None") },
        { label: "Delivery", value: delivery(product.delivery) },
        ...serviceFields(product.service_obligations),
    ];
};

/** Explicit, safe presentation of the proposal already admitted by the server. */
export function summarizeGaugeAppChange(proposal: GaugeAppProposal, page: GaugeAppPageModel): ChangeSummary {
    const definition = REVIEW_COMMANDS[proposal.command_id as keyof typeof REVIEW_COMMANDS];
    const unavailable = (reason: string): ChangeSummary => ({
        title: definition?.[2] ?? (proposal.status === "applying" ? "Approved change" : "Change summary unavailable"),
        fields: [],
        unavailable: proposal.status === "applying"
            ? "The original change remains approved. Its service status can still be checked."
            : reason,
    });
    if (!definition || definition[0] !== proposal.app || definition[1] !== proposal.page_id
        || page.id !== proposal.page_id || page.version !== 1) {
        return unavailable("This change cannot be reviewed in this version of Desk. Discard it and use the page controls.");
    }
    if (page.resource_basis !== proposal.expected_basis) {
        return unavailable("This page changed after the proposal was prepared. Discard it and prepare the change again.");
    }
    try {
        if (Object.hasOwn(MODEL_PROVIDER_REVIEW_COMMANDS, proposal.command_id)) {
            return summarizeProviderChange(proposal.command_id as ProviderCommand, proposal.payload, page.model);
        }
        const p = data(proposal.payload);
        const m = data(page.model);
        const fields: ReviewField[] = [];
        let note: string | undefined;
        const field = (name: string, value: string, before?: string, expanded?: boolean) => {
            fields.push({ label: name, value, ...(before !== undefined && before !== value ? { before } : {}), ...(expanded ? { expanded } : {}) });
        };
        const target = (name: string, values: unknown, key = "id"): Data => {
            const id = string(p.id);
            const found = recordIn(values, id, key);
            field(name, label(found, id));
            return found;
        };
        const member = () => target("Member", m.members);
        const engagement = (idValue: unknown = p.id) => {
            const id = string(idValue);
            const found = recordIn(m.engagements, id);
            field("Engagement", label(found, id));
            const clientId = string(found.client_id);
            const client = recordIn(list(m.clients).map((row) => data(row).client), clientId);
            field("Client", label(client, clientId));
            field("Product", string(data(found.product_commercial).listing_title));
            return found;
        };
        switch (proposal.command_id) {
            case "project.create":
                return {
                    title: definition[2],
                    fields: [{ label: "Project", value: string(p.name) }],
                    note: "Creates the project, its managed work target, and its built-in Agent on the selected Project Host.",
                };
            case "project-host.add": {
                if (p.kind !== "managed") throw new Error("Unsupported host enrollment");
                const enrollment = data(m.managed_enrollment);
                if (enrollment.available !== true) throw new Error("Managed enrollment unavailable");
                field("Name", string(p.name));
                field("Service location", string(enrollment.region));
                const capacity = data(enrollment.capacity);
                field("Plan capacity", `${hostBytes(number(capacity.storage_bytes))} · ${number(capacity.concurrent_agents)} concurrent agents`);
                note = "Uses the current hosting plan. This does not change the plan or grant project access.";
                break;
            }
            case "project-host.rename": {
                const host = target("Project Host", m.homes);
                field("Name", string(p.name), string(host.name));
                note = "Only the display name changes.";
                break;
            }
            case "project-host.managed-policy.set": {
                const host = target("Project Host", m.homes);
                if (host.kind !== "cloud") throw new Error("Managed host required");
                const policy = data(host.managed_policy);
                field("Metered Isolated workspace", enabled(p.isolated_workspace_enabled), enabled(policy.isolated_workspace_enabled));
                field("Maximum per-attempt reservation", nanoDollars(p.max_attempt_nanos_usd), nanoDollars(policy.max_attempt_nanos_usd));
                note = "Retries require a new reservation. Included workflows and project permissions are unchanged.";
                break;
            }
            case "project-home.handoff": {
                // The subject is the project, not the host, so this cannot lean
                // on `target()` — which reads `p.id`. Naming the two hosts is
                // the whole point of the review: a reviewer is agreeing to
                // where the work ends up, not merely that a move happens.
                const projectId = string(p.project_id);
                const from = recordIn(m.homes, string(p.expected_current_home_id), "home_id");
                const to = recordIn(m.homes, string(p.target_home_id), "home_id");
                const project = (from.projects as Data[] | null ?? []).find((candidate) => candidate.id === projectId);
                field("Project", project ? label(project, projectId) : projectId);
                field("Project Host", label(to, string(p.target_home_id)), label(from, string(p.expected_current_home_id)));
                note = "The two Project Hosts move the project between themselves. It stays readable on the current host until the receiving host holds all of it, and project permissions are unchanged.";
                break;
            }
            case "project-host.suspend":
            case "project-host.reinstate": {
                const host = target("Project Host", m.homes);
                if (host.kind !== "cloud") throw new Error("Managed host required");
                field("Service", proposal.command_id === "project-host.suspend" ? "Suspended" : "Active", string(host.lifecycle));
                note = proposal.command_id === "project-host.suspend" ? "Stops new hosted work. Existing history remains readable and project permissions are unchanged."
                    : "Rechecks the active hosting plan before resuming work. Project permissions are unchanged.";
                break;
            }
            case "project-host.retire": {
                const host = target("Project Host", m.homes);
                if (host.kind !== "cloud") throw new Error("Managed host required");
                const lifecycle = string(host.lifecycle);
                const phase = string(p.phase);
                if (phase === "retention" && (lifecycle === "active" || lifecycle === "suspended")) {
                    field("Lifecycle", "Retention", lifecycle);
                    return {
                        title: "Retire Project Host",
                        fields,
                        note: "Stops new hosted work and begins the plan's retention period. The Project Host can be reinstated while its data is retained.",
                    };
                }
                if (phase === "erase" && lifecycle === "retention") {
                    field("Lifecycle", "Permanently erased", "Retention");
                    return {
                        title: "Erase Project Host permanently",
                        fields,
                        note: "Permanently deletes this Project Host. This cannot be undone; recover or export required work before accepting.",
                    };
                }
                throw new Error("Invalid retirement phase");
            }
            case "backups.enable":
            case "backups.schedule.set": {
                const previous = optionalData(optionalData(m.facility).config);
                field("Backup interval", `Every ${number(p.schedule_days)} days`, previous.schedule_days == null ? "Not set" : `Every ${number(previous.schedule_days)} days`);
                field("Retention", `${number(p.retention_days)} days`, previous.retention_days == null ? "Not set" : `${number(previous.retention_days)} days`);
                if (proposal.command_id === "backups.enable") {
                    field("Protection", "On", m.facility == null ? "Off" : string(data(m.facility).status));
                    note = "Schedule encrypted recovery points for this managed Project Host. Recovery keys remain on enrolled holder devices.";
                } else {
                    note = "Change the schedule for future recovery points. Existing points keep their current expiry.";
                }
                break;
            }
            case "backups.disable": {
                const current = data(m.facility);
                field("Protection", "Paused", string(current.status));
                note = "Stop creating new recovery points. Existing encrypted points remain until their retention period ends.";
                break;
            }
            case "backups.recovery-holder.add":
                field("Recovery holder", optionalText(p.label, "This GaugeDesk device"));
                note = "Enroll only this device's public recovery key. Its private key remains non-exportable on the device.";
                break;
            case "backups.recovery-holder.remove": {
                const holder = target("Recovery holder", m.recipients);
                field("Standing", "Removed", optionalText(holder.label, "Enrolled"));
                note = "The device cannot unlock future recovery points. Existing encrypted point wraps are not rewritten.";
                break;
            }
            case "backups.point.create": {
                const host = data(m.project_host);
                field("Project Host", label(host, string(host.id)));
                field("Recovery holders", String(list(m.recipients).length));
                note = "Seal a consistent Home cut now and retain only ciphertext plus public-holder wraps in the backup service.";
                break;
            }
            case "backups.restore": {
                const handle = string(p.point_handle);
                const point = recordIn(m.points, handle, "handle");
                const host = data(m.project_host);
                field("Project Host", label(host, string(host.id)));
                field("Recovery point", new Date(number(point.created_at) * 1_000).toISOString());
                field("Encrypted size", `${number(point.bytes).toLocaleString()} bytes`);
                note = "Create a one-time receiving key for this erased Home. An enrolled recovery holder must then re-wrap the point key locally to finish the restore.";
                break;
            }
            case "subscription.plan.change":
                field("Plan quantity", String(number(p.quantity ?? 1)));
                note = "Open the processor-owned plan change flow. Current billing remains authoritative until admitted Stripe evidence confirms the change.";
                break;
            case "subscription.seats.change":
                field("Purchased seats", String(number(p.quantity)), String(number(data(data(m.cloud).subscription).quantity)));
                note = "Stripe will show any prorated charge or credit before the seat change is confirmed. GaugeDesk changes access only after admitted Stripe evidence.";
                break;
            case "subscription.cancellation.schedule":
                field("Service ends", new Date(number(data(data(m.cloud).subscription).current_period_end) * 1_000).toLocaleDateString());
                note = "Stripe will confirm future cancellation. Managed rights remain available through the current paid period.";
                break;
            case "subscription.service.add":
                field("Service", choice(p.service, {
                    "commercial-operations": "Commercial Operations",
                    "enterprise-controls": "Enterprise controls",
                }));
                field("Starts", "Now");
                note = "Setup continues on the service's own page after enrollment.";
                break;
            case "subscription.service.remove-scheduled":
                field("Service", choice(p.service, {
                    "commercial-operations": "Commercial Operations",
                    "enterprise-controls": "Enterprise controls",
                }));
                field("Service ends", new Date(number(data(data(m.cloud).subscription).current_period_end) * 1_000).toLocaleDateString());
                note = "Access remains available through the current paid period.";
                break;
            case "subscription.service.remove-cancel":
                field("Service", choice(p.service, {
                    "commercial-operations": "Commercial Operations",
                    "enterprise-controls": "Enterprise controls",
                }));
                field("Service ends", "Not scheduled");
                note = "Cancels the scheduled removal. Existing configuration is unchanged.";
                break;
            case "account.profile.set":
                field("Display name", string(p.display_name), optionalText(data(m.profile).display_name));
                break;
            case "account.erase":
                field("Account", string(data(m.profile).account_id));
                field("Confirmation", string(p.confirmation));
                note = "This permanently removes the account, signs out every device, leaves organizations where possible, and destroys account content. Organizations you solely own must be transferred or deleted first.";
                break;
            case "account.invitation.accept":
            case "account.invitation.decline":
            case "account.membership.leave": {
                const leaving = proposal.command_id === "account.membership.leave";
                const id = string(p.tenant_id);
                const found = recordIn(leaving ? m.memberships : m.invitations, id, leaving ? "id" : "tenant_id");
                field("Organization", label(found, id));
                field("Role", string(found.role));
                note = leaving ? "End your membership and organization access. Your Personal account is unchanged."
                    : proposal.command_id.endsWith("accept") ? "Join with this role. Project access remains subject to its own grants and policy."
                        : "Decline this invitation without joining the organization.";
                break;
            }
            case "provider-connection.rename":
            case "trusted-device.rename": {
                const found = target(proposal.command_id.startsWith("provider") ? "Connection" : "Device",
                    proposal.command_id.startsWith("provider") ? m.connections : m.devices);
                field("Name", string(p.label), optionalText(found.name ?? found.label));
                break;
            }
            case "provider-connection.default-model.set": {
                const id = string(p.connection_id);
                const found = recordIn(m.connections, id);
                const model = string(p.model);
                if (!list(found.models).includes(model)) throw new Error("Model is no longer available");
                field("Connection", label(found, id));
                field("Default model", model, optionalText(optionalData(m.default_model).model, "None"));
                if (m.default_model) {
                    const previous = data(m.default_model);
                    field("Previous connection", string(previous.connection_id));
                }
                note = "Change your personal default. Project-specific model choices are unchanged.";
                break;
            }
            case "application-settings.attention.set": {
                const level = (value: string) => choice(value, {
                    queue: "Task bar", badge: "Badge only", mute: "Transcript only",
                });
                const parseRules = (value: unknown) => parseAttentionRules(
                    typeof value === "string" ? value : JSON.stringify(value ?? null),
                );
                const next = parseRules(p.value);
                const current = parseRules(optionalData(m.preferences)["attention.rules"]);
                for (const meta of ATTENTION_SIGNALS) {
                    field(meta.label, level(next[meta.signal]), level(current[meta.signal]));
                }
                note = "Change which Desk events can interrupt you. Organization policy is unchanged.";
                break;
            }
            case "application-settings.appearance.set": {
                const next = data(p.value);
                const current = data(optionalData(m.preferences).appearance);
                if (number(next.version) !== 1 || number(current.version) !== 1) throw new Error("Unknown appearance version");
                field("Interface size", choice(next.interface_scale, { standard: "Standard", large: "Large" }), choice(current.interface_scale, { standard: "Standard", large: "Large" }));
                field("Contrast", choice(next.contrast, { standard: "Standard", high: "High" }), choice(current.contrast, { standard: "Standard", high: "High" }));
                field("Motion", choice(next.motion, { system: "Use device setting", reduced: "Reduced" }), choice(current.motion, { system: "Use device setting", reduced: "Reduced" }));
                note = "Apply this account preference to the complete Desk interface.";
                break;
            }
            case "commercial-product.create":
            case "commercial-product.revise": {
                const revision = data(p.revision);
                const current = proposal.command_id.endsWith("revise") ? target("Product", m.products) : undefined;
                if (!current) field("Product ID", string(p.id));
                const previous = optionalData(current?.commercial);
                const agent = data(revision.archetype);
                field("Listing title", string(revision.listing_title), optionalText(previous.listing_title));
                field("Description", optionalText(revision.description, "None"), optionalText(previous.description, "None"));
                field("Agent", `${string(agent.name)} (${string(agent.id)}) · ${choice(agent.kind, { agent: "Agent", "panel-agent": "Panel agent" })} · v${string(agent.version)}`);
                field("Project Home", string(agent.home_ref));
                field("Version policy", choice(revision.sale_version_policy, { "pinned-version": "Pinned version", "current-at-proposal": "Current at proposal" }));
                fields.push(...priceFields(revision.prices));
                field("Delivery", delivery(revision.delivery));
                fields.push(...serviceFields(revision.service_obligations));
                field("Commercial revision", String(current ? number(current.current_revision) + 1 : 1));
                note = "Existing proposals and accepted agreements keep their exact commercial revision. Agent behavior is unchanged.";
                break;
            }
            case "commercial-client.create":
            case "commercial-client.edit": {
                const previous = proposal.command_id.endsWith("edit") ? target("Client", list(m.clients).map((row) => data(row).client)) : {};
                if (proposal.command_id.endsWith("create")) field("Client ID", string(p.id));
                field("Name", string(p.display_name), optionalText(previous.display_name));
                field("Billing reference", optionalText(p.billing_reference, "None"), optionalText(previous.billing_reference, "None"));
                note = "This changes the contracting record, not project membership or the client's Stripe payment method.";
                break;
            }
            case "commercial-engagement.proposal.create": {
                field("Engagement ID", string(p.id));
                const clientId = string(p.client_id);
                field("Client", label(recordIn(list(m.clients).map((row) => data(row).client), clientId), clientId));
                const product = recordIn(m.products, string(p.product_id));
                const commercial = data(product.commercial);
                field("Product", `${string(commercial.listing_title)} · commercial revision ${number(product.current_revision)}`);
                fields.push(...termsFields(p.terms, commercial));
                note = "Create an unsent draft. No recipient is notified, charged, or granted access.";
                break;
            }
            case "commercial-engagement.proposal.save":
            case "commercial-engagement.proposal.revise":
            case "commercial-engagement.proposal.send":
            case "commercial-engagement.proposal.resend": {
                const found = engagement();
                field("Commercial revision", String(number(found.product_revision)));
                const sending = proposal.command_id.endsWith("send");
                fields.push(...termsFields(sending ? found.terms : p.terms, data(found.product_commercial)));
                note = sending ? "Create addressed proposal links to copy and send. Previous links stop working. No email is sent by Desk; this does not charge or grant access."
                    : proposal.command_id.endsWith("revise") ? "Replace the sent proposal with an unsent draft. Existing recipient links stop working until you send it again."
                        : "Save this unsent draft. No recipient is notified, charged, or granted access.";
                break;
            }
            case "commercial-engagement.placement.link":
                engagement();
                field("Placement reference", string(p.placement_ref));
                note = "Link this reference to the engagement. This does not create a deployment or grant project access.";
                break;
            case "commercial-engagement.entitlement.activate":
                engagement();
                field("Entitlement reference", string(p.entitlement_ref));
                note = "Activate the engagement entitlement. Execution remains subject to the project's own admission and policy; Stripe billing is unchanged.";
                break;
            case "commercial-engagement.invoice.issue":
            case "commercial-payments.invoice.issue":
                engagement(p.engagement_id);
                field("Invoice reference", string(p.id));
                field("Billing recipient", string(p.billing_email));
                field("Payment due", `${number(p.days_until_due)} days after issue`);
                note = "Issue the engagement invoice through Stripe. The amount and currency come from the accepted agreement; payment status updates only from admitted processor evidence.";
                break;
            case "organization.display-name.set":
                field("Display name", string(p.display_name), optionalText(m.display_name));
                break;
            case "organization.ownership.transfer": {
                target("New owner", m.ownership_candidates);
                const owner = data(m.owner);
                field("Current owner", `${label(owner, string(owner.id))} → admin`);
                break;
            }
            case "organization.delete":
                field("Organization", string(p.confirmation));
                note = "Remove this organization from GaugeDesk, end access, and destroy its content key. Required billing and audit evidence may remain. Members, services, plans, active engagements, or shared model connections prevent deletion.";
                break;
            case "organization.domain.add":
                field("Domain", string(p.domain));
                note = "Record this claim and publish its DNS challenge. The domain admits no sign-in and grants nothing until a separate Verify proves the TXT record.";
                break;
            case "organization.domain.verify":
                field("Domain", string(p.domain));
                note = "Check the published TXT record and, if it matches, promote this claim to a verified domain. Accepting this cannot succeed while the record is absent.";
                break;
            case "organization.domain.remove":
                field("Domain", string(p.domain));
                note = "Withdraw this domain, whether it is verified or still awaiting its DNS proof.";
                break;
            case "people.invitation.create":
                field("Recipients", strings(p.emails));
                field("Role", string(p.role));
                if (p.team) field("Team", string(p.team));
                note = "Create addressed links valid for 7 days. Copy and send them yourself; no email is sent by Desk.";
                break;
            case "people.invitation.cancel":
            case "people.invitation.resend": {
                const invitation = target("Recipient", [...list(m.invitations), ...list(m.members)]);
                field("Role", string(invitation.role));
                note = proposal.command_id.endsWith("resend")
                    ? "Invalidate the old link and create a new 7-day link to copy and send. No email is sent by Desk."
                    : "The invitation can no longer be accepted.";
                break;
            }
            case "people.role.change":
                field("Role", string(p.role), string(member().role));
                break;
            case "people.member.deactivate":
            case "people.member.reactivate": {
                const found = member();
                field("Role", string(found.role));
                field("Membership", proposal.command_id.endsWith("deactivate") ? "Deprovisioned" : "Active", string(found.status));
                note = "This changes organization membership, not the person's account.";
                break;
            }
            case "project-access.grant":
            case "project-access.revoke": {
                const authority = string(p.authority);
                field("Member", label(recordIn(m.members, authority, "authority"), authority));
                const project = string(p.project_id);
                field("Project", label(recordIn(m.projects, project), project));
                note = proposal.command_id.endsWith("grant") ? "Add this explicit project grant." : "Remove this explicit project grant; other role-based access is unchanged.";
                break;
            }
            case "organization-session.revoke":
                target("Session", m.sessions);
                note = "End this session's access to this organization. Trusted Devices and other organizations are unchanged.";
                break;
            case "enterprise-identity.connection.set": {
                const previous = optionalData(m.sso);
                field("Protocol", string(p.protocol).toUpperCase(), optionalText(previous.protocol).toUpperCase());
                field("Issuer", optionalText(p.issuer), optionalText(previous.issuer));
                field("Client IDs", strings(p.audiences ?? []));
                if (p.metadata) field(p.protocol === "saml" ? "IdP metadata XML" : "Discovery URL", string(p.metadata), undefined, p.protocol === "saml");
                const claims = optionalData(p.claim_mapping);
                field("Subject claim", optionalText(claims.subject_claim, "Default (sub)"));
                field("Email claim / attribute", optionalText(claims.email_claim, "Default email / NameID"));
                field("Roles claim", optionalText(claims.roles_claim, "Default mapping"));
                field("Region claim", optionalText(claims.region_claim, "Default mapping"));
                field("Tenant claim", optionalText(claims.tenant_claim, "Default mapping"));
                note = "Save connection settings without enforcing SSO. Enforcement is a separate operation.";
                break;
            }
            case "enterprise-identity.admission-mode.set": {
                const names: Record<string, string> = {
                    "invited-only": "Invited people only",
                    "verified-domain-jit": "Verified company email",
                    scim: "SCIM-provisioned people",
                };
                const next = string(p.mode);
                field("Who can join", names[next] ?? next, names[optionalText(m.admission_mode)]);
                note = "This changes how a verified corporate subject may become a member; it grants no role by itself.";
                break;
            }
            case "enterprise-identity.owner-subject.link":
                field("Recovery owner", "Link the recently tested corporate subject to this account");
                note = "The server requires this owner's current passkey session and a browser test started by the same account within ten minutes.";
                break;
            case "enterprise-identity.enforcement.enable":
            case "enterprise-identity.enforcement.disable": {
                const required = proposal.command_id === "enterprise-identity.enforcement.enable";
                field("Member sign-in", required ? "Require corporate SSO" : "Do not require corporate SSO", optionalData(m.enforcement).required === true ? "Require corporate SSO" : "Do not require corporate SSO");
                note = required
                    ? "The server will enable this only if every lockout-safety prerequisite is still current."
                    : "Members may use another admitted GaugeDesk sign-in method again.";
                break;
            }
            case "enterprise-identity.scim-credential.issue":
            case "enterprise-identity.scim-credential.rotate":
                field("Provisioning", proposal.command_id.endsWith("rotate") ? "Replace current SCIM credential" : "Create SCIM credential");
                note = proposal.command_id.endsWith("rotate")
                    ? "The old credential stops working. Copy the new credential once and update your identity provider."
                    : "Copy the credential once and configure it in your identity provider.";
                break;
            case "enterprise-identity.group-mapping.add":
            case "enterprise-identity.group-mapping.edit":
                field("Identity-provider group", string(p.group));
                field("Role", string(p.role));
                field("Team", optionalText(p.team, "No team scope"));
                break;
            case "enterprise-identity.group-mapping.remove":
                field("Identity-provider group", string(p.group));
                note = "Remove this group's role mapping.";
                break;
            case "organization-policy.set": {
                const roleAccess = (source: Data, action: string) => {
                    const rules = list(data(source.resource).rules).map(data);
                    return ["owner", "admin", "member", "viewer"].filter((role) => !rules.some((rule) =>
                        optionalData(typeof rule.when === "object" ? rule.when : null).ActorHasRole === role
                        && optionalData(typeof rule.require === "object" ? rule.require : null).DenyAction === action)).join(", ") || "None";
                };
                const matching = (source: Data) => list(data(source.resource).rules).map(data)
                    .some((rule) => rule.when === "Always" && rule.require === "RequireResourceRegionMatchesActor");
                field("Export roles", roleAccess(p, "export"), roleAccess(m, "export"));
                field("Run roles", roleAccess(p, "run"), roleAccess(m, "run"));
                field("Require matching region", enabled(matching(p)), enabled(matching(m)));
                const security = data(p.security);
                const oldSecurity = optionalData(m.security);
                field("Session lifetime", `${number(security.session_lifetime_secs) / 3600} hours`, `${number(oldSecurity.session_lifetime_secs ?? 0) / 3600} hours`);
                field("Idle timeout", `${number(security.idle_timeout_secs) / 60} minutes`, `${number(oldSecurity.idle_timeout_secs ?? 0) / 60} minutes`);
                field("History guarantee", `${number(security.audit_retention_min_days)} days`, `${number(oldSecurity.audit_retention_min_days ?? 365)} days`);
                field("Automatic publisher upgrades", enabled(security.allow_auto_upgrade), enabled(oldSecurity.allow_auto_upgrade ?? false));
                field("Eligible Project Hosts", strings(data(p.placement).allowed_operators, "All operators"), strings(data(m.placement).allowed_operators, "All operators"));
                field("Require approval for new placements", enabled(data(p.archetype_approval).require_approval), enabled(data(m.archetype_approval).require_approval));
                break;
            }
            case "software-policy.set":
                field("Minimum build", optionalText(p.minimum_version, "None"), optionalText(m.minimum_version, "None"));
                field("Minimum protocol", String(number(p.minimum_protocol)), String(number(m.minimum_protocol)));
                field("Release channels", strings(p.allowed_channels, "All"), strings(m.allowed_channels, "All"));
                field("Grace deadline", p.grace_until_unix_ms == null ? "Immediate" : stamp(p.grace_until_unix_ms), m.grace_until_unix_ms == null ? "Immediate" : stamp(m.grace_until_unix_ms));
                break;
            case "billing.contact.set": {
                const current = optionalData(m.billing_contact);
                field("Name", string(p.name), optionalText(current?.name, "Not set"));
                field("Email", string(p.email), optionalText(current?.email, "Not set"));
                note = "GaugeWright uses this recipient for billing notices. Payment details, addresses, and tax information remain in Stripe.";
                break;
            }
            case "account.authenticator.remove":
                target("Sign-in method", m.authenticators);
                field("Type", string(p.kind));
                note = "This method will no longer sign in to your account.";
                break;
            case "account.session.revoke-current": {
                const current = list(m.sessions).map(data).find((session) => session.current === true);
                if (!current) throw new Error("No current session");
                field("Session", string(current.id));
                note = "You will be signed out here. Your other sessions stay signed in.";
                break;
            }
            case "account.session.revoke":
                target("Session", m.sessions);
                note = "The selected account session will be signed out.";
                break;
            case "account.session.revoke-others": {
                const others = list(m.sessions).map(data).filter((session) => session.current !== true);
                field("Sessions to sign out", String(others.length));
                for (const session of others) field("Session", string(session.id));
                note = "Keep this account session signed in.";
                break;
            }
            case "provider-connection.revoke":
                target("Connection", m.connections);
                note = "Remove this connection's stored credential. It will no longer fund model requests.";
                break;
            case "trusted-device.revoke":
                target("Device", m.devices);
                note = "Revoke this device and its refresh sessions. This does not erase files stored on the device.";
                break;
            case "commercial-client.close":
                target("Client", list(m.clients).map((row) => data(row).client));
                note = "Close the client to new engagements. Existing engagement and payment records are retained.";
                break;
            case "commercial-engagement.proposal.discard":
                engagement();
                note = "Remove this unsent draft from the engagement list.";
                break;
            case "commercial-engagement.proposal.withdraw":
                engagement();
                note = "Withdraw the sent proposal so it can no longer be accepted. Its history is retained.";
                break;
            case "commercial-engagement.entitlement.suspend":
            case "commercial-engagement.entitlement.revoke": {
                const found = engagement();
                field("Entitlement", proposal.command_id.endsWith("suspend") ? "Suspended" : "Revoked", string(found.entitlement));
                note = "This changes the engagement entitlement, not the Stripe subscription or payment history.";
                break;
            }
            case "commercial-engagement.close":
                engagement();
                note = "Mark the engagement closed. This does not revoke its entitlement, stop a deployment, or cancel Stripe billing.";
                break;
            case "commercial-payments.payment.refund": {
                const transaction = string(p.transaction_id);
                const payment = recordIn(m.transactions, transaction, "object_id");
                field("Payment", transaction);
                field("Refund amount", commercialMoney(number(p.amount_cents), string(payment.currency)));
                field("Reason", optionalText(p.reason, "Not specified"));
                note = "Request this refund through Stripe. The payment history updates from admitted processor evidence.";
                break;
            }
        }
        const visibleFields = proposal.command_id === "organization-policy.set" || proposal.command_id === "software-policy.set"
            ? fields.filter((field) => field.before !== undefined)
            : fields;
        if (visibleFields.length === 0) return unavailable("No values would change. Discard this proposal.");
        return { title: definition[2], fields: visibleFields, ...(note ? { note } : {}) };
    } catch {
        return unavailable("The complete change or its target is no longer available. Refresh the page, or discard and prepare it again.");
    }
}
