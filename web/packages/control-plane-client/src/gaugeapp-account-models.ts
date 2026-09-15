import {
    arrayOf, booleanValue, integerValue, invalidModel, jsonValue, nullable,
    objectValue, oneOf, shape, stringValue, type ModelReader,
} from "./gaugeapp-model-validation";

const strings = arrayOf(stringValue);
const status = oneOf("active", "suspended", "lapsed");
const authenticator = (value: unknown, path: string) => {
    const record = objectValue(value, path);
    const result = record.kind === "passkey" ? shape({
        id: stringValue, kind: oneOf("passkey"), label: stringValue, created_at: integerValue,
        can_remove: booleanValue, remove_blocked_reason: nullable(stringValue),
    })(record, path) : shape({
        id: stringValue, kind: oneOf("consumer-oidc", "enterprise-oidc", "enterprise-saml"),
        connection_id: stringValue, linked_at: integerValue,
        can_remove: booleanValue, remove_blocked_reason: nullable(stringValue),
    })(record, path);
    if (result.can_remove === (result.remove_blocked_reason !== null)) {
        return invalidModel(`${path}.remove_blocked_reason`);
    }
    return result;
};
const accountMembershipShape = shape({
    id: stringValue, display_name: stringValue, role: stringValue,
    personal: booleanValue, provider_commercial: booleanValue,
    can_leave: booleanValue, leave_blocked_reason: nullable(stringValue),
});
const accountMembership = (value: unknown, path: string) => {
    const membership = accountMembershipShape(value, path);
    if (membership.personal && (membership.can_leave || membership.leave_blocked_reason !== null)) {
        return invalidModel(`${path}.can_leave`);
    }
    if (!membership.personal && membership.can_leave === (membership.leave_blocked_reason !== null)) {
        return invalidModel(`${path}.leave_blocked_reason`);
    }
    return membership;
};
export const parseAccountSettingsModel = shape({
    profile: shape({ account_id: stringValue, display_name: nullable(stringValue) }),
    consumer_oidc: shape({
        available: booleanValue,
        connection_id: nullable(stringValue),
        label: nullable(stringValue),
    }),
    verified_contacts: arrayOf(shape({ id: stringValue, email: stringValue, verified_at: integerValue })),
    authenticators: arrayOf(authenticator),
    recovery: shape({ batches: arrayOf(shape({ id: stringValue, created_at: integerValue, remaining_codes: integerValue })) }),
    sessions: arrayOf(shape({
        id: stringValue, method: stringValue, issued_at_ms: integerValue,
        last_seen_ms: integerValue, lifetime_secs: integerValue, current: booleanValue,
    })),
    memberships: arrayOf(accountMembership),
    invitations: arrayOf(shape({ tenant_id: stringValue, display_name: stringValue, role: stringValue })),
    erasure: shape({
        available: booleanValue,
        confirmation: oneOf("ERASE MY ACCOUNT"),
        blocking_organizations: strings,
    }),
});
export type AccountSettingsPageV1 = ReturnType<typeof parseAccountSettingsModel>;

export const parseProviderConnection = shape({
    id: stringValue, provider: stringValue, name: stringValue,
    kind: oneOf("bearer", "api-key", "o-auth"),
    endpoint_class: oneOf("provider-hosted", "openai-compatible"),
    base_url: nullable(stringValue), linked: booleanValue, status: oneOf("active", "revoked"),
    version: integerValue,
    execution_classes: arrayOf(oneOf("local-interactive", "private-home", "public-deployment")),
    models: strings, linked_at_ms: nullable(integerValue), last_verified_at_ms: nullable(integerValue),
    verification: oneOf("unverified", "reachable", "unreachable"),
});
export type ProviderConnectionModel = ReturnType<typeof parseProviderConnection>;

const providerSignIn = shape({
    provider: stringValue, linked: booleanValue, expires: nullable(integerValue), expired: booleanValue,
    login: nullable(shape({
        login_id: stringValue, verification_url: stringValue, user_code: stringValue,
        status: oneOf("pending", "cancelling", "linked", "failed", "cancelled"), error: nullable(stringValue),
    })),
});
const managedPlan = shape({ plan: stringValue, status, included_tokens: integerValue });
export const parseManagedInferenceUsage = shape({
    runs: integerValue, input_tokens: integerValue, output_tokens: integerValue,
    total_tokens: integerValue, included_tokens: integerValue, overage_tokens: integerValue,
    unattributed_runs: integerValue, unattributed_tokens: integerValue,
});
const subscription = shape({
    event_id: stringValue, event_created: integerValue, subscription_id: stringValue,
    customer_id: stringValue, price_id: stringValue,
    subscription_item_id: nullable(stringValue), quantity: nullable(integerValue),
    status, storage_bytes: integerValue,
    concurrent_agents: integerValue, retention_secs: integerValue, current_period_end: nullable(integerValue),
    processor_mode: oneOf("live", "test"), verified_at: integerValue, cancel_at_period_end: booleanValue,
});
const billingLine = shape({
    description: nullable(stringValue), amount_cents: integerValue, currency: stringValue,
    period_start: nullable(integerValue), period_end: nullable(integerValue),
});
const tenantInvoice = shape({
    id: stringValue, customer_id: stringValue, subscription_id: stringValue,
    processor_mode: oneOf("live", "test"), status: oneOf("draft", "open", "paid", "uncollectible", "void"),
    currency: stringValue, total_cents: integerValue, amount_due_cents: integerValue,
    amount_paid_cents: integerValue, amount_remaining_cents: integerValue,
    created_at: integerValue, due_at: nullable(integerValue),
    hosted_invoice_url: nullable(stringValue), invoice_pdf: nullable(stringValue),
});
const tenantEstimate = shape({
    id: stringValue, customer_id: stringValue, subscription_id: stringValue,
    processor_mode: oneOf("live", "test"), currency: stringValue,
    total_cents: integerValue, amount_due_cents: integerValue,
    period_start: nullable(integerValue), period_end: nullable(integerValue),
    lines: arrayOf(billingLine), lines_complete: booleanValue, generated_at: integerValue,
});
const billingDocuments = shape({
    invoices: arrayOf(tenantInvoice), estimate: nullable(tenantEstimate),
    refreshed_at: nullable(integerValue), history_complete: booleanValue,
    freshness: oneOf("not-refreshed", "processor-refreshed", "unavailable"),
});
const subscriptionBilling = shape({
    customer_linked: booleanValue, subscription: nullable(subscription),
    processor_mode: oneOf("live", "test"), verification: oneOf("verified", "unverified", "unavailable", "unlinked"),
    configured_plan: shape({ name: stringValue, included_tokens: integerValue, checkout_available: booleanValue }),
    management: shape({ plan_change: booleanValue, seats: booleanValue, cancellation: booleanValue }),
    documents: billingDocuments,
    freshness: oneOf("processor-reconciled"),
});
export function parseSubscriptionBilling(value: unknown, path: string) {
    const model = subscriptionBilling(value, path);
    if (model.subscription && (model.verification !== "verified" || !model.customer_linked
        || model.subscription.processor_mode !== model.processor_mode || model.subscription.verified_at === 0)) return invalidModel(`${path}.subscription`);
    if (!model.subscription && (model.verification === "verified" || model.customer_linked)) return invalidModel(`${path}.verification`);
    if (model.subscription?.quantity === 0) return invalidModel(`${path}.subscription.quantity`);
    if (model.management.seats && (!model.subscription?.subscription_item_id || !model.subscription.quantity)) return invalidModel(`${path}.management.seats`);
    if (model.management.cancellation && (!model.subscription || model.subscription.cancel_at_period_end)) return invalidModel(`${path}.management.cancellation`);
    if (model.documents.freshness === "processor-refreshed" && model.documents.refreshed_at === null) return invalidModel(`${path}.documents.refreshed_at`);
    if (model.documents.estimate && (!model.subscription
        || model.documents.estimate.customer_id !== model.subscription.customer_id
        || model.documents.estimate.subscription_id !== model.subscription.subscription_id
        || model.documents.estimate.processor_mode !== model.processor_mode)) return invalidModel(`${path}.documents.estimate`);
    if (model.documents.invoices.some(invoice => invoice.processor_mode !== model.processor_mode
        || (model.subscription && invoice.customer_id !== model.subscription.customer_id))) return invalidModel(`${path}.documents.invoices`);
    return model;
}
export type SubscriptionBilling = ReturnType<typeof parseSubscriptionBilling>;
export const parseProviderConnectionsModel = shape({
    connections: arrayOf(parseProviderConnection),
    default_model: nullable(shape({ connection_id: stringValue, model: stringValue })),
    subscription_sign_ins: shape({ codex: providerSignIn, grok: providerSignIn }),
    managed_inference: shape({ plan: nullable(managedPlan), usage: parseManagedInferenceUsage, billing: parseSubscriptionBilling }),
});
export type ProviderConnectionsPageV1 = ReturnType<typeof parseProviderConnectionsModel>;
export type ProviderConnectionsPageModel = ProviderConnectionsPageV1;

export const parseAccountDeviceLink = shape({
    id: stringValue,
    phase: oneOf("waiting-for-device", "awaiting-acceptance", "authorized", "enrolled", "rejected", "canceled", "expired"),
    human_code: stringValue, qr_payload: stringValue, created_at_ms: integerValue, expires_at_ms: integerValue,
    device: nullable(shape({ id: stringValue, label: stringValue, kind: oneOf("computer", "phone", "tablet") })),
    sas: nullable(stringValue), completed_at_ms: nullable(integerValue),
});
export type AccountDeviceLink = ReturnType<typeof parseAccountDeviceLink>;
const linkAvailability = (value: unknown, path: string) => {
    const record = objectValue(value, path);
    if (record.available === true) return { available: true as const };
    if (record.available !== false) return invalidModel(`${path}.available`);
    return { available: false as const, reason: stringValue(record.reason, `${path}.reason`) };
};
export const parseTrustedDevicesModel = shape({
    devices: arrayOf(shape({
        id: stringValue, label: stringValue, subkey_pubkey: stringValue,
        kind: oneOf("computer", "phone", "tablet", "unknown"),
        status: oneOf("active", "revoked"), enrolled_at: integerValue,
        last_seen_ms: nullable(integerValue), current: booleanValue,
    })),
    pending_link: nullable(parseAccountDeviceLink), link_availability: linkAvailability,
});
export type TrustedDevicesPageV1 = ReturnType<typeof parseTrustedDevicesModel>;

export const parseAppearancePreference = shape({
    version: (value, path) => integerValue(value, path) === 1 ? 1 as const : invalidModel(path),
    interface_scale: oneOf("standard", "large"),
    contrast: oneOf("standard", "high"),
    motion: oneOf("system", "reduced"),
});
export type AppearancePreferenceV1 = ReturnType<typeof parseAppearancePreference>;

const preferences = (value: unknown, path: string) => {
    const entries = objectValue(value, path);
    const parsed = Object.fromEntries(
        Object.entries(entries).map(([key, entry]) => [key, jsonValue(entry, `${path}.*`)]),
    );
    if (!("appearance" in entries)) return invalidModel(`${path}.appearance`);
    parsed.appearance = parseAppearancePreference(entries.appearance, `${path}.appearance`);
    return parsed;
};
export const parseApplicationSettingsModel = shape({
    // Attention remains a structured evaluator document. Appearance is the
    // closed cross-client schema above; a raw JSON/string editor may not
    // rewrite either preference.
    preferences,
    appearance_saved: booleanValue,
    ownership: shape({
        "attention.rules": oneOf("person"),
        appearance: oneOf("person"),
    }),
    managed: strings,
});
export type ApplicationSettingsPageV1 = ReturnType<typeof parseApplicationSettingsModel>;

export const accountPageModels = {
    account: parseAccountSettingsModel,
    "provider-connections": parseProviderConnectionsModel,
    "trusted-devices": parseTrustedDevicesModel,
    "application-settings": parseApplicationSettingsModel,
} satisfies Record<string, ModelReader<unknown>>;
export type AccountGaugeAppPageId = keyof typeof accountPageModels;
export type AccountGaugeAppPageData = {
    readonly [P in AccountGaugeAppPageId]: ReturnType<(typeof accountPageModels)[P]>;
};
