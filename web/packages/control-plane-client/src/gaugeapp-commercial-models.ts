import { arrayOf, booleanValue, integerValue, invalidModel, nullable, objectValue, oneOf, shape, stringValue, type ModelReader } from "./gaugeapp-model-validation";

// First-party wire models, not a UI schema. The owning Rust HTTP projections
// are exercised against these readers by the Cloud conformance gate.
const operation = oneOf("upsert", "tombstone");
const agent = shape({ id: stringValue, name: stringValue, kind: oneOf("agent", "panel-agent"), version: stringValue, home_ref: stringValue });
export type CommercialArchetypeRef = ReturnType<typeof agent>;
const readPrice = shape({
    id: stringValue, label: stringValue, kind: oneOf("one-time", "recurring", "per-seat", "metered-usage", "cost-plus"),
    currency: stringValue, amount_cents: nullable(integerValue), markup_basis_points: nullable(integerValue),
    cadence: nullable(oneOf("monthly", "annual")), collection: oneOf("in-advance", "in-arrears"),
    unit: nullable(stringValue), minimum_quantity: nullable(integerValue), maximum_quantity: nullable(integerValue),
});
export type CommercialPrice = ReturnType<typeof readPrice>;
const price: ModelReader<CommercialPrice> = (value, path) => {
    const result = readPrice(value, path);
    if (result.kind === "cost-plus") {
        if (result.markup_basis_points === null || result.amount_cents !== null) return invalidModel(`${path}.markup_basis_points`);
    } else if (result.amount_cents === null || result.markup_basis_points !== null) return invalidModel(`${path}.amount_cents`);
    if ((result.kind === "recurring" || result.kind === "per-seat") && result.cadence === null) return invalidModel(`${path}.cadence`);
    if (result.kind === "metered-usage" && !result.unit) return invalidModel(`${path}.unit`);
    return result;
};
const service = shape({ id: stringValue, label: stringValue, description: stringValue, cadence: nullable(stringValue) });
const revision = shape({
    id: stringValue, op: operation, product_id: stringValue, revision: integerValue,
    archetype: agent, sale_version_policy: oneOf("pinned-version", "current-at-proposal"),
    listing_title: stringValue, description: stringValue, prices: arrayOf(price),
    delivery: oneOf("provider-hosted-panel", "customer-project-placement"), service_obligations: arrayOf(service),
});
export type CommercialProductRevision = ReturnType<typeof revision>;
const counts = shape({ open: integerValue, active: integerValue, closed: integerValue });
const readProduct = shape({ id: stringValue, current_revision: integerValue, commercial: revision, engagement_counts: counts });
export type CommercialProduct = ReturnType<typeof readProduct>;
const product: ModelReader<CommercialProduct> = (value, path) => {
    const result = readProduct(value, path);
    if (result.id !== result.commercial.product_id || result.current_revision !== result.commercial.revision) return invalidModel(`${path}.commercial`);
    return result;
};
const accountRecipient = shape({ kind: oneOf("account"), account_id: stringValue, purpose: stringValue });
const manualRecipient = shape({ kind: oneOf("manual"), name: stringValue, email: stringValue, purpose: stringValue });
export type CommercialRecipient = ReturnType<typeof accountRecipient> | ReturnType<typeof manualRecipient>;
const recipient: ModelReader<CommercialRecipient> = (value, path) => {
    const source = objectValue(value, path);
    switch (source.kind) {
        case "account": return accountRecipient(source, path);
        case "manual": return manualRecipient(source, path);
        default: return invalidModel(`${path}.kind`);
    }
};
const client = shape({
    client: shape({ id: stringValue, op: operation, display_name: stringValue, billing_reference: nullable(stringValue), status: oneOf("active", "closed") }),
    engagement_counts: counts, participant_references: arrayOf(recipient),
});
export type CommercialClient = ReturnType<typeof client>;
const terms = shape({
    seats: nullable(integerValue), discount_basis_points: integerValue, price_overrides: arrayOf(price),
    term_months: nullable(integerValue), start_rule: oneOf("on-acceptance", "fixed-date"), start_at_ms: nullable(integerValue),
    renewal: oneOf("none", "month-to-month", "annual"), payment_terms_days: integerValue, valid_until_ms: integerValue,
    proposal_recipients: arrayOf(recipient), billing_recipient: recipient, client_note: stringValue,
});
export type CommercialEngagementTerms = ReturnType<typeof terms>;
const agreement = shape({ product: revision, terms, accepted_by: recipient, accepted_at_ms: integerValue });
const readEngagement = shape({
    id: stringValue, op: operation, client_id: stringValue, product_id: stringValue, product_revision: integerValue,
    proposal_revision: integerValue, stage: oneOf("draft", "sent", "withdrawn", "expired", "accepted", "active", "closed"),
    terms, sent_at_ms: nullable(integerValue), agreement: nullable(agreement), placement_ref: nullable(stringValue),
    entitlement: oneOf("inactive", "active", "suspended", "revoked"), entitlement_ref: nullable(stringValue),
    payment_refs: arrayOf(stringValue), product_commercial: revision,
});
export type CommercialEngagement = ReturnType<typeof readEngagement>;
const engagement: ModelReader<CommercialEngagement> = (value, path) => {
    const result = readEngagement(value, path);
    if (result.product_id !== result.product_commercial.product_id || result.product_revision !== result.product_commercial.revision) return invalidModel(`${path}.product_commercial`);
    if (result.agreement && (result.agreement.product.product_id !== result.product_id || result.agreement.product.revision !== result.product_revision)) return invalidModel(`${path}.agreement.product`);
    if (["accepted", "active", "closed"].includes(result.stage) && !result.agreement) return invalidModel(`${path}.agreement`);
    return result;
};
const availableLibrary = shape({ availability: oneOf("available"), reason: nullable(stringValue), home_ref: stringValue, archetypes: arrayOf(agent) });
const emptyArray: ModelReader<readonly never[]> = (value, path) => Array.isArray(value) && value.length === 0 ? [] : invalidModel(path);
const nullValue: ModelReader<null> = (value, path) => value === null ? null : invalidModel(path);
const unavailableLibrary = shape({ availability: oneOf("unavailable"), reason: stringValue, home_ref: nullValue, archetypes: emptyArray });
const library: ModelReader<ReturnType<typeof availableLibrary> | ReturnType<typeof unavailableLibrary>> = (value, path) => {
    const source = objectValue(value, path);
    return source.availability === "available" ? availableLibrary(source, path) : unavailableLibrary(source, path);
};
// Runtime-ledger integration is not implemented by this projection yet. Never
// accept invented deployment usage or turn unavailable cost into zero.
const metering = shape({
    status: oneOf("no_edge_deployments", "unavailable"), complete: booleanValue,
    metered_cost_cents: nullable(integerValue), reserved_cents: nullable(integerValue), deployments: emptyArray,
    unmatched_deployment_refs: arrayOf(stringValue), basis: stringValue,
});
const processorEvent = shape({
    event_id: stringValue, event_type: stringValue, object_id: stringValue, amount_cents: integerValue,
    currency: stringValue, status: stringValue, engagement_id: nullable(stringValue), client_id: nullable(stringValue),
    payment_intent_id: nullable(stringValue), platform_fee_cents: integerValue, created: integerValue,
});
export type CommercialProcessorEvent = ReturnType<typeof processorEvent>;
const financialInteger: ModelReader<number> = (value, path) => typeof value === "number" && Number.isSafeInteger(value) ? value : invalidModel(path);
const readProcessorInvoice = shape({
    object: oneOf("invoice"), object_id: stringValue,
    status: oneOf("unreconciled", "unknown", "draft", "open", "paid", "uncollectible", "void", "deleted"),
    currency: nullable(stringValue), total_cents: nullable(financialInteger), amount_due_cents: nullable(financialInteger),
    amount_paid_cents: nullable(financialInteger), amount_remaining_cents: nullable(financialInteger),
    due_at: nullable(integerValue), hosted_invoice_url: nullable(stringValue), engagement_id: nullable(stringValue), client_id: nullable(stringValue), verified_at: nullable(integerValue),
});
const processorInvoice: ModelReader<ReturnType<typeof readProcessorInvoice>> = (value, path) => {
    const result = readProcessorInvoice(value, path);
    const unresolved = result.status === "unreconciled", deleted = result.status === "deleted";
    const amounts = [result.total_cents, result.amount_due_cents, result.amount_paid_cents, result.amount_remaining_cents];
    if (unresolved ? result.verified_at !== null : result.verified_at === null || result.verified_at <= 0) return invalidModel(`${path}.verified_at`);
    if (unresolved || deleted) {
        if (amounts.some(value => value !== null) || result.currency !== null || result.hosted_invoice_url !== null || result.due_at !== null) return invalidModel(path);
    } else if (amounts.some(value => value === null) || !result.currency) return invalidModel(path);
    return result;
};
export type CommercialProcessorInvoice = ReturnType<typeof processorInvoice>;
const readProcessorPayout = shape({
    object: oneOf("payout"), object_id: stringValue, status: oneOf("unreconciled", "pending", "in_transit", "paid", "failed", "canceled"),
    currency: nullable(stringValue), amount_cents: nullable(financialInteger), arrival_at: nullable(integerValue), verified_at: nullable(integerValue),
});
const processorPayout: ModelReader<ReturnType<typeof readProcessorPayout>> = (value, path) => {
    const result = readProcessorPayout(value, path);
    if (result.status === "unreconciled") {
        if ([result.currency, result.amount_cents, result.arrival_at, result.verified_at].some(value => value !== null)) return invalidModel(path);
    } else if (!result.currency || result.amount_cents === null || result.verified_at === null || result.verified_at <= 0) return invalidModel(path);
    return result;
};
const invoice = shape({
    id: stringValue, op: operation, client_id: stringValue, offer_id: stringValue, amount_cents: integerValue,
    currency: stringValue, billing_email: stringValue, days_until_due: integerValue, processor_invoice_ref: stringValue,
    hosted_invoice_url: nullable(stringValue), status: stringValue,
});
const refund = shape({
    id: stringValue, op: operation, transaction_id: stringValue, client_id: nullable(stringValue), offer_id: nullable(stringValue),
    amount_cents: integerValue, currency: stringValue, reason: stringValue, processor_refund_ref: stringValue, status: stringValue,
});
const readProcessor = shape({
    connected: booleanValue, connected_account_ref: nullable(stringValue),
    charges_ready: nullable(booleanValue), payouts_ready: nullable(booleanValue), verified_at: nullable(integerValue),
    freshness: oneOf("not-connected", "unreconciled", "processor-verified"),
});
const processor: ModelReader<ReturnType<typeof readProcessor>> = (value, path) => {
    const result = readProcessor(value, path);
    const verified = result.freshness === "processor-verified";
    if (result.connected !== Boolean(result.connected_account_ref)
        || (!result.connected && result.freshness !== "not-connected")
        || (result.connected && result.freshness === "not-connected")
        || (verified && (result.charges_ready === null || result.payouts_ready === null || result.verified_at === null || result.verified_at <= 0))
        || (!verified && (result.charges_ready !== null || result.payouts_ready !== null || result.verified_at !== null))) return invalidModel(path);
    return result;
};
export const commercialPageModels = {
    products: shape({ products: arrayOf(product), library }),
    clients: shape({ clients: arrayOf(client) }),
    engagements: shape({
        engagements: arrayOf(engagement), products: arrayOf(product), clients: arrayOf(client),
        settlement_policy: shape({ take_rate_bps: integerValue, metered_floor_cents: integerValue }), metering,
    }),
    payments: shape({
        processor_mode: oneOf("live", "test"),
        processor,
        engagements: arrayOf(engagement), products: arrayOf(product), clients: arrayOf(client),
        transactions: arrayOf(processorEvent), invoices: arrayOf(invoice), refunds: arrayOf(refund),
        processor_invoices: arrayOf(processorInvoice), processor_refunds: arrayOf(processorEvent), payouts: arrayOf(processorPayout),
        gross_cents: nullable(integerValue), refunded_cents: nullable(integerValue), platform_fees_cents: nullable(integerValue),
        currency_totals: arrayOf(shape({
            currency: stringValue, gross_cents: nullable(integerValue), platform_fees_cents: nullable(integerValue),
            refunded_cents: nullable(integerValue), pending_refund_cents: nullable(integerValue),
        })),
        metering, metered_cost_cents: nullable(integerValue), operational_freshness: stringValue,
    }),
} as const;
export type CommercialGaugeAppPageId = keyof typeof commercialPageModels;
export type CommercialGaugeAppPageData = { readonly [K in CommercialGaugeAppPageId]: ReturnType<(typeof commercialPageModels)[K]> };
export type ProductsPageV1 = CommercialGaugeAppPageData["products"];
export type ClientsPageV1 = CommercialGaugeAppPageData["clients"];
export type EngagementsPageV1 = CommercialGaugeAppPageData["engagements"];
export type CommercialPaymentsPageV1 = CommercialGaugeAppPageData["payments"];
