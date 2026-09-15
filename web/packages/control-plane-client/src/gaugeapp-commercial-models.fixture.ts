import type { CommercialGaugeAppPageData, CommercialPrice, CommercialProductRevision, CommercialEngagement } from "./gaugeapp-commercial-models";

export const commercialEmptyModels: CommercialGaugeAppPageData = {
    products: { products: [], library: { availability: "unavailable", reason: "Home unavailable", home_ref: null, archetypes: [] } },
    clients: { clients: [] },
    engagements: {
        engagements: [], products: [], clients: [], settlement_policy: { take_rate_bps: 0, metered_floor_cents: 0 },
        metering: { status: "no_edge_deployments", complete: true, metered_cost_cents: 0, reserved_cents: 0, deployments: [], unmatched_deployment_refs: [], basis: "edge authority" },
    },
    payments: {
        processor_mode: "live",
        processor: { connected: false, connected_account_ref: null, charges_ready: null, payouts_ready: null, verified_at: null, freshness: "not-connected" },
        engagements: [], products: [], clients: [], transactions: [], invoices: [], refunds: [], processor_invoices: [], processor_refunds: [], payouts: [],
        gross_cents: 0, refunded_cents: 0, platform_fees_cents: 0, currency_totals: [],
        metering: { status: "unavailable", complete: false, metered_cost_cents: null, reserved_cents: null, deployments: [], unmatched_deployment_refs: ["deployment-a"], basis: "edge authority" },
        metered_cost_cents: null, operational_freshness: "webhook-admitted",
    },
};
export const commercialTestInvoice: CommercialGaugeAppPageData["payments"]["processor_invoices"][number] = {
    object: "invoice", object_id: "in-a", status: "open", currency: "eur", total_cents: 1200,
    amount_due_cents: 1000, amount_paid_cents: 400, amount_remaining_cents: 600, due_at: 1_900_000_000,
    hosted_invoice_url: "https://invoice.stripe.com/i/test", engagement_id: "engagement-a", client_id: "client-a", verified_at: 1_800_000_000,
};
export const commercialTestPayout: CommercialGaugeAppPageData["payments"]["payouts"][number] = {
    object: "payout", object_id: "po-a", status: "failed", currency: "eur", amount_cents: 1000, arrival_at: 1_900_000_000, verified_at: 1_800_000_000,
};
export const commercialTestPrices: readonly CommercialPrice[] = ["one-time", "recurring", "per-seat", "metered-usage", "cost-plus"].map((kind, index) => ({
    id: `charge-${index}`, label: kind, kind: kind as CommercialPrice["kind"], currency: "eur",
    amount_cents: kind === "cost-plus" ? null : 1200, markup_basis_points: kind === "cost-plus" ? 1500 : null,
    cadence: kind === "one-time" ? null : "annual", collection: "in-arrears",
    unit: kind === "metered-usage" ? "request" : null, minimum_quantity: 1, maximum_quantity: 10,
}));
export const commercialTestRevision: CommercialProductRevision = {
    id: "product-a:revision:1", op: "upsert", product_id: "product-a", revision: 1,
    archetype: { id: "agent-a", name: "Research", kind: "agent", version: "1", home_ref: "home-a" },
    sale_version_policy: "pinned-version", listing_title: "Research", description: "Research service", prices: commercialTestPrices,
    delivery: "customer-project-placement", service_obligations: [{ id: "service-a", label: "Source review", description: "Review sources", cadence: "monthly" }],
};
export const commercialTestEngagement: CommercialEngagement = {
    id: "engagement-a", op: "upsert", product_id: "product-a", product_revision: 1, proposal_revision: 1, client_id: "client-a", stage: "draft",
    terms: {
        seats: 3, discount_basis_points: 1500, price_overrides: [], term_months: 12, start_rule: "fixed-date", start_at_ms: 1900000000000,
        renewal: "annual", payment_terms_days: 14, valid_until_ms: 2000000000000,
        proposal_recipients: [{ kind: "account", account_id: "person-a", purpose: "proposal" }],
        billing_recipient: { kind: "manual", name: "Client", email: "billing@example.test", purpose: "billing" }, client_note: "Note",
    },
    sent_at_ms: null, agreement: null, placement_ref: null, entitlement: "inactive", entitlement_ref: null, payment_refs: [], product_commercial: commercialTestRevision,
};
