import { describe, expect, expectTypeOf, it } from "vitest";
import { commercialPageModels, type CommercialGaugeAppPageData, type CommercialGaugeAppPageId } from "./gaugeapp-commercial-models";
import { parseCommercialGaugeAppPage, gaugeAppPageDefinitions } from "./gaugeapp-page-models";
import { commercialEmptyModels, commercialTestEngagement, commercialTestRevision, commercialTestInvoice, commercialTestPayout } from "./gaugeapp-commercial-models.fixture";

const counts = { open: 1, active: 0, closed: 0 };
const product = { id: "product-a", current_revision: 1, commercial: commercialTestRevision, engagement_counts: counts };
const client = { client: { id: "client-a", op: "upsert" as const, display_name: "Client", billing_reference: null, status: "active" as const }, engagement_counts: counts, participant_references: [...commercialTestEngagement.terms.proposal_recipients, commercialTestEngagement.terms.billing_recipient] };
const event = { event_id: "evt-a", event_type: "charge.succeeded", object_id: "ch-a", amount_cents: 1200, currency: "eur", status: "succeeded", engagement_id: "engagement-a", client_id: "client-a", payment_intent_id: "pi-a", platform_fee_cents: 120, created: 1800000000 };
const populated: CommercialGaugeAppPageData = {
    products: { products: [product], library: { availability: "available", home_ref: "home-a", reason: null, archetypes: [commercialTestRevision.archetype] } },
    clients: { clients: [client] },
    engagements: { ...commercialEmptyModels.engagements, products: [product], clients: [client], engagements: [commercialTestEngagement] },
    payments: { ...commercialEmptyModels.payments, products: [product], clients: [client], engagements: [commercialTestEngagement],
        transactions: [event], processor_invoices: [commercialTestInvoice], processor_refunds: [event], payouts: [commercialTestPayout],
        currency_totals: [{ currency: "eur", gross_cents: 1200, platform_fees_cents: 120, refunded_cents: 100, pending_refund_cents: 0 }],
        invoices: [{ id: "invoice-a", op: "upsert", client_id: "client-a", offer_id: "engagement-a", amount_cents: 1200, currency: "eur", billing_email: "billing@example.test", days_until_due: 14, processor_invoice_ref: "in-a", hosted_invoice_url: null, status: "open" }],
        refunds: [{ id: "refund-a", op: "upsert", transaction_id: "ch-a", client_id: "client-a", offer_id: "engagement-a", amount_cents: 100, currency: "eur", reason: "Duplicate", processor_refund_ref: "re-a", status: "pending" }],
    },
};
const page = (id: CommercialGaugeAppPageId, model: unknown) => ({ app: "commercial-operations", id, scope: { kind: "provider-tenant", id: "org-a" }, read_model: gaugeAppPageDefinitions[id][1], version: 1, resource_basis: "basis", freshness: "live", model });

describe("Commercial page contracts", () => {
    for (const id of Object.keys(commercialPageModels) as CommercialGaugeAppPageId[]) {
        it(`${id}: retains real empty and populated models`, () => {
            expect(parseCommercialGaugeAppPage(page(id, commercialEmptyModels[id])).model).toEqual(commercialEmptyModels[id]);
            expect(parseCommercialGaugeAppPage(page(id, populated[id])).model).toEqual(populated[id]);
        });
        it(`${id}: refuses missing required fields at every populated depth`, () => {
            const visit = (value: unknown, path: (string | number)[]) => {
                if (!value || typeof value !== "object") return;
                if (Array.isArray(value)) return value.forEach((entry, index) => visit(entry, [...path, index]));
                for (const key of Object.keys(value)) {
                    const changed = structuredClone(populated[id]);
                    let target: any = changed;
                    for (const part of path) target = target[part];
                    delete target[key];
                    expect(() => parseCommercialGaugeAppPage(page(id, changed)), `${id}.${[...path, key].join(".")}`).toThrow(/incompatible/);
                    visit((value as Record<string, unknown>)[key], [...path, key]);
                }
            };
            visit(populated[id], []);
        });
    }
    it("keeps unavailable metering distinct from zero cost", () => {
        const parsed = parseCommercialGaugeAppPage(page("payments", commercialEmptyModels.payments));
        if (parsed.id !== "payments") throw Error("wrong page");
        expectTypeOf(parsed.model.metered_cost_cents).toEqualTypeOf<number | null>();
        expect(parsed.model.metered_cost_cents).toBeNull();
        expect(parsed.model.metering.complete).toBe(false);
    });
    it("retains separate invoice amounts and rejects false verified or legacy financial states", () => {
        const unknown = { ...commercialTestInvoice, status: "unreconciled", currency: null, total_cents: null, amount_due_cents: null,
            amount_paid_cents: null, amount_remaining_cents: null, verified_at: null, due_at: null, hosted_invoice_url: null };
        for (const invoice of [unknown, { ...unknown, status: "deleted", verified_at: 1_800_000_000 }, { ...commercialTestInvoice, total_cents: -200 }]) {
            const parsed = parseCommercialGaugeAppPage(page("payments", { ...populated.payments, processor_invoices: [invoice] }));
            if (parsed.id !== "payments") throw Error("wrong page");
            expect(parsed.model.processor_invoices[0]).toEqual(invoice);
        }
        for (const invoice of [{ ...unknown, amount_paid_cents: 0 }, { ...unknown, verified_at: 1 },
            { ...commercialTestInvoice, verified_at: null }, { ...commercialTestInvoice, total_cents: Number.MAX_SAFE_INTEGER + 1 },
            { ...commercialTestInvoice, amount_remaining_cents: null }, { ...commercialTestInvoice, status: "deleted" }]) {
            expect(() => parseCommercialGaugeAppPage(page("payments", { ...populated.payments, processor_invoices: [invoice] }))).toThrow(/incompatible/);
        }
    });
    it("keeps unverified payouts unknown rather than zero or paid", () => {
        const unknown = { ...commercialTestPayout, status: "unreconciled", amount_cents: null, currency: null, arrival_at: null, verified_at: null };
        expect(() => parseCommercialGaugeAppPage(page("payments", { ...populated.payments, payouts: [unknown] }))).not.toThrow();
        for (const payout of [{ ...unknown, amount_cents: 0 }, { ...unknown, status: "paid" }, { ...commercialTestPayout, verified_at: null }])
            expect(() => parseCommercialGaugeAppPage(page("payments", { ...populated.payments, payouts: [payout] }))).toThrow(/incompatible/);
    });
    it("requires the server's explicit processor mode without defaulting unknown values to live", () => {
        for (const processor_mode of ["live", "test"] as const) {
            const parsed = parseCommercialGaugeAppPage(page("payments", { ...commercialEmptyModels.payments, processor_mode }));
            if (parsed.id !== "payments") throw Error("wrong page");
            expect(parsed.model.processor_mode).toBe(processor_mode);
        }
        for (const processor_mode of [undefined, null, "unknown", true]) {
            expect(() => parseCommercialGaugeAppPage(page("payments", { ...commercialEmptyModels.payments, processor_mode }))).toThrow(/processor_mode/);
        }
    });
    it("rejects mismatched product revisions and accepted agreements without snapshots", () => {
        for (const change of [{ product_revision: 2 }, { stage: "accepted" }, { stage: "unexpected-stage" }]) {
            expect(() => parseCommercialGaugeAppPage(page("engagements", { ...populated.engagements, engagements: [{ ...commercialTestEngagement, ...change }] }))).toThrow(/incompatible/);
        }
        const accepted = { ...commercialTestEngagement, stage: "active", agreement: { product: commercialTestRevision, terms: commercialTestEngagement.terms, accepted_by: commercialTestEngagement.terms.billing_recipient, accepted_at_ms: 1900000000000 } };
        expect(parseCommercialGaugeAppPage(page("engagements", { ...populated.engagements, engagements: [accepted] })).id).toBe("engagements");
    });
    it("keeps unknown payment readiness distinct from disabled and rejects contradictory evidence", () => {
        const unknown = { connected: true, connected_account_ref: "acct_test", charges_ready: null, payouts_ready: null, verified_at: null, freshness: "unreconciled" };
        const verified = { ...unknown, charges_ready: true, payouts_ready: false, verified_at: 1_800_000_000, freshness: "processor-verified" };
        for (const processor of [unknown, verified, commercialEmptyModels.payments.processor]) {
            const parsed = parseCommercialGaugeAppPage(page("payments", { ...commercialEmptyModels.payments, processor }));
            if (parsed.id !== "payments") throw Error("wrong page");
            expect(parsed.model.processor).toEqual(processor);
        }
        for (const processor of [
            { ...unknown, charges_ready: true }, { ...unknown, payouts_ready: false }, { ...unknown, verified_at: 1 },
            { ...verified, connected: false }, { ...verified, connected_account_ref: null },
            { ...verified, verified_at: null }, { ...verified, verified_at: 0 }, { ...verified, charges_ready: null },
            { ...unknown, freshness: "not-connected" }, { ...unknown, verified_at: undefined },
        ]) expect(() => parseCommercialGaugeAppPage(page("payments", { ...commercialEmptyModels.payments, processor }))).toThrow(/incompatible/);
    });
    it("retains server totals and distinguishes unknown refunds from zero", () => {
        const currency_totals = [
            { currency: "eur", gross_cents: 1200, platform_fees_cents: 120, refunded_cents: null, pending_refund_cents: null },
            { currency: "usd", gross_cents: 800, platform_fees_cents: 80, refunded_cents: 0, pending_refund_cents: 200 },
        ];
        const parsed = parseCommercialGaugeAppPage(page("payments", { ...populated.payments, gross_cents: null, refunded_cents: null, platform_fees_cents: null, currency_totals }));
        if (parsed.id !== "payments") throw Error("wrong page");
        expect(parsed.model.currency_totals).toEqual(currency_totals);
        expectTypeOf(parsed.model.currency_totals[0].refunded_cents).toEqualTypeOf<number | null>();
        expect(() => parseCommercialGaugeAppPage(page("payments", { ...populated.payments, currency_totals: [{ ...currency_totals[0], pending_refund_cents: Number.MAX_SAFE_INTEGER + 1 }] }))).toThrow(/pending_refund_cents/);
    });
    it("rejects unsafe amounts without leaking values and strips undeclared wire fields", () => {
        expect(() => parseCommercialGaugeAppPage(page("payments", { ...populated.payments, gross_cents: Number.MAX_SAFE_INTEGER + 1 }))).toThrow(/gross_cents/);
        expect(() => parseCommercialGaugeAppPage(page("payments", { ...populated.payments, gross_cents: "sensitive-value" }))).not.toThrow(/sensitive-value/);
        expect(parseCommercialGaugeAppPage(page("clients", { ...populated.clients, secret: "not-a-page-field" })).model).toEqual(populated.clients);
    });
});
