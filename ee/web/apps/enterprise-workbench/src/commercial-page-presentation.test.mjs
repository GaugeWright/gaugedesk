import assert from "node:assert/strict";
import test from "node:test";
import { priceDrafts, pricePayloads, validPriceDraft, priceSummary, commercialMoney, commercialAmountInput, commercialAmountStep, commercialMinorAmount, engagementPresentation, agentChoice, initialLibraryAgent, paymentRefundRows, paymentModeDescription, paymentReadinessLabel, paymentInvoiceRows, paymentPayoutRows } from "./commercial-page-presentation.ts";
import { commercialTestPrices, commercialTestEngagement, commercialTestRevision, commercialTestInvoice, commercialTestPayout } from "../../../../../web/packages/control-plane-client/src/gaugeapp-commercial-models.fixture.ts";

test("editing every price kind preserves currency, cadence, collection, unit and quantity bounds", () => {
    const drafts = priceDrafts(commercialTestPrices);
    assert.ok(drafts.every(validPriceDraft));
    assert.deepEqual(pricePayloads(drafts), commercialTestPrices);
    for (const patch of [{ amount: "" }, { amount: "NaN" }, { amount: "-1" }, { currency: "" }, { minimum: "5", maximum: "2" }, { minimum: "1.5" }]) {
        assert.equal(validPriceDraft({ ...drafts[0], ...patch }), false);
    }
    assert.match(priceSummary(commercialTestPrices), /EUR 12.00/);
    assert.equal(commercialMoney(1200, "eur"), "EUR 12.00");
});
test("processor minor units round-trip without assuming two decimal places", () => {
    assert.equal(commercialMoney(500, "jpy"), "JPY 500");
    assert.equal(commercialMoney(500, "usd"), "USD 5.00");
    assert.equal(commercialAmountInput(500, "jpy"), "500");
    assert.equal(commercialAmountInput(505, "usd"), "5.05");
    assert.equal(commercialMinorAmount("500", "jpy"), 500);
    assert.equal(commercialMinorAmount("5.05", "usd"), 505);
    assert.equal(commercialMinorAmount("5.5", "usd"), 550);
    assert.equal(commercialMinorAmount("5.01", "isk"), null);
    assert.equal(commercialMinorAmount("5", "isk"), 500);
    assert.equal(commercialMinorAmount("1.25", "jpy"), null);
    assert.equal(commercialMinorAmount("90071992547409.92", "usd"), null);
    assert.equal(commercialAmountStep("jpy"), "1");
    assert.equal(commercialAmountStep("isk"), "1");
    assert.equal(commercialAmountStep("usd"), "0.01");
    const jpy = { ...commercialTestPrices[0], currency: "jpy", amount_cents: 500 };
    assert.deepEqual(pricePayloads(priceDrafts([jpy])), [jpy]);
    assert.equal(validPriceDraft({ ...priceDrafts([jpy])[0], amount: "5.5" }), false);
});
test("engagement summaries use exact frozen revision, overrides, seats and discount", () => {
    const newer = { ...commercialTestRevision, revision: 2, listing_title: "New listing" };
    const terms = { ...commercialTestEngagement.terms, price_overrides: [{ ...commercialTestPrices[0], amount_cents: 3500 }] };
    const engagement = { ...commercialTestEngagement, product_commercial: newer, agreement: { product: commercialTestRevision, terms } };
    const result = engagementPresentation(engagement);
    assert.equal(result.product.revision, 1);
    assert.equal(result.product.listing_title, "Research");
    assert.equal(result.summary, "EUR 35.00 once · 3 seats · 15% discount");
    assert.equal(engagementPresentation(commercialTestEngagement).product.revision, 1);
});
test("same-name Library entries and different versions remain distinct choices", () => {
    const agent = commercialTestRevision.archetype;
    assert.notEqual(agentChoice(agent), agentChoice({ ...agent, id: "another-agent" }));
    assert.notEqual(agentChoice(agent), agentChoice({ ...agent, version: "2" }));
    assert.equal(initialLibraryAgent([agent], { ...agent, version: "0" }), undefined);
    assert.equal(initialLibraryAgent([agent], { ...agent, home_ref: "old-home" }), undefined);
    assert.equal(initialLibraryAgent([agent], { ...agent, id: "deleted-agent" }), undefined);
    assert.equal(initialLibraryAgent([agent], agent), agent);
    assert.equal(initialLibraryAgent([agent]), agent);
});
test("test payment accounts are explicitly labeled rather than presented as real money", () => {
    assert.equal(paymentModeDescription("test"), "Test mode. No real money is collected.");
    assert.equal(paymentModeDescription("live"), "Collect client payments through Stripe.");
});
test("connection, unverified readiness and processor-disabled collection remain distinct", () => {
    assert.equal(paymentReadinessLabel(false, null), "—");
    assert.equal(paymentReadinessLabel(true, null), "Not yet verified");
    assert.equal(paymentReadinessLabel(true, false), "Not enabled");
    assert.equal(paymentReadinessLabel(true, true), "Enabled");
});
test("invoice presentation uses current status and amounts, while deletion removes stale links", () => {
    const instructions = [{ processor_invoice_ref: "in-a", status: "paid", amount_cents: 9999, hosted_invoice_url: "https://invoice.stripe.com/i/old" }];
    const rows = paymentInvoiceRows({ processor_invoices: [commercialTestInvoice], invoices: instructions });
    assert.equal(rows[0].label, "Open"); assert.equal(rows[0].amount_remaining_cents, 600); assert.equal(rows[0].total_cents, 1200);
    assert.equal(rows[0].url, commercialTestInvoice.hosted_invoice_url);
    const deleted = { ...commercialTestInvoice, status: "deleted", hosted_invoice_url: null };
    assert.equal(paymentInvoiceRows({ processor_invoices: [deleted], invoices: instructions })[0].url, null);
    const unverified = { ...deleted, status: "unreconciled", total_cents: null, amount_paid_cents: null };
    const historical = paymentInvoiceRows({ processor_invoices: [unverified], invoices: instructions })[0];
    assert.equal(historical.label, "Awaiting verification"); assert.equal(historical.amount_paid_cents, null);
    assert.equal(historical.url, instructions[0].hosted_invoice_url);
});
test("payout bank returns and unverified history are not shown as paid money", () => {
    assert.deepEqual(paymentPayoutRows({ payouts: [commercialTestPayout] }), [{ id: "po-a", detail: "EUR 10.00 · Failed" }]);
    assert.equal(paymentPayoutRows({ payouts: [{ ...commercialTestPayout, status: "unreconciled", currency: null, amount_cents: null }] })[0].detail, "Awaiting verification");
    assert.equal(commercialMoney(null, null), "Unavailable");
});
test("refund rows use canonical processor evidence, not stale instructions", () => {
    const refund = { object_id: "re-a", currency: "eur", amount_cents: 200, status: "failed" };
    assert.deepEqual(paymentRefundRows({ processor_refunds: [refund], refunds: [
        { processor_refund_ref: "re-a", currency: "eur", amount_cents: 200, status: "succeeded" },
        { processor_refund_ref: "re-b", currency: "usd", amount_cents: 100, status: "pending" },
    ] }), [
        { id: "re-a", amount: "EUR 2.00", status: "Failed" },
        { id: "re-b", amount: "USD 1.00", status: "Awaiting reconciliation" },
    ]);
    for (const [status, label] of [["requires_action", "Action required in Stripe"], ["unreconciled", "Awaiting reconciliation"], ["unknown", "Status unavailable"], ["succeeded", "Refunded"], ["pending", "Pending"]]) {
        assert.equal(paymentRefundRows({ processor_refunds: [{ ...refund, status }], refunds: [] })[0].status, label);
    }
    assert.equal(commercialMoney(null, "eur"), "Unavailable");
    assert.equal(commercialMoney(0, "eur"), "EUR 0.00");
    assert.deepEqual(paymentRefundRows({ processor_refunds: [], refunds: [] }), []);
});
