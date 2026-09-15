import type { CommercialArchetypeRef, CommercialEngagement, CommercialPrice, CommercialPaymentsPageV1 } from "@gaugewright/control-plane-client";

export interface PriceDraft {
    readonly id: string;
    readonly label: string;
    readonly kind: CommercialPrice["kind"];
    readonly currency: string;
    readonly amount: string;
    readonly cadence: "" | NonNullable<CommercialPrice["cadence"]>;
    readonly collection: CommercialPrice["collection"];
    readonly unit: string;
    readonly minimum: string;
    readonly maximum: string;
}

// Stripe calls every API amount a minor-unit amount, even for currencies whose
// display unit has no decimal fraction. ISK and UGX retain Stripe's historical
// two-place API representation but cannot be charged fractionally.
const ZERO_DECIMAL_CHARGE_CURRENCIES = new Set([
    "bif", "clp", "djf", "gnf", "jpy", "kmf", "krw", "mga", "pyg", "rwf",
    "vnd", "vuv", "xaf", "xof", "xpf",
]);
const WHOLE_UNIT_TWO_PLACE_CURRENCIES = new Set(["isk", "ugx"]);

export const commercialCurrencyExponent = (currency: string): 0 | 2 =>
    ZERO_DECIMAL_CHARGE_CURRENCIES.has(currency.trim().toLowerCase()) ? 0 : 2;

export const commercialAmountStep = (currency: string): string =>
    commercialCurrencyExponent(currency) === 0 || WHOLE_UNIT_TWO_PLACE_CURRENCIES.has(currency.trim().toLowerCase()) ? "1" : "0.01";

export function commercialAmountInput(amountMinor: number, currency: string): string {
    const exponent = commercialCurrencyExponent(currency);
    if (exponent === 0) return String(amountMinor);
    const whole = Math.floor(amountMinor / 100);
    const fraction = String(amountMinor % 100).padStart(2, "0");
    return fraction === "00" ? String(whole) : `${whole}.${fraction}`;
}

export function commercialMinorAmount(input: string, currency: string): number | null {
    const match = /^(\d+)(?:\.(\d+))?$/.exec(input.trim());
    if (!match) return null;
    const exponent = commercialCurrencyExponent(currency);
    const fraction = match[2] ?? "";
    if (fraction.length > exponent) return null;
    if (exponent === 0 && fraction && !/^0+$/.test(fraction)) return null;
    if (WHOLE_UNIT_TWO_PLACE_CURRENCIES.has(currency.trim().toLowerCase()) && fraction && !/^0+$/.test(fraction)) return null;
    const scale = exponent === 0 ? 1n : 100n;
    const paddedFraction = exponent === 0 ? 0n : BigInt(fraction.padEnd(2, "0") || "0");
    const amount = BigInt(match[1]) * scale + paddedFraction;
    return amount <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(amount) : null;
}

const basisPoints = (input: string): number | null => commercialMinorAmount(input, "usd");

export const freshPrice = (currency = "usd"): PriceDraft => ({ id: `price-${crypto.randomUUID()}`, label: "Monthly service", kind: "recurring", currency, amount: "", cadence: "monthly", collection: "in-advance", unit: "", minimum: "", maximum: "" });
export const priceDrafts = (prices: readonly CommercialPrice[]): readonly PriceDraft[] => prices.map((price) => ({
    id: price.id, label: price.label, kind: price.kind, currency: price.currency,
    amount: price.kind === "cost-plus"
        ? commercialAmountInput(price.markup_basis_points!, "usd")
        : commercialAmountInput(price.amount_cents!, price.currency),
    cadence: price.cadence ?? "", collection: price.collection, unit: price.unit ?? "",
    minimum: price.minimum_quantity === null ? "" : String(price.minimum_quantity),
    maximum: price.maximum_quantity === null ? "" : String(price.maximum_quantity),
}));
export const validPriceDraft = (price: PriceDraft): boolean => {
    const quantity = (value: string) => !value || (Number.isSafeInteger(Number(value)) && Number(value) >= 0);
    const amount = price.kind === "cost-plus" ? basisPoints(price.amount) : commercialMinorAmount(price.amount, price.currency);
    return Boolean(price.label.trim() && /^[a-z]{3}$/i.test(price.currency) && price.amount.trim() &&
        amount !== null && (price.kind === "cost-plus" ? amount >= 0 && amount <= 100_000 : amount > 0) &&
        (!(price.kind === "recurring" || price.kind === "per-seat") || price.cadence) &&
        (price.kind !== "metered-usage" || price.unit.trim()) && quantity(price.minimum) && quantity(price.maximum) &&
        (!price.minimum || !price.maximum || Number(price.minimum) <= Number(price.maximum)));
};
export const pricePayloads = (prices: readonly PriceDraft[]): readonly CommercialPrice[] => prices.map((price) => ({
    id: price.id, label: price.label.trim(), kind: price.kind, currency: price.currency.trim().toLowerCase(),
    amount_cents: price.kind === "cost-plus" ? null : commercialMinorAmount(price.amount, price.currency)!,
    markup_basis_points: price.kind === "cost-plus" ? basisPoints(price.amount)! : null,
    cadence: price.kind === "one-time" ? null : price.cadence || null, collection: price.collection, unit: price.unit.trim() || null,
    minimum_quantity: price.minimum ? Number(price.minimum) : null, maximum_quantity: price.maximum ? Number(price.maximum) : null,
}));
export const commercialMoney = (amountMinor: number | null, currency: string | null): string => {
    if (amountMinor === null || currency === null) return "Unavailable";
    const exponent = commercialCurrencyExponent(currency);
    const scale = exponent === 0 ? 1 : 100;
    return `${currency.toUpperCase()} ${(amountMinor / scale).toLocaleString(undefined, { minimumFractionDigits: exponent, maximumFractionDigits: exponent })}`;
};
export function priceSummary(prices: readonly CommercialPrice[]): string {
    return prices.map((price) => {
        const amount = price.amount_cents === null ? "" : commercialMoney(price.amount_cents, price.currency);
        const cadence = price.cadence === "annual" ? "year" : "month";
        switch (price.kind) {
            case "one-time": return `${amount} once`;
            case "recurring": return `${amount}/${cadence}`;
            case "per-seat": return `${amount}/seat/${cadence}`;
            case "metered-usage": return `${amount}/${price.unit}`;
            case "cost-plus": return `${price.currency.toUpperCase()} cost + ${(price.markup_basis_points ?? 0) / 100}%`;
        }
    }).join(" · ") || "No price";
}
export function engagementPresentation(engagement: CommercialEngagement) {
    const product = engagement.agreement?.product ?? engagement.product_commercial;
    const terms = engagement.agreement?.terms ?? engagement.terms;
    const prices = terms.price_overrides.length ? terms.price_overrides : product.prices;
    const adjustments = [terms.seats === null ? "" : `${terms.seats} seats`, terms.discount_basis_points ? `${terms.discount_basis_points / 100}% discount` : ""].filter(Boolean);
    return { product, terms, prices, summary: [priceSummary(prices), ...adjustments].join(" · ") };
}
// Choosing an Agent must never silently replace a missing or older reference.
export const agentChoice = (agent: CommercialArchetypeRef) => `${agent.name} · ${agent.kind === "panel-agent" ? "Panel agent" : "Agent"} · v${agent.version} · ${agent.id}`;
export function initialLibraryAgent(agents: readonly CommercialArchetypeRef[], current?: CommercialArchetypeRef) {
    return current ? agents.find((agent) => agent.id === current.id && agent.kind === current.kind && agent.version === current.version && agent.home_ref === current.home_ref) : agents[0];
}
// Totals come from the settlement projection. Only row presentation belongs here;
// a local instruction's original status must not override processor evidence.
export const paymentModeDescription = (mode: CommercialPaymentsPageV1["processor_mode"]): string =>
    mode === "test" ? "Test mode. No real money is collected." : "Collect client payments through Stripe.";
export const paymentReadinessLabel = (connected: boolean, ready: boolean | null): string =>
    !connected ? "—" : ready === null ? "Not yet verified" : ready ? "Enabled" : "Not enabled";
export function paymentInvoiceRows(model: Pick<CommercialPaymentsPageV1, "processor_invoices" | "invoices">) {
    const labels = { unreconciled: "Awaiting verification", unknown: "Status unavailable", draft: "Draft", open: "Open", paid: "Paid", uncollectible: "Uncollectible", void: "Void", deleted: "Deleted" };
    return model.processor_invoices.map(invoice => ({ ...invoice, label: labels[invoice.status],
        url: invoice.status === "deleted" ? null : invoice.hosted_invoice_url ?? (
            invoice.status === "unreconciled" ? model.invoices.find(instruction => instruction.processor_invoice_ref === invoice.object_id)?.hosted_invoice_url ?? null : null),
    }));
}
export function paymentPayoutRows(model: Pick<CommercialPaymentsPageV1, "payouts">) {
    const labels = { unreconciled: "Awaiting verification", pending: "Pending", in_transit: "In transit", paid: "Paid", failed: "Failed", canceled: "Canceled" };
    return model.payouts.map(payout => ({ id: payout.object_id, detail: payout.status === "unreconciled" ? labels[payout.status] : `${commercialMoney(payout.amount_cents, payout.currency)} · ${labels[payout.status]}` }));
}
export function paymentRefundRows(model: Pick<CommercialPaymentsPageV1, "processor_refunds" | "refunds">) {
    const statusLabel = (status: string): string => ({
        succeeded: "Refunded", pending: "Pending", requires_action: "Action required in Stripe",
        failed: "Failed", canceled: "Canceled", unreconciled: "Awaiting reconciliation",
    })[status] ?? "Status unavailable";
    const observed = new Set(model.processor_refunds.map((refund) => refund.object_id));
    return [
        ...model.processor_refunds.map((refund) => ({ id: refund.object_id, amount: commercialMoney(refund.amount_cents, refund.currency), status: statusLabel(refund.status) })),
        ...model.refunds.filter((refund) => !observed.has(refund.processor_refund_ref)).map((refund) => ({
            id: refund.processor_refund_ref || refund.id, amount: commercialMoney(refund.amount_cents, refund.currency), status: "Awaiting reconciliation",
        })),
    ];
}
