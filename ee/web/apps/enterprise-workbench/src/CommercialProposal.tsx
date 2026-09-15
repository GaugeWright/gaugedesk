import { For, Show, type JSX } from "solid-js";
import type { CommercialProposalPreview } from "@gaugewright/enterprise-client";
import { commercialMoney } from "./commercial-page-presentation";

function record(value: unknown): Record<string, unknown> {
    return typeof value === "object" && value !== null && !Array.isArray(value)
        ? value as Record<string, unknown>
        : {};
}

function values(value: unknown): readonly unknown[] {
    return Array.isArray(value) ? value : [];
}

function text(value: unknown, fallback = "—"): string {
    return typeof value === "string" && value.trim() ? value : fallback;
}

function money(value: unknown, currency: unknown): string {
    return typeof value === "number" && typeof currency === "string"
        ? commercialMoney(value, currency)
        : "—";
}

function priceSummary(value: unknown): string {
    const parts = values(value).map((entry) => {
        const price = record(entry);
        if (price.kind === "one-time") return `${money(price.amount_cents, price.currency)} once`;
        if (price.kind === "recurring") return `${money(price.amount_cents, price.currency)}/${price.cadence === "annual" ? "year" : "month"}`;
        if (price.kind === "per-seat") return `${money(price.amount_cents, price.currency)}/seat/${price.cadence === "annual" ? "year" : "month"}`;
        if (price.kind === "metered-usage") return `${money(price.amount_cents, price.currency)}/${text(price.unit, "unit")}`;
        if (price.kind === "cost-plus") return `cost + ${typeof price.markup_basis_points === "number" ? price.markup_basis_points / 100 : 0}%`;
        return text(price.label, "Charge");
    });
    return parts.join(" · ") || "No charge stated";
}

function date(value: unknown): string {
    if (typeof value !== "number") return "—";
    const parsed = new Date(value);
    return Number.isNaN(parsed.valueOf()) ? "—" : parsed.toLocaleDateString();
}

export function ProposalChat(props: {
    readonly preview?: CommercialProposalPreview;
    readonly onClose: () => void;
}): JSX.Element {
    return <section class="proposal-chat">
        <header><span>Commercial proposal</span><button type="button" onClick={props.onClose}>Close</button></header>
        <div><strong>{props.preview?.provider_name ?? "Proposal"}</strong><p>Review the exact commercial terms in the content pane. Acceptance freezes this revision; it does not activate technical access or make a payment.</p></div>
    </section>;
}

export function ProposalContent(props: {
    readonly preview?: CommercialProposalPreview;
    readonly loading: boolean;
    readonly error?: unknown;
    readonly accepting: boolean;
    readonly actionError?: string;
    readonly onAccept: () => void;
}): JSX.Element {
    const product = () => record(props.preview?.product);
    const terms = () => record(props.preview?.terms);
    const prices = () => values(terms().price_overrides).length > 0
        ? terms().price_overrides
        : product().prices;
    const discount = () => {
        const basisPoints = terms().discount_basis_points;
        return typeof basisPoints === "number" ? `${basisPoints / 100}%` : "None";
    };
    return <main class="gaugeapp-content">
        <article class="gaugeapp-page proposal-page">
            <header class="gaugeapp-page-heading"><div><span class="gaugeapp-eyebrow">Commercial proposal</span><h1>{props.preview?.provider_name ?? "Proposal"}</h1></div><span class="gaugeapp-freshness">recipient copy</span></header>
            <Show when={!props.loading} fallback={<p class="gaugeapp-loading">Opening the proposal…</p>}>
                <Show when={!props.error && props.preview} fallback={<section class="gaugeapp-panel proposal-state"><strong>This proposal link cannot be opened.</strong><p>Ask the provider for a new link. No agreement was accepted.</p></section>}>
                    <section class="gaugeapp-panel proposal-sheet">
                        <header><div><span>Proposal for {props.preview?.client_name}</span><h2>{text(product().listing_title, "Product")}</h2><p>{text(product().description, "No description supplied.")}</p></div><strong>{priceSummary(prices())}</strong></header>
                        <div class="proposal-facts">
                            <div><span>Term</span><strong>{typeof terms().term_months === "number" ? `${terms().term_months} months` : "No fixed term"}</strong></div>
                            <div><span>Seats</span><strong>{typeof terms().seats === "number" ? String(terms().seats) : "Not seat-priced"}</strong></div>
                            <div><span>Discount</span><strong>{discount()}</strong></div>
                            <div><span>Payment due</span><strong>{typeof terms().payment_terms_days === "number" ? `${terms().payment_terms_days} days` : "—"}</strong></div>
                            <div><span>Starts</span><strong>{terms().start_rule === "fixed-date" ? date(terms().start_at_ms) : "On acceptance"}</strong></div>
                            <div><span>Valid through</span><strong>{date(terms().valid_until_ms)}</strong></div>
                        </div>
                        <Show when={values(product().service_obligations).length > 0}><section class="proposal-services"><strong>Services included</strong><For each={values(product().service_obligations)}>{(entry) => { const service = record(entry); return <div><span>{text(service.label)}</span><small>{text(service.description, text(service.cadence, "Included"))}</small></div>; }}</For></section></Show>
                        <Show when={text(terms().client_note, "")}><section class="proposal-note"><strong>Note</strong><p>{text(terms().client_note, "")}</p></section></Show>
                        <footer>
                            <Show when={props.actionError}><div class="proposal-decision"><strong>Agreement was not accepted</strong><span>{props.actionError}</span></div></Show>
                            <Show when={props.preview?.accepted}><div class="proposal-decision accepted"><strong>Agreement accepted</strong><span>The provider can now arrange delivery. Payment and technical access remain separate actions.</span></div></Show>
                            <Show when={props.preview?.expired && !props.preview?.accepted}><div class="proposal-decision"><strong>Proposal expired</strong><span>Ask the provider for a revised proposal.</span></div></Show>
                            <Show when={props.preview?.requires_account_sign_in && !props.preview?.accepted}><div class="proposal-decision"><strong>Sign in as the addressed recipient</strong><span>Sign in to GaugeDesk, then reopen the original proposal link.</span></div></Show>
                            <Show when={props.preview?.can_accept}><button type="button" class="primary" disabled={props.accepting} onClick={props.onAccept}>{props.accepting ? "Accepting…" : "Accept agreement"}</button></Show>
                        </footer>
                    </section>
                </Show>
            </Show>
        </article>
    </main>;
}

export function ProposalMenu(props: { readonly preview?: CommercialProposalPreview }): JSX.Element {
    return <nav class="gaugeapp-menu proposal-menu" aria-label="Proposal details">
        <h2>Proposal</h2>
        <div><span>Provider</span><strong>{props.preview?.provider_name ?? "—"}</strong></div>
        <div><span>Client</span><strong>{props.preview?.client_name ?? "—"}</strong></div>
        <div><span>Revision</span><strong>{props.preview?.proposal_revision ?? "—"}</strong></div>
        <div><span>Status</span><strong>{props.preview?.accepted ? "Accepted" : props.preview?.expired ? "Expired" : "Awaiting response"}</strong></div>
    </nav>;
}
