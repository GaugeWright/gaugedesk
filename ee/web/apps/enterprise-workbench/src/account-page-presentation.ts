import type { ProviderConnectionsPageV1, SubscriptionBilling } from "@gaugewright/control-plane-client";

export function subscriptionPresentation(billing: SubscriptionBilling) {
    const blocked = billing.verification === "unverified" || billing.verification === "unavailable";
    const issue = billing.verification === "unverified"
        ? "Existing billing records need processor verification before this plan can be managed."
        : billing.verification === "unavailable" ? "Subscription verification is unavailable. Existing records have not been replaced." : null;
    const mode = billing.processor_mode === "test" ? "Test subscription" : null;
    const status = blocked ? "Not verified" : billing.subscription?.status ?? "Not enrolled";
    return { blocked, issue, mode, status, canManage: !blocked && (billing.customer_linked || billing.configured_plan.checkout_available) } as const;
}

export function managedInferencePresentation(managed: ProviderConnectionsPageV1["managed_inference"]) {
    const action = managed.billing.customer_linked ? "manage" : "subscribe";
    const current = subscriptionPresentation(managed.billing);
    const available = current.canManage;
    return {
        action,
        label: action === "manage" ? "Manage plan" : "Choose plan",
        available,
        unavailableReason: current.issue ?? (available ? null : "Managed inference signup is not available right now."),
        description: current.blocked ? "Plan status is not verified."
            : managed.usage.unattributed_runs > 0
            ? `${managed.usage.total_tokens.toLocaleString()} tokens are assigned to this billing period. ${managed.usage.unattributed_tokens.toLocaleString()} older tokens remain visible but are not assigned to the current allowance.`
            : managed.billing.subscription
            ? `${current.mode ? `${current.mode} · ` : ""}${managed.plan?.plan ?? managed.billing.configured_plan.name} · ${current.status}. ${managed.usage.total_tokens.toLocaleString()} tokens recorded · ${managed.usage.included_tokens.toLocaleString()} included.`
            : "Use GaugeWright-managed model access without bringing a provider account.",
    } as const;
}
