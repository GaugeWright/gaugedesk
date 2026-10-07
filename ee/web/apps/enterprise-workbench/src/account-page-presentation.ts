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

const PROVIDER_NAMES: Readonly<Record<string, string>> = {
    "openai": "OpenAI",
    "anthropic": "Anthropic",
    "openai-generic": "your OpenAI-compatible endpoint",
    "openrouter": "OpenRouter",
    "xai": "xAI",
    "openai-codex": "ChatGPT / Codex",
    "xai-grok": "Grok",
};

/**
 * What to tell a person after revoking a trusted device. The device's copies
 * of their provider links are deleted, but it cannot unlearn a key it opened,
 * so the links it held are named for rotating (DR-0334 §5). `result` is the
 * revoke command's result as the server sent it.
 */
export function revokedDeviceNotice(result: unknown): string | null {
    const held = result && typeof result === "object" && Array.isArray((result as { held_links?: unknown }).held_links)
        ? (result as { held_links: unknown[] }).held_links.filter((provider): provider is string => typeof provider === "string")
        : [];
    if (held.length === 0) return null;
    const names = held.map((provider) => PROVIDER_NAMES[provider] ?? provider);
    const list = names.length === 1 ? names[0] : `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
    return `Device revoked. It held your ${list} ${held.length === 1 ? "link" : "links"}: if you no longer trust it, replace ${held.length === 1 ? "that key" : "those keys"} with the provider and link ${held.length === 1 ? "it" : "them"} again.`;
}
