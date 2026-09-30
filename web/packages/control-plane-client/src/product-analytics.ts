/** Authenticated GaugeDesk product analytics (GaugeWright DR-0181).
 *
 * The server derives person identity from the session. These values are a
 * closed, content-free vocabulary; callers cannot add arbitrary properties.
 */
import type { RouteJson } from "./control-plane-transport";

export const PRODUCT_ANALYTICS_SETTING = "product.analytics.enabled";

export type ProductFeature = "chat.create" | "chat.turn";
export type ProductOutcome = "completed" | "failed";
export type ProductPlatform = "web" | "desktop" | "mobile";

export interface ProductAnalyticsPolicy {
    readonly enabled: boolean;
    readonly person_enabled: boolean;
    readonly tenant_disabled: boolean;
    readonly tenant_locked_off: boolean;
    readonly can_manage_tenant: boolean;
}

export interface ProductEvent {
    readonly version: 1;
    readonly id: string;
    readonly tenant: string;
    readonly feature: ProductFeature;
    readonly outcome: ProductOutcome;
    readonly platform: ProductPlatform;
    readonly release: string;
}

export async function productAnalyticsPolicy(json: RouteJson, tenant: string): Promise<ProductAnalyticsPolicy> {
    const value = await json("GET", `/product-analytics/policy?tenant=${encodeURIComponent(tenant)}`) as Partial<ProductAnalyticsPolicy>;
    if (typeof value.enabled !== "boolean" || typeof value.person_enabled !== "boolean"
        || typeof value.tenant_disabled !== "boolean" || typeof value.tenant_locked_off !== "boolean"
        || typeof value.can_manage_tenant !== "boolean") {
        throw new Error("product analytics policy response is malformed");
    }
    return value as ProductAnalyticsPolicy;
}

export async function productAnalyticsSetTenantDisabled(json: RouteJson, tenant: string, disabled: boolean): Promise<void> {
    await json("PUT", `/product-analytics/tenants/${encodeURIComponent(tenant)}/policy`, { disabled });
}

export async function productAnalyticsRecord(
    json: RouteJson,
    event: ProductEvent,
    maySend: () => boolean = () => true,
): Promise<void> {
    // A fresh policy read prevents a current client from sending an event for an
    // analytics-off tenant. The server repeats the check at write time, so stale
    // and modified clients cannot turn an earlier permission into authority.
    const policy = await productAnalyticsPolicy(json, event.tenant);
    if (!policy.enabled || !maySend()) return;
    await json("POST", "/product-analytics/events", event);
}
