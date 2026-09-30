import { describe, expect, it, vi } from "vitest";
import { productAnalyticsPolicy, productAnalyticsRecord, type ProductEvent } from "./product-analytics";
import type { RouteJson } from "./control-plane-transport";

const event: ProductEvent = {
    version: 1,
    id: "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa",
    tenant: "org:health",
    feature: "chat.turn",
    outcome: "completed",
    platform: "web",
    release: "0.4.30",
};

describe("product analytics policy", () => {
    it("never sends a product event when the tenant is disabled", async () => {
        const json = vi.fn(async () => ({ enabled: false, person_enabled: true, tenant_disabled: true, tenant_locked_off: true, can_manage_tenant: false })) as unknown as RouteJson;
        await productAnalyticsRecord(json, event);
        expect(json).toHaveBeenCalledTimes(1);
        expect(json).toHaveBeenCalledWith("GET", "/product-analytics/policy?tenant=org%3Ahealth");
    });

    it("fails closed when the policy is unavailable or malformed", async () => {
        const missing = vi.fn(async () => { throw new Error("unavailable"); }) as unknown as RouteJson;
        await expect(productAnalyticsRecord(missing, event)).rejects.toThrow("unavailable");
        expect(missing).toHaveBeenCalledTimes(1);
        const malformed = vi.fn(async () => ({ enabled: true })) as unknown as RouteJson;
        await expect(productAnalyticsPolicy(malformed, event.tenant)).rejects.toThrow("malformed");
        expect(malformed).toHaveBeenCalledTimes(1);
    });

    it("sends only the closed event body after a current allow", async () => {
        const json = vi.fn(async (method: string) => method === "GET"
            ? { enabled: true, person_enabled: true, tenant_disabled: false, tenant_locked_off: false, can_manage_tenant: false }
            : null) as unknown as RouteJson;
        await productAnalyticsRecord(json, event);
        expect(json).toHaveBeenNthCalledWith(2, "POST", "/product-analytics/events", event);
    });
});
