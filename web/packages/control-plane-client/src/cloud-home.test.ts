import { describe, expect, it, vi } from "vitest";
import { getCloudHome } from "./cloud-home";
import type { RouteJson } from "./control-plane-transport";

function fakeJson(response: unknown): { json: RouteJson; calls: [string, string, unknown?][] } {
    const calls: [string, string, unknown?][] = [];
    const json = vi.fn(async (method: string, path: string, body?: unknown) => {
        calls.push([method, path, body]);
        return response;
    }) as unknown as RouteJson;
    return { json, calls };
}

const response = {
    facility: {
        status: "active",
        config: {
            home_id: "home:cloud:abc",
            endpoint: "https://abc.home.gaugewright.com",
            region: "eastus",
            subscription: "active",
        },
    },
    usage: {
        storage_bytes: 42,
        storage_limit_bytes: 1000,
        concurrent_agent_limit: 2,
    },
};

describe("Cloud Home client (HOME-5)", () => {
    it("parses the tenant facility projection", async () => {
        const { json, calls } = fakeJson(response);
        const home = await getCloudHome(json, "personal/root");
        expect(calls[0]).toEqual(["GET", "/account/tenants/personal%2Froot/cloud-home", undefined]);
        expect(home).toMatchObject({
            tenant: "personal/root",
            homeId: "home:cloud:abc",
            status: "active",
            storageBytes: 42,
            compute: "scale_to_zero",
        });
    });

    it("rejects a malformed facility projection", async () => {
        await expect(getCloudHome(fakeJson({}).json, "tenant")).rejects.toThrow("malformed");
    });
});
