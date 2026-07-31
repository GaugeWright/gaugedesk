import { describe, expect, it, vi } from "vitest";
import { tenantHosts } from "./registered-host";
import type { RouteJson } from "./control-plane-transport";

function route(response: unknown) {
    const calls: Array<[string, string, unknown?]> = [];
    const json = vi.fn(async (method: string, path: string, body?: unknown) => {
        calls.push([method, path, body]);
        return response;
    }) as unknown as RouteJson;
    return { json, calls };
}

const host = {
    id: "registered-host:home:studio",
    display_name: "Studio Mac",
    home_id: "home:studio",
    endpoint: "https://studio.example",
};

describe("tenant registered computers", () => {
    it("reads the tenant-scoped host projection", async () => {
        const fake = route({ hosts: [host] });
        await expect(tenantHosts(fake.json, "acme")).resolves.toEqual([{
            id: host.id,
            displayName: "Studio Mac",
            homeId: "home:studio",
            endpoint: "https://studio.example",
        }]);
        expect(fake.calls).toEqual([["GET", "/account/tenants/acme/hosts", undefined]]);
    });
});
