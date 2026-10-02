import { describe, expect, it } from "vitest";
import { homeExecutionPolicyClient, parseHomeExecutionPolicy, type HomeExecutionPolicyClientOptions } from "./home-execution-policy";
import { RemoteControlPlane } from "./remote-control-plane";

const reading = {
    policy: { version: 1, tenant_id: "organization:acme", isolated_workspace_enabled: true, max_attempt_nanos_usd: 10_000_000 },
    isolated_workspace: {
        available: true,
        enabled_by_tenant_policy: true,
        capabilities: ["build", "process", "test", "workspace"],
        compute_state: "per_attempt",
        reason: null,
        metering: { kind: "usage", reservation_nanos_usd: 10_000_000, nanos_usd_per_second: 50_000 },
    },
    pricing: { reservation_nanos_usd: 50_000_000, nanos_usd_per_second: 50_000 },
    can_edit: true,
    replayed: false,
};

describe("parseHomeExecutionPolicy", () => {
    it("reads the Home's policy, its metering and its own prices", () => {
        const parsed = parseHomeExecutionPolicy(reading);
        expect(parsed.policy.max_attempt_nanos_usd).toBe(10_000_000);
        expect(parsed.isolated_workspace.metering.nanos_usd_per_second).toBe(50_000);
        expect(parsed.pricing).toEqual({ reservation_nanos_usd: 50_000_000, nanos_usd_per_second: 50_000 });
        expect(parsed.can_edit).toBe(true);
        // Wire fields the page does not use stay out of it.
        expect("replayed" in parsed).toBe(false);
    });

    it("accepts a Home that predates reporting its own prices", () => {
        const { pricing: _pricing, ...older } = reading;
        expect(parseHomeExecutionPolicy(older).pricing).toBeNull();
    });

    it("refuses a reading that is not a policy", () => {
        expect(() => parseHomeExecutionPolicy({ ...reading, can_edit: "yes" })).toThrow();
        expect(() => parseHomeExecutionPolicy({ ...reading, policy: null })).toThrow();
    });
});

type FakeHome = ReturnType<NonNullable<HomeExecutionPolicyClientOptions["home"]>> & { readonly calls: string[] };

function fakeHome(admitted: string, { failWith }: { failWith?: Error } = {}): FakeHome {
    const calls: string[] = [];
    return {
        calls,
        admitHome: async () => { calls.push("admit"); return admitted; },
        revokeHomeAdmission: async () => { calls.push("revoke"); },
        homeExecutionPolicy: async () => {
            calls.push("read");
            if (failWith) throw failWith;
            return reading;
        },
        setHomeExecutionPolicy: async (change, key) => {
            calls.push(`set ${JSON.stringify(change)} ${key}`);
            if (failWith) throw failWith;
            return reading;
        },
    };
}

const host = { home_id: "home:cloud:acme", endpoint: "https://acme.home.example" };

describe("homeExecutionPolicyClient", () => {
    it("admits the host's own Home, calls it, and gives the admission back", async () => {
        const home = fakeHome(host.home_id);
        const endpoints: string[] = [];
        const client = homeExecutionPolicyClient({ bearer: () => "token", home: (endpoint) => { endpoints.push(endpoint); return home; } });
        await client.read(host);
        await client.set(host, { isolated_workspace_enabled: false, max_attempt_nanos_usd: 0 }, "key-1");
        expect(endpoints).toEqual([host.endpoint, host.endpoint]);
        expect(home.calls).toEqual([
            "admit", "read", "revoke",
            "admit", `set {"isolated_workspace_enabled":false,"max_attempt_nanos_usd":0} key-1`, "revoke",
        ]);
    });

    it("refuses a Home that answers as a different Home, and still gives the admission back", async () => {
        const home = fakeHome("home:cloud:someone-else");
        const client = homeExecutionPolicyClient({ bearer: () => "token", home: () => home });
        await expect(client.read(host)).rejects.toThrow(/no longer identifies as its registered Home/);
        expect(home.calls).toEqual(["admit", "revoke"]);
    });

    it("gives the admission back when the Home refuses the change", async () => {
        const home = fakeHome(host.home_id, { failWith: new Error("PUT /machine/execution-policy returned 403") });
        const client = homeExecutionPolicyClient({ bearer: () => "token", home: () => home });
        await expect(client.set(host, { isolated_workspace_enabled: true, max_attempt_nanos_usd: 1 }, "k")).rejects.toThrow(/403/);
        expect(home.calls.at(-1)).toBe("revoke");
    });
});

describe("RemoteControlPlane Isolated policy routes", () => {
    it("reads and sets the policy on the admitted Home with the caller's key", async () => {
        const calls: unknown[][] = [];
        const control = new RemoteControlPlane("https://home.example", {
            bearer: "owner-token",
            route: async (method, path, body, options) => {
                calls.push([method, path, body, options]);
                return reading;
            },
        });
        await control.homeExecutionPolicy();
        await control.setHomeExecutionPolicy({ isolated_workspace_enabled: true, max_attempt_nanos_usd: 5 }, "key-7");
        expect(calls).toEqual([
            ["GET", "/machine/execution-policy", undefined, undefined],
            ["PUT", "/machine/execution-policy", { isolated_workspace_enabled: true, max_attempt_nanos_usd: 5 }, { idempotencyKey: "key-7" }],
        ]);
    });
});
