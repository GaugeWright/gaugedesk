import { describe, expect, it } from "vitest";
import {
    type HomeId,
    type OpaqueHomeRoute,
    type ProjectId,
    type RouteJson,
} from "@gaugewright/control-plane-client";
import {
    accountTokenExpiresWithin,
    MobileHomePool,
    MobileRouteCache,
} from "./mobile-home-pool";

const project = (id: string) => id as ProjectId;
const home = (id: string) => id as HomeId;

const routes: OpaqueHomeRoute[] = [
    {
        project: project("project:one"),
        homeId: home("home:one"),
        endpoint: "https://one.example",
    },
    {
        project: project("project:two"),
        homeId: home("home:two"),
        endpoint: "https://two.example",
    },
];

function recorder(announced: Record<string, string> = {}) {
    const calls: string[] = [];
    const factory = (endpoint: string): RouteJson =>
        async (method, path) => {
            calls.push(`${method} ${endpoint}${path}`);
            if (method === "POST" && path === "/home/admissions") {
                const expected = endpoint.includes("one") ? "home:one" : "home:two";
                return {
                    home: announced[endpoint] ?? expected,
                    admission: `admission:${expected}`,
                };
            }
            return null;
        };
    return { calls, factory };
}

describe("MobileHomePool", () => {
    it("admits the exact routed Home and reuses only that Home's session", async () => {
        const { calls, factory } = recorder();
        const pool = new MobileHomePool(routes, () => "account-token", {
            routeJson: factory,
        });

        const first = await pool.connectProject(project("project:one"));
        const reused = await pool.connectProject(project("project:one"));
        expect(first.homeId).toBe("home:one");
        expect(reused.homeId).toBe("home:one");
        expect(calls).toEqual(["POST https://one.example/home/admissions"]);
    });

    it("rejects a wrong-Home response and tears down its admission", async () => {
        const { calls, factory } = recorder({
            "https://one.example": "home:forged",
        });
        const pool = new MobileHomePool(routes, () => "account-token", {
            routeJson: factory,
        });

        await expect(pool.connectProject(project("project:one"))).rejects.toThrow(
            "expected home:one",
        );
        expect(calls).toEqual([
            "POST https://one.example/home/admissions",
            "DELETE https://one.example/home/admissions",
        ]);
        expect(pool.snapshot()).toEqual([]);
    });

    it("keeps independent Homes and evicts the least-recent one at the bound", async () => {
        let now = 1;
        const { calls, factory } = recorder();
        const pool = new MobileHomePool(routes, () => "account-token", {
            routeJson: factory,
            maxConnections: 1,
            now: () => now,
        });
        await pool.connectProject(project("project:one"));
        now = 2;
        await pool.connectProject(project("project:two"));

        expect(pool.snapshot().map((connection) => connection.homeId)).toEqual([
            "home:two",
        ]);
        expect(calls).toContain("DELETE https://one.example/home/admissions");
    });

    it("coalesces concurrent selections into one exact-Home admission", async () => {
        const { calls, factory } = recorder();
        const pool = new MobileHomePool(routes, () => "account-token", {
            routeJson: factory,
        });
        const [first, second] = await Promise.all([
            pool.connectProject(project("project:one")),
            pool.connectProject(project("project:one")),
        ]);
        expect(first.homeId).toBe("home:one");
        expect(second.homeId).toBe("home:one");
        expect(calls).toEqual(["POST https://one.example/home/admissions"]);
    });

    it("retires the old admission when a project route moves Homes", async () => {
        const { calls, factory } = recorder();
        const pool = new MobileHomePool([routes[0]], () => "account-token", {
            routeJson: factory,
        });
        await pool.connectProject(project("project:one"));
        pool.replaceRoutes([{
            project: project("project:one"),
            homeId: home("home:two"),
            endpoint: "https://two.example",
        }]);
        const moved = await pool.connectProject(project("project:one"));
        expect(moved.homeId).toBe("home:two");
        expect(calls).toEqual([
            "POST https://one.example/home/admissions",
            "DELETE https://one.example/home/admissions",
            "POST https://two.example/home/admissions",
        ]);
    });

    it("cannot publish an admission whose project route moved in flight", async () => {
        let release: ((value: unknown) => void) | null = null;
        const calls: string[] = [];
        const routeJson = (endpoint: string): RouteJson =>
            async (method, path) => {
                calls.push(`${method} ${endpoint}${path}`);
                if (method === "POST" && path === "/home/admissions") {
                    return await new Promise((resolve) => {
                        release = resolve;
                    });
                }
                return null;
            };
        const pool = new MobileHomePool([routes[0]], () => "account-token", {
            routeJson,
        });
        const pending = pool.connectProject(project("project:one"));
        await Promise.resolve();
        pool.replaceRoutes([{
            project: project("project:one"),
            homeId: home("home:two"),
            endpoint: "https://two.example",
        }]);
        if (!release) throw new Error("admission did not begin");
        (release as (value: unknown) => void)({
            home: "home:one",
            admission: "admission:home:one",
        });

        await expect(pending).rejects.toThrow("route changed");
        expect(pool.snapshot()).toEqual([]);
        expect(calls).toEqual([
            "POST https://one.example/home/admissions",
            "DELETE https://one.example/home/admissions",
        ]);
    });

    it("closes every live Home on account sign-out", async () => {
        const { calls, factory } = recorder();
        const pool = new MobileHomePool(routes, () => "account-token", {
            routeJson: factory,
        });
        await pool.connectProject(project("project:one"));
        await pool.connectProject(project("project:two"));
        await pool.closeAll();
        expect(pool.snapshot()).toEqual([]);
        expect(calls).toContain("DELETE https://one.example/home/admissions");
        expect(calls).toContain("DELETE https://two.example/home/admissions");
    });

    it("marks only the failing Home offline and readmits it on retry", async () => {
        const states: string[] = [];
        const routeJson = (endpoint: string): RouteJson =>
            async (method, path) => {
                if (method === "POST" && path === "/home/admissions") {
                    const suffix = endpoint.includes("one") ? "one" : "two";
                    return {
                        home: `home:${suffix}`,
                        admission: `admission:${suffix}`,
                    };
                }
                if (path === "/tasks") {
                    if (endpoint.includes("one")) {
                        throw new TypeError("fetch failed");
                    }
                    return { tasks: [] };
                }
                return null;
            };
        const pool = new MobileHomePool(routes, () => "account-token", {
            routeJson,
            onStateChange: (homeId, state) => states.push(`${homeId}:${state}`),
        });
        const one = await pool.connectProject(project("project:one"));
        const two = await pool.connectProject(project("project:two"));

        await expect(one.api.getTasks()).rejects.toThrow(/fetch failed/i);
        expect(one.state).toBe("offline");
        expect(two.state).toBe("live");
        const repaired = await pool.connectProject(project("project:one"));
        expect(repaired.state).toBe("live");
        expect(states).toContain("home:one:offline");
    });

    it("does not admit without account authority", async () => {
        const { factory } = recorder();
        const pool = new MobileHomePool(routes, () => null, { routeJson: factory });
        await expect(pool.connectProject(project("project:one"))).rejects.toThrow(
            "sign in",
        );
    });
});

describe("mobile account refresh timing", () => {
    const token = (exp: number) => {
        const encoded = btoa(JSON.stringify({ exp }))
            .replace(/\+/g, "-")
            .replace(/\//g, "_")
            .replace(/=+$/, "");
        return `header.${encoded}.signature`;
    };

    it("refreshes before expiry and rejects malformed expiry as stale", () => {
        expect(accountTokenExpiresWithin(token(2_000), 300, 1_800)).toBe(true);
        expect(accountTokenExpiresWithin(token(2_000), 100, 1_800)).toBe(false);
        expect(accountTokenExpiresWithin("not-a-token", 100, 1_800)).toBe(true);
    });
});

describe("MobileRouteCache", () => {
    it("partitions secret-free routes by account identity", () => {
        const values = new Map<string, string>();
        const storage = {
            getItem: (key: string) => values.get(key) ?? null,
            setItem: (key: string, value: string) => values.set(key, value),
        };
        new MobileRouteCache("account:one", storage).save(routes);
        expect(new MobileRouteCache("account:one", storage).load()).toEqual(routes);
        expect(new MobileRouteCache("account:two", storage).load()).toEqual([]);
        expect([...values.values()].join(" ")).not.toContain("secret");
    });
});
