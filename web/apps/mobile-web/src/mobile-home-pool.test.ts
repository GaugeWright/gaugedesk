import { afterEach, describe, expect, it, vi } from "vitest";
import {
    setDirectoryModuleLoader,
    type HomeId,
    type OpaqueHomeRoute,
    type ProjectId,
    type RouteJson,
} from "@gaugewright/control-plane-client";
import {
    accountTokenExpiresWithin,
    loadMobileHomeRoutes,
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

    it("refreshes JWTs before expiry and leaves opaque Hub expiry to the server", () => {
        expect(accountTokenExpiresWithin(token(2_000), 300, 1_800)).toBe(true);
        expect(accountTokenExpiresWithin(token(2_000), 100, 1_800)).toBe(false);
        expect(accountTokenExpiresWithin("opaque-hub-session", 100, 1_800)).toBe(false);
        expect(accountTokenExpiresWithin("header.!!!.signature", 100, 1_800)).toBe(true);
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

describe("loadMobileHomeRoutes (WS-746)", () => {
    const ROOT = "ed25519:root";
    const locator = {
        endpoint: "wss://relay.example",
        handle: "A".repeat(43),
        proof: `${"B".repeat(42)}A`,
        route_epoch: 1,
        home_fingerprint: "ab".repeat(32),
    };
    const relayOnly = { project: "proj-relay", home_id: "home:relay", endpoint: "", relay: locator };
    const addressable = { project: "proj-direct", home_id: "home:direct", endpoint: "https://d.example" };

    function memoryStorage() {
        const held = new Map<string, string>();
        return {
            held,
            getItem: (key: string) => held.get(key) ?? null,
            setItem: (key: string, value: string) => void held.set(key, value),
        };
    }

    /** The Hub's account plane as the native app reaches it over fetch. */
    function hub({ hubRoutes, directory }: { hubRoutes: unknown[]; directory: unknown }) {
        const seen: string[] = [];
        vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = new URL(String(input));
            seen.push(`${init?.method ?? "GET"} ${url.pathname}`);
            if (url.pathname === "/account/home-routes") {
                return new Response(JSON.stringify({ routes: hubRoutes }), { status: 200 });
            }
            if (url.pathname === "/account/directory") {
                return directory
                    ? new Response(JSON.stringify(directory), { status: 200 })
                    : new Response("not found", { status: 404 });
            }
            return new Response("unexpected", { status: 500 });
        });
        return seen;
    }

    const signedRecord = (routes: unknown[]) =>
        JSON.stringify({ entry: { directory: { root_pubkey: ROOT, home_routes: routes } } });
    const beforeEntries = (body: string) => async (url: string) =>
        url.endsWith("/entries") ? null : body;

    afterEach(() => {
        vi.unstubAllGlobals();
        setDirectoryModuleLoader(null);
    });

    it("reaches a relay-only Home the desktop published only to the signed directory", async () => {
        // The case the issue names: the desktop authors its relay route into the
        // root-signed record and never into the Hub table, so a phone reading
        // only the table never saw the Home at all.
        setDirectoryModuleLoader(async () => ({ verify_signed_put_json: () => true }));
        const storage = memoryStorage();
        const seen = hub({
            hubRoutes: [addressable],
            directory: { root_pubkey: ROOT, origin: "https://dir.example" },
        });
        const routes = await loadMobileHomeRoutes("https://hub.example", () => "token", {
            subject: "account:one",
            storage,
            fetchJson: beforeEntries(signedRecord([relayOnly])),
        });
        expect(seen).toEqual(["GET /account/home-routes", "GET /account/directory"]);
        const relay = routes.find((route) => route.project === "proj-relay");
        expect(relay?.relay?.homeFingerprint).toBe("ab".repeat(32));
        expect(relay?.relay?.endpoint).toBe("wss://relay.example");
        // The Hub still answers for what the record does not mention.
        expect(routes.find((route) => route.project === "proj-direct")?.endpoint)
            .toBe("https://d.example");
        // Pinned under the account the device partitions by.
        expect(storage.getItem("gw.root.account:one")).toBe(ROOT);
    });

    it("no longer honours a relay pin that arrives only through the Hub table", async () => {
        // The retired carve-out read this table as signed. Anyone holding the
        // session can write it, so its certificate pin is never trusted.
        setDirectoryModuleLoader(async () => ({ verify_signed_put_json: () => true }));
        hub({ hubRoutes: [relayOnly, addressable], directory: null });
        const reasons: string[] = [];
        const routes = await loadMobileHomeRoutes("https://hub.example", () => "token", {
            subject: "account:one",
            storage: memoryStorage(),
            onDegraded: (reason) => reasons.push(reason),
        });
        expect(routes.some((route) => route.relay)).toBe(false);
        expect(routes.map((route) => route.project)).toEqual(["proj-direct"]);
        expect(reasons).toEqual(["the account has published no directory root"]);
    });

    it("degrades to the Hub's endpoints when the build registered no verifier", async () => {
        hub({
            hubRoutes: [addressable],
            directory: { root_pubkey: ROOT, origin: "https://dir.example" },
        });
        const reasons: string[] = [];
        const routes = await loadMobileHomeRoutes("https://hub.example", () => "token", {
            onDegraded: (reason) => reasons.push(reason),
        });
        expect(routes.map((route) => route.endpoint)).toEqual(["https://d.example"]);
        expect(reasons).toEqual(["this build registered no verifier"]);
    });

    it("keeps the endpoints and reports a root key that changed", async () => {
        setDirectoryModuleLoader(async () => ({ verify_signed_put_json: () => true }));
        const storage = memoryStorage();
        storage.setItem("gw.root.account:one", "ed25519:earlier");
        hub({
            hubRoutes: [addressable],
            directory: { root_pubkey: ROOT, origin: "https://dir.example" },
        });
        const conflicts: string[] = [];
        const routes = await loadMobileHomeRoutes("https://hub.example", () => "token", {
            subject: "account:one",
            storage,
            fetchJson: beforeEntries(signedRecord([relayOnly])),
            onRootKeyConflict: (error) => conflicts.push(error.message),
        });
        expect(conflicts).toHaveLength(1);
        expect(routes.map((route) => route.project)).toEqual(["proj-direct"]);
        expect(storage.getItem("gw.root.account:one")).toBe("ed25519:earlier");
    });
});
