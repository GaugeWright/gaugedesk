import { afterEach, describe, expect, it, vi } from "vitest";
import { resolveHomeRoutes } from "./resolve-home-routes";
import { setDirectoryModuleLoader } from "./directory-module";
import type { RouteJson } from "./control-plane-transport";

const ROOT = "ed25519:root";
const OTHER = "ed25519:other";

const locator = {
    endpoint: "wss://relay.example",
    handle: "A".repeat(43),
    proof: `${"B".repeat(42)}A`,
    route_epoch: 1,
    home_fingerprint: "ab".repeat(32),
};

/** A record the verifier will accept, naming `root` as its signer. */
function record(root: string, routes: unknown[]) {
    return JSON.stringify({ entry: { directory: { root_pubkey: root, home_routes: routes } } });
}

function memoryStorage() {
    const held = new Map<string, string>();
    return {
        getItem: (key: string) => held.get(key) ?? null,
        setItem: (key: string, value: string) => void held.set(key, value),
    };
}

/** The account plane: the hub's table plus the directory projection. */
function plane({ directory, hubRoutes = [] as unknown[] }: {
    directory: unknown;
    hubRoutes?: unknown[];
}): RouteJson {
    return (async (_method: string, path: string) => {
        if (path === "/account/home-routes") return { routes: hubRoutes };
        if (path === "/account/directory") {
            if (!directory) throw new Error("GET /account/directory: 404");
            return directory;
        }
        throw new Error(`unexpected ${path}`);
    }) as unknown as RouteJson;
}

const hubRelayRoute = {
    project: "proj-a",
    home_id: "home:a",
    endpoint: "",
    relay: locator,
};

/** A directly-reachable Home, which survives an unsigned read intact. */
const addressable = { project: "proj-b", home_id: "home:b", endpoint: "https://b.example" };

afterEach(() => setDirectoryModuleLoader(null));

describe("resolving routes across both channels (DESK-5g)", () => {
    it("honours a locator from a record signed by the pinned root", async () => {
        setDirectoryModuleLoader(async () => ({ verify_signed_put_json: () => true }));
        const routes = await resolveHomeRoutes({
            json: plane({ directory: { root_pubkey: ROOT, origin: "https://dir.example" } }),
            subject: "person-1",
            storage: memoryStorage(),
            fetchJson: async () => record(ROOT, [hubRelayRoute]),
        });
        expect(routes.verified).toBe(true);
        expect(routes.routes[0]?.relay?.homeFingerprint).toBe("ab".repeat(32));
    });

    it("yields nothing at all for a relay-only route that arrives only from the hub", async () => {
        // The hub table is writable by anyone holding the person's session, so a
        // fingerprint arriving that way must never be honoured (ADR 0131 §3).
        // Dropping the pin leaves no reach, so the route is refused outright
        // rather than surfaced with an empty endpoint — a caller must see *no
        // usable route*, not a broken one.
        const routes = await resolveHomeRoutes({
            json: plane({ directory: null, hubRoutes: [hubRelayRoute, addressable] }),
            subject: "person-1",
            storage: memoryStorage(),
        });
        expect(routes.verified).toBe(false);
        expect(routes.routes.map((route) => route.project)).toEqual(["proj-b"]);
    });

    it("refuses a record signed by a root other than the pinned one", async () => {
        // The signature verifies perfectly — a forger signs their own record
        // with their own key. The pin comparison is the only thing that catches
        // it, which is why it lives outside the verifier.
        setDirectoryModuleLoader(async () => ({ verify_signed_put_json: () => true }));
        const storage = memoryStorage();
        const options = {
            subject: "person-1",
            storage,
            fetchJson: async () => record(OTHER, [hubRelayRoute]),
        };
        const conflicts: Error[] = [];
        const routes = await resolveHomeRoutes({
            ...options,
            json: plane({
                directory: { root_pubkey: ROOT, origin: "" },
                hubRoutes: [hubRelayRoute, addressable],
            }),
            onRootKeyConflict: (error) => conflicts.push(error),
        });
        expect(routes.verified).toBe(false);
        expect(routes.routes.map((route) => route.project)).toEqual(["proj-b"]);
        expect(conflicts).toHaveLength(1);
    });

    it("treats a changed root key as an alarm and keeps the person reachable", async () => {
        setDirectoryModuleLoader(async () => ({ verify_signed_put_json: () => true }));
        const storage = memoryStorage();
        const first = plane({ directory: { root_pubkey: ROOT, origin: "" } });
        await resolveHomeRoutes({
            json: first,
            subject: "person-1",
            storage,
            fetchJson: async () => record(ROOT, []),
        });

        const conflicts: Error[] = [];
        const routes = await resolveHomeRoutes({
            json: plane({
                directory: { root_pubkey: OTHER, origin: "" },
                hubRoutes: [{ project: "proj-a", home_id: "home:a", endpoint: "https://a.example" }],
            }),
            subject: "person-1",
            storage,
            fetchJson: async () => record(OTHER, []),
            onRootKeyConflict: (error) => conflicts.push(error),
        });
        expect(conflicts).toHaveLength(1);
        expect(routes.verified).toBe(false);
        expect(
            routes.routes[0]?.endpoint,
            "a substitution must stop the pins, not strand the person",
        ).toBe("https://a.example");
    });

    it("pins per subject, so signing in as someone else is not a conflict", async () => {
        setDirectoryModuleLoader(async () => ({ verify_signed_put_json: () => true }));
        const storage = memoryStorage();
        const conflicts: Error[] = [];
        for (const [subject, root] of [["person-1", ROOT], ["person-2", OTHER]] as const) {
            await resolveHomeRoutes({
                json: plane({ directory: { root_pubkey: root, origin: "" } }),
                subject,
                storage,
                fetchJson: async () => record(root, []),
                onRootKeyConflict: (error) => conflicts.push(error),
            });
        }
        expect(conflicts).toHaveLength(0);
    });

    it("degrades rather than failing when the record cannot be read or verified", async () => {
        // A directory outage and a forged signature are different problems with
        // the same correct answer: no signed routes, endpoints still usable.
        const cases = [
            { verify: () => true, fetchJson: async () => { throw new Error("directory down"); } },
            { verify: () => false, fetchJson: async () => record(ROOT, [hubRelayRoute]) },
            { verify: () => true, fetchJson: async () => null },
        ];
        for (const { verify, fetchJson } of cases) {
            setDirectoryModuleLoader(async () => ({ verify_signed_put_json: verify }));
            const routes = await resolveHomeRoutes({
                json: plane({
                    directory: { root_pubkey: ROOT, origin: "" },
                    hubRoutes: [hubRelayRoute, addressable],
                }),
                subject: "person-1",
                storage: memoryStorage(),
                fetchJson,
            });
            expect(routes.verified).toBe(false);
            expect(routes.routes.map((route) => route.project)).toEqual(["proj-b"]);
        }
    });

    it("does not report a build with no verifier as an unverified record", async () => {
        // Absent module and failed verification must not look alike: one is a
        // build problem, the other is an attack. Neither may honour a pin.
        const routes = await resolveHomeRoutes({
            json: plane({
                directory: { root_pubkey: ROOT, origin: "" },
                hubRoutes: [hubRelayRoute, addressable],
            }),
            subject: "person-1",
            storage: memoryStorage(),
            fetchJson: async () => record(ROOT, [hubRelayRoute]),
        });
        expect(routes.verified).toBe(false);
        expect(routes.routes.map((route) => route.project)).toEqual(["proj-b"]);
    });

    it("keeps hub routes for projects the signed record never mentions", async () => {
        // A project reached through someone else's invitation has no route this
        // person's Home ever authored, so the signed record cannot cover it.
        setDirectoryModuleLoader(async () => ({ verify_signed_put_json: () => true }));
        const invited = { project: "proj-b", home_id: "home:b", endpoint: "https://b.example" };
        const routes = await resolveHomeRoutes({
            json: plane({
                directory: { root_pubkey: ROOT, origin: "" },
                hubRoutes: [hubRelayRoute, invited],
            }),
            subject: "person-1",
            storage: memoryStorage(),
            fetchJson: async () => record(ROOT, [hubRelayRoute]),
        });
        expect(routes.routes.map((route) => route.project).sort()).toEqual(["proj-a", "proj-b"]);
        expect(routes.routes.find((route) => route.project === "proj-a")?.relay).toBeTruthy();
        expect(routes.routes.find((route) => route.project === "proj-b")?.relay).toBeUndefined();
    });

    it("reads the hub alone when no session subject is known", async () => {
        const json = vi.fn(async (_method: string, path: string) => {
            expect(path).toBe("/account/home-routes");
            return { routes: [hubRelayRoute] };
        }) as unknown as RouteJson;
        const routes = await resolveHomeRoutes({ json, subject: "", storage: memoryStorage() });
        expect(routes.verified).toBe(false);
        expect(routes.routes).toEqual([]);
    });
});
