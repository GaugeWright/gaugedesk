import { describe, expect, it } from "vitest";
import {
    pinRootKey,
    pinnedRootKey,
    RootKeyConflict,
    signedHomeRoutes,
    type SignedRouteOptions,
} from "./signed-routes";

function memoryStorage(seed: Record<string, string> = {}) {
    const map = new Map(Object.entries(seed));
    return {
        getItem: (key: string) => map.get(key) ?? null,
        setItem: (key: string, value: string) => void map.set(key, value),
    };
}

function record(root: string, relay = true) {
    return JSON.stringify({
        entry: {
            directory: {
                root_pubkey: root,
                home_routes: [{
                    project: "proj",
                    home_id: "home:a",
                    ...(relay ? {
                        relay: {
                            endpoint: "wss://relay.example",
                            handle: "A".repeat(43),
                            proof: "B".repeat(42) + "A",
                            route_epoch: 2,
                            home_fingerprint: "ab".repeat(32),
                        },
                    } : { endpoint: "https://home.example" }),
                }],
            },
        },
    });
}

/** A directory from before per-computer entries: no list, one entry. */
function beforeEntries(body: string) {
    return async (url: string) => (url.endsWith("/entries") ? null : body);
}

function options(over: Partial<SignedRouteOptions> = {}): SignedRouteOptions {
    return {
        subject: "person-1",
        verify: () => true,
        storage: memoryStorage(),
        fetchJson: beforeEntries(record("root-a")),
        ...over,
    };
}

describe("signed directory routes (DESK-5c)", () => {
    it("honours a relay locator once the record verifies against the pinned root", async () => {
        const storage = memoryStorage();
        const base = options({ storage });
        pinRootKey(base, "root-a");
        const routes = await signedHomeRoutes(base);
        expect(routes?.[0]?.relay?.routeEpoch).toBe(2);
    });

    it("reads nothing without a pin, rather than laundering the hub's word", async () => {
        // No pin means no key to check against; reading anyway would produce
        // something that merely looks verified.
        await expect(signedHomeRoutes(options())).resolves.toBeNull();
    });

    it("refuses a record signed by a different root than the pinned one", async () => {
        const storage = memoryStorage();
        const base = options({ storage, fetchJson: beforeEntries(record("root-attacker")) });
        pinRootKey(base, "root-a");
        await expect(signedHomeRoutes(base)).rejects.toBeInstanceOf(RootKeyConflict);
    });

    it("refuses a record whose signature does not verify", async () => {
        const storage = memoryStorage();
        const base = options({ storage, verify: () => false });
        pinRootKey(base, "root-a");
        await expect(signedHomeRoutes(base)).rejects.toThrow(/failed signature verification/);
    });

    it("treats an account that has published nothing as ordinary, not hostile", async () => {
        const storage = memoryStorage();
        const base = options({ storage, fetchJson: async () => null });
        pinRootKey(base, "root-a");
        await expect(signedHomeRoutes(base)).resolves.toBeNull();
    });

    it("reads every computer's entry under the root, newest route winning (DR-0359)", async () => {
        const storage = memoryStorage();
        const put = (project: string, endpoint: string, root = "root-a") => JSON.stringify({
            entry: {
                directory: { root_pubkey: root, home_routes: [{ project, home_id: "home:a", endpoint }] },
            },
        });
        const urls: string[] = [];
        const listed = (puts: string[]) => async (url: string) => {
            urls.push(url);
            return url.endsWith("/entries") ? JSON.stringify({ version: 1, puts }) : null;
        };
        const base = options({
            storage,
            fetchJson: listed([
                put("p-1", "https://laptop.example"),
                put("p-2", "https://laptop.example"),
                put("p-2", "https://desktop.example"),
            ]),
        });
        pinRootKey(base, "root-a");
        const routes = await signedHomeRoutes(base);
        expect(routes?.map((route) => [route.project, route.endpoint])).toEqual([
            ["p-1", "https://laptop.example"],
            ["p-2", "https://desktop.example"],
        ]);
        expect(urls).toHaveLength(1);

        // One entry under the root that the root did not sign refuses them all.
        const forged = options({
            storage,
            fetchJson: listed([put("p-1", "https://laptop.example"), put("p-1", "https://x", "root-x")]),
        });
        await expect(signedHomeRoutes(forged)).rejects.toBeInstanceOf(RootKeyConflict);

        // Every computer withdrawn is an account with nothing published.
        await expect(signedHomeRoutes(options({ storage, fetchJson: listed([]) }))).resolves.toBeNull();
        const withdrawn = JSON.stringify({
            entry: { directory: { root_pubkey: "root-a", home_routes: [] }, retracted: true },
        });
        await expect(
            signedHomeRoutes(options({ storage, fetchJson: listed([withdrawn]) })),
        ).resolves.toBeNull();
        await expect(
            signedHomeRoutes(options({ storage, fetchJson: async () => JSON.stringify({ puts: [7] }) })),
        ).rejects.toThrow(/malformed/);
    });

    it("drops a route whose project placement does not hold (DR-0370)", async () => {
        const storage = memoryStorage();
        const placed = (project: string) => ({
            project,
            home_id: "home:a",
            endpoint: `https://${project}.example`,
            placement: { project_key: "project-key", host_key: "host-key" },
        });
        const body = JSON.stringify({
            entry: { directory: { root_pubkey: "root-a", home_routes: [placed("p-good"), placed("p-bad")] } },
        });
        const checked: string[] = [];
        const base = options({
            storage,
            fetchJson: beforeEntries(body),
            placementHolds: async (route, key) => {
                checked.push(key);
                return (route as { project: string }).project === "p-good";
            },
        });
        pinRootKey(base, "root-a");
        const routes = await signedHomeRoutes(base);
        expect(routes?.map((route) => route.project)).toEqual(["p-good"]);
        expect(checked).toEqual(["project-key", "project-key"]);
    });

    it("pins on first sight and treats a change as a conflict, not an update", () => {
        const storage = memoryStorage();
        const base = options({ storage });
        expect(pinnedRootKey(base)).toBeNull();
        expect(pinRootKey(base, "root-a")).toBe("pinned");
        expect(pinRootKey(base, "root-a")).toBe("matched");
        expect(pinRootKey(base, "root-b")).toBe("conflict");
        expect(pinnedRootKey(base)).toBe("root-a");
    });

    it("keeps pins per subject, so two people never share one", () => {
        const storage = memoryStorage();
        pinRootKey(options({ storage, subject: "person-1" }), "root-a");
        expect(pinnedRootKey(options({ storage, subject: "person-2" }))).toBeNull();
        expect(pinRootKey(options({ storage, subject: "person-2" }), "root-b")).toBe("pinned");
    });
});
