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

function options(over: Partial<SignedRouteOptions> = {}): SignedRouteOptions {
    return {
        subject: "person-1",
        verify: () => true,
        storage: memoryStorage(),
        fetchJson: async () => record("root-a"),
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
        const base = options({ storage, fetchJson: async () => record("root-attacker") });
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
