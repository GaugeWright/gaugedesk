import { describe, expect, it } from "vitest";
import { HomePool, isStaleRouteFailure } from "./home-pool";
import { parseOpaqueHomeRoutes } from "./home-routing";
import type { ProjectId } from "./control-plane-domain";

function routes(proof: string) {
    return parseOpaqueHomeRoutes(
        {
            routes: [{
                project: "proj",
                home_id: "home:a",
                relay: {
                    endpoint: "wss://relay.example",
                    handle: "A".repeat(43),
                    proof,
                    route_epoch: proof === "B".repeat(43) ? 2 : 1,
                    home_fingerprint: "ab".repeat(32),
                },
            }],
        },
        "signed",
    );
}

/** A pool whose admission fails while the locator is the stale one, and
 * succeeds once the rotated locator arrives. */
function pool(refreshRoutes?: () => Promise<ReturnType<typeof routes>>) {
    const attempts: string[] = [];
    const instance = new HomePool<{ endpoint: string }>(routes("A".repeat(43)), () => "token", {
        client: (context) => ({ endpoint: context.endpoint }),
        resolveEndpoint: async (route) => `https://home.example/${route.relay?.proof ?? ""}`,
        routeJson: (endpoint) => (async (method: string) => {
            if (method !== "POST") return {};
            attempts.push(endpoint);
            if (endpoint.endsWith("A".repeat(43))) {
                throw new Error("relay refused pairing: stale route epoch");
            }
            return { home: "home:a", admission: "token" };
        }) as never,
        ...(refreshRoutes ? { refreshRoutes } : {}),
    });
    return { instance, attempts };
}

/** A pool whose Home admits, but answers as `answersAs` rather than the id the
 * route named. */
function impostorPool(answersAs: string) {
    const calls: string[] = [];
    const instance = new HomePool<{ endpoint: string }>(routes("A".repeat(43)), () => "token", {
        client: (context) => ({ endpoint: context.endpoint }),
        resolveEndpoint: async () => "https://home.example",
        routeJson: (() => (async (method: string) => {
            calls.push(method);
            if (method !== "POST") return {};
            return { home: answersAs, admission: "token" };
        })) as never,
    });
    return { instance, calls };
}

describe("a Home that answers as another Home does not get to serve", () => {
    it("refuses the connection and releases the admission it was handed", async () => {
        const { instance, calls } = impostorPool("home:impostor");
        await expect(instance.connectProject("proj" as ProjectId)).rejects.toThrow(
            /Home identity mismatch: expected home:a/,
        );
        // The admission is surrendered rather than left live on the wrong Home.
        expect(calls).toEqual(["POST", "DELETE"]);
        expect(instance.snapshot()).toHaveLength(0);
    });

    it("connects the project to the Home its route named", async () => {
        const { instance } = impostorPool("home:a");
        const connection = await instance.connectProject("proj" as ProjectId);
        expect(connection.homeId).toBe("home:a");
    });
});

describe("a stale route epoch is re-read once (ADR 0131 §5)", () => {
    it("classifies a superseded locator, not an admission refusal", () => {
        expect(isStaleRouteFailure(new Error("relay refused pairing: stale route epoch"))).toBe(true);
        expect(isStaleRouteFailure(new Error("invalid route proof"))).toBe(true);
        expect(isStaleRouteFailure(new Error("Home admission required"))).toBe(false);
        expect(isStaleRouteFailure(new Error("sign in before opening a project"))).toBe(false);
    });

    it("re-reads the route and connects on the rotated locator", async () => {
        const { instance, attempts } = pool(async () => routes("B".repeat(43)));
        const connection = await instance.connectProject("proj" as ProjectId);
        expect(connection.homeId).toBe("home:a");
        expect(attempts).toHaveLength(2);
        expect(attempts[1]).toContain("B".repeat(43));
    });

    it("does not retry when nothing rotated, so a refusing Home is not hammered", async () => {
        const { instance, attempts } = pool(async () => routes("A".repeat(43)));
        await expect(instance.connectProject("proj" as ProjectId)).rejects.toThrow(/stale route epoch/);
        expect(attempts).toHaveLength(1);
    });

    it("does not retry without a refresh seam", async () => {
        const { instance, attempts } = pool();
        await expect(instance.connectProject("proj" as ProjectId)).rejects.toThrow(/stale route epoch/);
        expect(attempts).toHaveLength(1);
    });
});

describe("closing a connection releases the transport that held it", () => {
    /** A pool that records every transport it is asked to build, and every Home
     * it is asked to hang up. */
    function lifecyclePool() {
        const built: string[] = [];
        const calls: string[] = [];
        const closed: string[] = [];
        const instance = new HomePool<{ endpoint: string }>(
            routes("A".repeat(43)),
            () => "token",
            {
                client: (context) => ({ endpoint: context.endpoint }),
                resolveEndpoint: async () => "https://home.example",
                routeJson: ((_endpoint: string, _auth: unknown, route: { homeId: string }) => {
                    const id = `${route.homeId}#${built.length}`;
                    built.push(id);
                    return async (method: string) => {
                        calls.push(`${id} ${method}`);
                        return method === "POST"
                            ? { home: "home:a", admission: "token" }
                            : {};
                    };
                }) as never,
                closeRoute: async (homeId) => { closed.push(homeId); },
            },
        );
        return { instance, built, calls, closed };
    }

    it("revokes over the connection that holds the admission", async () => {
        // Asking `routeJson` again would build a second transport to give back a
        // credential the first one is holding. For a relay-only Home that is a
        // whole second carrier and a second parked leg — both then leaked.
        const { instance, built, calls, closed } = lifecyclePool();
        await instance.connectProject("proj" as ProjectId);
        await instance.closeAll();
        expect(built).toEqual(["home:a#0"]);
        expect(calls).toEqual(["home:a#0 POST", "home:a#0 DELETE"]);
        expect(closed).toEqual(["home:a"]);
        expect(instance.snapshot()).toHaveLength(0);
    });
});
