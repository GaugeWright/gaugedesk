import { describe, expect, it } from "vitest";
import type { HomeId, ProjectId } from "./control-plane-domain";
import { HomeRouteDirectory, parseOpaqueHomeRoutes, type OpaqueHomeRoute } from "./home-routing";
import { RemoteControlPlane } from "./remote-control-plane";

const project = (id: string) => id as ProjectId;
const home = (id: string) => id as HomeId;

function control(route: OpaqueHomeRoute, announcedHome = route.homeId): RemoteControlPlane {
    return new RemoteControlPlane(route.endpoint, {
        route: async (method, path) => {
            if (method === "POST" && path === "/home/admissions") {
                return { home: announcedHome, admission: `admission:${route.homeId}` };
            }
            if (method === "DELETE" && path === "/home/admissions") return null;
            throw new Error(`unexpected ${method} ${path}`);
        },
    });
}

describe("opaque project Home routing", () => {
    const routes = parseOpaqueHomeRoutes({
        routes: [
            { project: "project-a", home_id: "home:one", endpoint: "https://one.example/" },
            { project: "project-b", home_id: "home:two", endpoint: "https://two.example" },
        ],
    });

    it("connects two projects to their exact independently admitted Homes", async () => {
        const directory = new HomeRouteDirectory(routes, { controlPlane: control });
        const one = await directory.connectProject(project("project-a"), home("home:one"));
        const two = await directory.connectProject(project("project-b"), home("home:two"));
        expect(one).not.toBe(two);
        expect(directory.routeFor(project("project-a")).endpoint).toBe("https://one.example");
        expect(directory.routeFor(project("project-b")).endpoint).toBe("https://two.example");
    });

    it("refuses ungranted, cross-Home, conflicting, insecure, and lying routes", async () => {
        const directory = new HomeRouteDirectory(routes, { controlPlane: control });
        expect(() => directory.routeFor(project("forged"))).toThrow(/no granted Home route/);
        await expect(
            directory.connectProject(project("project-a"), home("home:two")),
        ).rejects.toThrow(/is not routed/);
        expect(
            () => new HomeRouteDirectory([...routes, { ...routes[0]!, homeId: home("home:two") }]),
        ).toThrow(/conflicting Home routes/);
        expect(() =>
            parseOpaqueHomeRoutes({
                routes: [{ project: "p", home_id: "h", endpoint: "http://remote.example" }],
            }),
        ).toThrow(/insecure Home endpoint/);

        const liar = new HomeRouteDirectory([routes[0]!], {
            controlPlane: (route) => control(route, home("home:two")),
        });
        await expect(liar.connectProject(project("project-a"))).rejects.toThrow(
            /Home identity mismatch/,
        );
    });

    it("parses only bounded opaque relay locators without treating them as authority", () => {
        const [route] = parseOpaqueHomeRoutes({
            routes: [{
                project: "project-relay",
                home_id: "home:relay",
                endpoint: "https://fallback.example",
                relay: {
                    endpoint: "wss://relay.gaugewright.com",
                    handle: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    proof: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI",
                    route_epoch: 2,
                    home_fingerprint: "ab".repeat(32),
                },
            }],
        });
        expect(route?.relay).toEqual({
            endpoint: "wss://relay.gaugewright.com",
            handle: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            proof: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI",
            routeEpoch: 2,
            homeFingerprint: "ab".repeat(32),
        });
        const [relayOnly] = parseOpaqueHomeRoutes({
            routes: [{
                project: "project-relay-only",
                home_id: "home:relay-only",
                relay: {
                    endpoint: "wss://relay.gaugewright.com",
                    handle: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    proof: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI",
                    route_epoch: 3,
                    home_fingerprint: "cd".repeat(32),
                },
            }],
        });
        expect(relayOnly?.endpoint).toBe("");
        expect(relayOnly?.relay?.routeEpoch).toBe(3);
        expect(
            new HomeRouteDirectory([relayOnly!]).routeFor(project("project-relay-only")),
        ).toBe(relayOnly);
        expect(() => parseOpaqueHomeRoutes({
            routes: [{
                project: "project-relay",
                home_id: "home:relay",
                endpoint: "https://fallback.example",
                relay: {
                    endpoint: "https://relay.example",
                    handle: "short",
                    proof: "short",
                    route_epoch: 0,
                    home_fingerprint: "not-a-pin",
                },
            }],
        })).toThrow(/invalid relay locator/);
    });
});
