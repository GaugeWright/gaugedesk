import { afterEach, describe, expect, it, vi } from "vitest";
import { setTunnelModuleLoader } from "@gaugewright/control-plane-client";
import { WorkbenchControlPlane } from "./workbench-control-plane";

afterEach(() => vi.unstubAllGlobals());

describe("hosted Home bootstrap", () => {
    it("keeps account discovery on the Hub and sends work only to the admitted selected Home", async () => {
        const calls: Array<[string, RequestInit | undefined]> = [];
        const fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = String(input);
            calls.push([url, init]);
            if (url === "https://hub.example/account/homes") {
                return new Response(
                    JSON.stringify({
                        homes: [
                            {
                                id: "home:cloud",
                                kind: "cloud",
                                endpoint: "https://home.example",
                            },
                        ],
                        selected_home: "home:cloud",
                    }),
                );
            }
            if (url === "https://home.example/home/admissions") {
                return new Response(
                    JSON.stringify({ home: "home:cloud", admission: "home-token" }),
                    { status: 201 },
                );
            }
            if (url === "https://home.example/workspace") {
                return new Response(
                    JSON.stringify({
                        archetypes: [], projects: [], recent: [], workstreams: [], work_targets: [],
                        personal_placement: null,
                    }),
                );
            }
            throw new Error(`unexpected fetch ${url}`);
        });
        vi.stubGlobal("fetch", fetch);
        const api = new WorkbenchControlPlane("https://hub.example", { splitHomes: true });
        api.setBearer("account-token");

        await expect(api.bootstrapHome()).resolves.toMatchObject({
            kind: "connected",
            home: { id: "home:cloud" },
        });
        await expect(api.getWorkspace()).resolves.toMatchObject({ projects: [] });

        expect(calls.map(([url]) => url)).toEqual([
            "https://hub.example/account/homes",
            "https://home.example/home/admissions",
            "https://hub.example/account/homes",
            "https://home.example/workspace",
        ]);
        const hubCalls = calls.filter(([url]) => url.startsWith("https://hub.example/"));
        expect(hubCalls).toHaveLength(2);
        for (const [, init] of hubCalls) {
            const hubHeaders = new Headers(init?.headers);
            expect(hubHeaders.get("authorization")).toBe("Bearer account-token");
            expect(hubHeaders.has("x-gaugewright-home-admission")).toBe(false);
        }
        const workHeaders = new Headers(calls[3]?.[1]?.headers);
        expect(workHeaders.get("authorization")).toBe("Bearer account-token");
        expect(workHeaders.get("x-gaugewright-home-admission")).toBe("home-token");
    });

    it("reports an honest no-Home state instead of falling back to Hub work routes", async () => {
        const fetch = vi.fn(async (input: RequestInfo | URL) => {
            const url = String(input);
            if (url === "https://hub.example/account/homes") {
                return new Response(JSON.stringify({ homes: [], selected_home: null }));
            }
            if (url === "https://hub.example/account/home-routes") {
                return new Response(JSON.stringify({ routes: [] }));
            }
            throw new Error(`work escaped to ${url}`);
        });
        vi.stubGlobal("fetch", fetch);
        const api = new WorkbenchControlPlane("https://hub.example", { splitHomes: true });

        await expect(api.bootstrapHome()).resolves.toEqual({ kind: "none", homes: [], routes: [] });
        expect(fetch).not.toHaveBeenCalledWith("https://hub.example/workspace", expect.anything());
    });

    it("treats an unprovisioned managed Home as setup state, not an access error", async () => {
        const fetch = vi.fn(async (input: RequestInfo | URL) => {
            const url = String(input);
            if (url === "https://hub.example/account/homes") {
                return new Response(JSON.stringify({
                    homes: [{ id: "home:cloud", kind: "cloud", endpoint: "https://home.example" }],
                    selected_home: "home:cloud",
                }));
            }
            if (url === "https://hub.example/account/home-routes") {
                return new Response(JSON.stringify({ routes: [] }));
            }
            if (url === "https://home.example/home/admissions") {
                return new Response(JSON.stringify({ error: "Home has no active owner" }), { status: 403 });
            }
            throw new Error(`unexpected fetch ${url}`);
        });
        vi.stubGlobal("fetch", fetch);
        const api = new WorkbenchControlPlane("https://hub.example", { splitHomes: true });

        await expect(api.bootstrapHome()).resolves.toMatchObject({
            kind: "none",
            homes: [{ id: "home:cloud" }],
            routes: [],
        });
    });

    it("routes project credential clients to the admitted Home, never the Hub", async () => {
        const calls: Array<[string, RequestInit | undefined]> = [];
        vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = String(input);
            calls.push([url, init]);
            if (url === "https://hub.example/account/homes") {
                return new Response(JSON.stringify({
                    homes: [{
                        id: "home:cloud",
                        kind: "cloud",
                        endpoint: "https://home.example",
                    }],
                    selected_home: "home:cloud",
                }));
            }
            if (url === "https://home.example/home/admissions") {
                return new Response(JSON.stringify({
                    home: "home:cloud",
                    admission: "home-token",
                }), { status: 201 });
            }
            if (url.startsWith("https://home.example/projects/project%3Aone/credentials")) {
                if (init?.method === "GET") {
                    return new Response(JSON.stringify({ credentials: [] }));
                }
                return new Response(null, { status: 204 });
            }
            throw new Error(`unexpected fetch ${url}`);
        }));
        const api = new WorkbenchControlPlane("https://hub.example", { splitHomes: true });
        api.setBearer("account-token");

        await expect(api.projectCredentials("project:one")).resolves.toEqual([]);
        await api.linkProjectCredential("project:one", "anthropic", "write-only-token");
        await api.unlinkProjectCredential("project:one", "anthropic");

        expect(calls.map(([url, init]) => `${init?.method ?? "GET"} ${url}`)).toEqual([
            "GET https://hub.example/account/homes",
            "POST https://home.example/home/admissions",
            "GET https://home.example/projects/project%3Aone/credentials",
            "POST https://home.example/projects/project%3Aone/credentials",
            "DELETE https://home.example/projects/project%3Aone/credentials/anthropic",
        ]);
        for (const [, init] of calls.slice(2)) {
            const headers = new Headers(init?.headers);
            expect(headers.get("authorization")).toBe("Bearer account-token");
            expect(headers.get("x-gaugewright-home-admission")).toBe("home-token");
        }
        expect(calls.some(([url]) =>
            url.startsWith("https://hub.example/projects/"))).toBe(false);
    });

    it("selects a workspace through its tenant-owned active Cloud Home", async () => {
        const calls: Array<[string, RequestInit | undefined]> = [];
        vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = String(input);
            calls.push([url, init]);
            if (url === "https://hub.example/account/tenants/acme/cloud-home") {
                return new Response(JSON.stringify({
                    facility: {
                        status: "active",
                        config: {
                            home_id: "home:cloud:acme",
                            endpoint: "https://acme.home.gaugewright.com",
                            region: "eastus",
                            subscription: "active",
                        },
                    },
                    usage: {},
                }));
            }
            if (url === "https://hub.example/account/homes") return new Response(null, { status: 204 });
            throw new Error(`unexpected fetch ${url}`);
        }));
        const api = new WorkbenchControlPlane("https://hub.example", { splitHomes: true });
        api.setBearer("account-token");

        await api.selectTenantWorkspace("acme");

        expect(calls.map(([url]) => url)).toEqual([
            "https://hub.example/account/tenants/acme/cloud-home",
            "https://hub.example/account/homes",
        ]);
        expect(String(calls[1]?.[1]?.body)).toBe(
            '{"id":"home:cloud:acme","kind":"cloud","endpoint":"https://acme.home.gaugewright.com","selected":true}',
        );
    });

    it("collects host reachability and project names only after Home admission", async () => {
        const calls: Array<[string, RequestInit | undefined]> = [];
        vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = String(input);
            calls.push([url, init]);
            if (url === "https://hub.example/account/tenants/acme/hosts") {
                return new Response(JSON.stringify({ hosts: [{
                    id: "registered-host:home:studio",
                    display_name: "Studio Mac",
                    home_id: "home:studio",
                    endpoint: "https://studio.example",
                }] }));
            }
            if (url === "https://hub.example/account/tenants/acme/facilities") {
                return new Response(JSON.stringify({ facilities: [{
                    id: "cloud-home:acme",
                    kind: "hosted_home_node",
                    owner: "tenant",
                    status: "active",
                    display_name: "Cloud Home",
                }] }));
            }
            if (url === "https://studio.example/home/admissions") {
                return new Response(JSON.stringify({ home: "home:studio", admission: "temporary" }));
            }
            if (url === "https://studio.example/workspace") {
                return new Response(JSON.stringify({
                    archetypes: [],
                    projects: [{ id: "project:studio", name: "Studio work", targets: [], placements: [] }],
                    recent: [], workstreams: [], work_targets: [], personal_placement: null,
                }));
            }
            throw new Error(`unexpected fetch ${url}`);
        }));
        const api = new WorkbenchControlPlane("https://hub.example", { splitHomes: true });
        api.setBearer("account-token");

        await expect(api.tenantHostOverviews("acme")).resolves.toEqual([{
            id: "registered-host:home:studio",
            displayName: "Studio Mac",
            homeId: "home:studio",
            endpoint: "https://studio.example",
            reachability: "online",
            projects: [{ id: "project:studio", name: "Studio work" }],
        }]);
        expect(calls.map(([url, init]) => `${init?.method ?? "GET"} ${url}`)).toEqual([
            "GET https://hub.example/account/tenants/acme/hosts",
            "POST https://studio.example/home/admissions",
            "GET https://studio.example/workspace",
            "DELETE https://studio.example/home/admissions",
        ]);
        expect(new Headers(calls[2]?.[1]?.headers).get("x-gaugewright-home-admission")).toBe("temporary");
        expect(new Headers(calls[0]?.[1]?.headers).has("x-gaugewright-home-admission")).toBe(false);
    });

    it("collects count-only review pointers without selecting or registering a Home", async () => {
        const calls: Array<[string, RequestInit | undefined]> = [];
        vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = String(input);
            calls.push([url, init]);
            if (url === "https://hub.example/account/tenants/acme/hosts") {
                return new Response(JSON.stringify({ hosts: [{
                    id: "registered-host:home:studio",
                    display_name: "Studio Mac",
                    home_id: "home:studio",
                    endpoint: "https://studio.example",
                }] }));
            }
            if (url === "https://hub.example/account/tenants/acme/cloud-home") {
                return new Response(JSON.stringify({
                    facility: { status: "active", config: {
                        home_id: "home:cloud:acme", endpoint: "https://acme.home.gaugewright.com", region: "eastus",
                    } }, usage: {},
                }));
            }
            if (url === "https://studio.example/home/admissions") {
                return init?.method === "DELETE"
                    ? new Response(null, { status: 204 })
                    : new Response(JSON.stringify({ home: "home:studio", admission: "studio-admission" }));
            }
            if (url === "https://acme.home.gaugewright.com/home/admissions") {
                return init?.method === "DELETE"
                    ? new Response(null, { status: 204 })
                    : new Response(JSON.stringify({ home: "home:cloud:acme", admission: "cloud-admission" }));
            }
            if (url === "https://studio.example/console/review-count") {
                return new Response(JSON.stringify({ review_count: 1 }));
            }
            if (url === "https://acme.home.gaugewright.com/console/review-count") {
                return new Response(JSON.stringify({ review_count: 2 }));
            }
            throw new Error(`unexpected fetch ${url}`);
        }));
        const api = new WorkbenchControlPlane("https://hub.example", { splitHomes: true });
        api.setBearer("account-token");

        await expect(api.reviewNotifications([{
            id: "acme", displayName: "Acme", role: "member", personal: false, providerCommercial: false,
        }])).resolves.toEqual([{ tenant: "acme", count: 3, unavailableHomes: 0 }]);

        expect(calls.map(([url, init]) => `${init?.method ?? "GET"} ${url}`)).toEqual([
            "GET https://hub.example/account/tenants/acme/hosts",
            "GET https://hub.example/account/tenants/acme/facilities",
            "GET https://hub.example/account/tenants/acme/cloud-home",
            "POST https://studio.example/home/admissions",
            "POST https://acme.home.gaugewright.com/home/admissions",
            "GET https://studio.example/console/review-count",
            "GET https://acme.home.gaugewright.com/console/review-count",
            "DELETE https://studio.example/home/admissions",
            "DELETE https://acme.home.gaugewright.com/home/admissions",
        ]);
        const countCalls = calls.filter(([url]) => url.endsWith("/console/review-count"));
        for (const [, init] of countCalls) {
            expect(new Headers(init?.headers).get("x-gaugewright-home-admission")).toMatch(/admission$/);
        }
        expect(calls.some(([url]) => url.includes("/account/homes"))).toBe(false);
    });

    it("does not probe a missing Cloud Home after the facility projection says it is absent", async () => {
        const calls: string[] = [];
        vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
            const url = String(input);
            calls.push(url);
            if (url.endsWith("/hosts")) return new Response(JSON.stringify({ hosts: [] }));
            if (url.endsWith("/facilities")) return new Response(JSON.stringify({ facilities: [] }));
            throw new Error(`unexpected fetch ${url}`);
        }));
        const api = new WorkbenchControlPlane("https://hub.example", { splitHomes: true });

        await expect(api.reviewNotifications([{
            id: "personal:alice", displayName: "Personal", role: "owner", personal: true, providerCommercial: false,
        }])).resolves.toEqual([{ tenant: "personal:alice", count: 0, unavailableHomes: 0 }]);

        expect(calls).toEqual([
            "https://hub.example/account/tenants/personal%3Aalice/hosts",
            "https://hub.example/account/tenants/personal%3Aalice/facilities",
        ]);
    });

    it("accepts a project invitation on its Home and saves only the opaque Hub route", async () => {
        const raw = JSON.stringify({
            version: 1,
            invitation: "hinv-1",
            invited_authority: "account:invitee",
            project: "proj-shared",
            home_id: "home:owner",
            endpoint: "https://owner.example",
            secret: "invitation-secret",
        });
        const invite = Array.from(new TextEncoder().encode(raw), (byte) =>
            byte.toString(16).padStart(2, "0"),
        ).join("");
        const calls: Array<[string, RequestInit | undefined]> = [];
        vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = String(input);
            calls.push([url, init]);
            if (url === "https://owner.example/home/invitations/accept") {
                return new Response(JSON.stringify({
                    home_id: "home:owner",
                    project: "proj-shared",
                    endpoint: "https://owner.example",
                    admission: "accepted-admission",
                }));
            }
            if (url === "https://hub.example/account/homes") return new Response(null, { status: 204 });
            if (url === "https://hub.example/account/home-routes") return new Response(null, { status: 204 });
            if (url === "https://owner.example/workspace") {
                return new Response(JSON.stringify({
                    archetypes: [], projects: [], recent: [], workstreams: [], work_targets: [], personal_placement: null,
                }));
            }
            throw new Error(`unexpected fetch ${url}`);
        }));
        const api = new WorkbenchControlPlane("https://hub.example", { splitHomes: true });
        api.setBearer("account-token");

        await expect(api.acceptHomeInvitation(invite)).resolves.toMatchObject({
            kind: "connected",
            home: { id: "home:owner", kind: "registered" },
        });
        await api.getWorkspace();

        expect(calls.map(([url]) => url)).toEqual([
            "https://owner.example/home/invitations/accept",
            "https://hub.example/account/homes",
            "https://hub.example/account/home-routes",
            "https://owner.example/workspace",
        ]);
        const registered = String(calls[1]?.[1]?.body);
        const route = String(calls[2]?.[1]?.body);
        expect(registered).toContain('"selected":true');
        expect(route).toContain('"project":"proj-shared"');
        expect(registered + route).not.toContain("invitation-secret");
        expect(new Headers(calls[3]?.[1]?.headers).get("x-gaugewright-home-admission")).toBe(
            "accepted-admission",
        );
    });
});

describe("project-first Home resolution (DESK-3)", () => {
    /** Two projects on two different Homes, plus a selected Home that serves
     * neither, so a mistake cannot pass by accidentally hitting the right one. */
    function twoHomes() {
        const admitted: string[] = [];
        const worked: string[] = [];
        const fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = String(input);
            if (url === "https://hub.example/account/home-routes") {
                return new Response(
                    JSON.stringify({
                        routes: [
                            { project: "proj-a", home_id: "home:a", endpoint: "https://a.example" },
                            { project: "proj-b", home_id: "home:b", endpoint: "https://b.example" },
                        ],
                    }),
                );
            }
            if (url === "https://hub.example/account/homes") {
                return new Response(
                    JSON.stringify({
                        homes: [{ id: "home:z", kind: "cloud", endpoint: "https://z.example" }],
                        selected_home: "home:z",
                    }),
                );
            }
            const admission = url.match(/^https:\/\/([abz])\.example\/home\/admissions$/);
            if (admission && init?.method === "POST") {
                admitted.push(admission[1]);
                return new Response(
                    JSON.stringify({ home: `home:${admission[1]}`, admission: `token-${admission[1]}` }),
                    { status: 201 },
                );
            }
            if (admission) return new Response(null, { status: 204 });
            const work = url.match(/^https:\/\/([abz])\.example\/workspace$/);
            if (work) {
                worked.push(work[1]);
                return new Response(
                    JSON.stringify({
                        archetypes: [], projects: [], recent: [], workstreams: [],
                        work_targets: [], personal_placement: null,
                    }),
                );
            }
            throw new Error(`unexpected fetch ${url}`);
        });
        vi.stubGlobal("fetch", fetch);
        const api = new WorkbenchControlPlane("https://hub.example", { splitHomes: true });
        api.setBearer("person-token");
        return { api, admitted, worked };
    }

    it("sends a project's work to that project's Home, not to a selected one", async () => {
        const { api, worked } = twoHomes();
        api.setCurrentProject("proj-a" as never);
        await api.getWorkspace();
        expect(worked).toEqual(["a"]);
    });

    it("holds several Homes at once and follows the open project between them", async () => {
        const { api, admitted, worked } = twoHomes();
        api.setCurrentProject("proj-a" as never);
        await api.getWorkspace();
        api.setCurrentProject("proj-b" as never);
        await api.getWorkspace();
        expect(worked).toEqual(["a", "b"]);
        // Returning to the first project reuses its live connection rather than
        // re-admitting: that is what "several Homes at once" has to mean.
        api.setCurrentProject("proj-a" as never);
        await api.getWorkspace();
        expect(worked).toEqual(["a", "b", "a"]);
        expect(admitted).toEqual(["a", "b"]);
    });

    it("falls back to the selected Home for a project with no granted route", async () => {
        const { api, worked } = twoHomes();
        api.setCurrentProject("proj-unrouted" as never);
        await api.getWorkspace();
        expect(worked).toEqual(["z"]);
    });
});

describe("relay-only Homes over the tunnel (DESK-7)", () => {
    /** A relay-only route has no endpoint to dial. With no tunnel module
     * registered the build must behave as it always did rather than failing in
     * a new way, so the route is simply not served over a tunnel. */
    it("falls back to the selected Home when no tunnel module is registered", async () => {
        const worked: string[] = [];
        vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = String(input);
            if (url === "https://hub.example/account/home-routes") {
                return new Response(JSON.stringify({
                    routes: [{
                        project: "proj-relay",
                        home_id: "home:r",
                        relay: {
                            endpoint: "wss://relay.example",
                            handle: "A".repeat(43),
                            proof: "B".repeat(42) + "A",
                            route_epoch: 1,
                            home_fingerprint: "ab".repeat(32),
                        },
                    }],
                }));
            }
            if (url === "https://hub.example/account/homes") {
                return new Response(JSON.stringify({
                    homes: [{ id: "home:z", kind: "cloud", endpoint: "https://z.example" }],
                    selected_home: "home:z",
                }));
            }
            if (url === "https://z.example/home/admissions" && init?.method === "POST") {
                return new Response(JSON.stringify({ home: "home:z", admission: "t" }), { status: 201 });
            }
            if (url === "https://z.example/workspace") {
                worked.push("z");
                return new Response(JSON.stringify({
                    archetypes: [], projects: [], recent: [], workstreams: [],
                    work_targets: [], personal_placement: null,
                }));
            }
            throw new Error(`unexpected fetch ${url}`);
        }));
        const api = new WorkbenchControlPlane("https://hub.example", { splitHomes: true });
        api.setBearer("person-token");
        api.setCurrentProject("proj-relay" as never);
        await api.getWorkspace();
        // No tunnel, so the relay-only route yields nothing dialable and the
        // account's selected Home serves — unchanged behaviour, not a new failure.
        expect(worked).toEqual(["z"]);
    });
});

describe("the tunnel payload is only fetched when it is needed (DESK-7)", () => {
    /** The wasm module is ~650 KB. Nothing on the ordinary path may wait for it:
     * a person whose Homes are all directly addressable must never fetch it. */
    it("never loads the wasm module for a directly addressable Home", async () => {
        let loads = 0;
        setTunnelModuleLoader(async () => {
            loads += 1;
            throw new Error("the tunnel module must not be loaded here");
        });
        try {
            vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
                const url = String(input);
                if (url === "https://hub.example/account/home-routes") {
                    return new Response(JSON.stringify({
                        routes: [{ project: "proj-direct", home_id: "home:d", endpoint: "https://d.example" }],
                    }));
                }
                if (url === "https://d.example/home/admissions" && init?.method === "POST") {
                    return new Response(JSON.stringify({ home: "home:d", admission: "t" }), { status: 201 });
                }
                if (url === "https://d.example/workspace") {
                    return new Response(JSON.stringify({
                        archetypes: [], projects: [], recent: [], workstreams: [],
                        work_targets: [], personal_placement: null,
                    }));
                }
                throw new Error(`unexpected fetch ${url}`);
            }));
            const api = new WorkbenchControlPlane("https://hub.example", { splitHomes: true });
            api.setBearer("person-token");
            api.setCurrentProject("proj-direct" as never);
            await api.getWorkspace();
            expect(loads).toBe(0);
        } finally {
            setTunnelModuleLoader(null);
        }
    });
});
