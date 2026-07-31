import { afterEach, describe, expect, it, vi } from "vitest";
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
