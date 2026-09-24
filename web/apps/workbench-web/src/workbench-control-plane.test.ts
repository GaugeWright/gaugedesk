import { afterEach, describe, expect, it, vi } from "vitest";
import {
    setDirectoryModuleLoader,
    setTunnelModuleLoader,
    type TunnelFacade,
} from "@gaugewright/control-plane-client";
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

        await expect(api.bootstrapHome()).resolves.toEqual({
            kind: "none",
            homes: [],
            routes: [],
            selectedHome: null,
        });
        expect(fetch).not.toHaveBeenCalledWith("https://hub.example/workspace", expect.anything());
    });

    // "No Home is serving you" covers three different people, and the surface
    // that meets them can only tell them apart if this says which. Without the
    // selection, someone whose laptop is asleep is indistinguishable from
    // someone who has never installed anything, and both were told to install.
    it("says which Home was selected when the selected Home is the one not serving", async () => {
        const fetch = vi.fn(async (input: RequestInfo | URL) => {
            const url = String(input);
            if (url === "https://hub.example/account/homes") {
                return new Response(JSON.stringify({
                    homes: [
                        { id: "home:laptop", kind: "registered", endpoint: "https://laptop.example" },
                        { id: "home:studio", kind: "registered", endpoint: "https://studio.example" },
                    ],
                    selected_home: "home:laptop",
                }));
            }
            if (url === "https://hub.example/account/home-routes") {
                return new Response(JSON.stringify({ routes: [] }));
            }
            if (url === "https://laptop.example/home/admissions") {
                return new Response(JSON.stringify({ error: "Home has no active owner" }), { status: 403 });
            }
            throw new Error(`unexpected fetch ${url}`);
        });
        vi.stubGlobal("fetch", fetch);
        const api = new WorkbenchControlPlane("https://hub.example", { splitHomes: true });

        const state = await api.bootstrapHome();
        expect(state).toMatchObject({ kind: "none", selectedHome: "home:laptop" });
        // Both Homes travel with it, so the surface can offer the other one
        // rather than only naming the one that is down.
        expect(state.kind === "none" && state.homes.map((home) => home.id))
            .toEqual(["home:laptop", "home:studio"]);
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
        const streamed: string[] = [];
        let includeNewProject = false;
        let homeGeneration = 1;
        let workRefusal: string | null = null;
        const fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = String(input);
            if (url === "https://hub.example/account/home-routes") {
                return new Response(
                    JSON.stringify({
                        routes: [
                            { project: "proj-a", home_id: "home:a", endpoint: "https://a.example" },
                            { project: "proj-b", home_id: "home:b", endpoint: "https://b.example" },
                            ...(includeNewProject
                                ? [{ project: "proj-c", home_id: "home:c", endpoint: "https://c.example" }]
                                : []),
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
            const admission = url.match(/^https:\/\/([abcz])\.example\/home\/admissions$/);
            if (admission && init?.method === "POST") {
                admitted.push(admission[1]);
                return new Response(
                    JSON.stringify({ home: `home:${admission[1]}`, admission: `token-${admission[1]}-${homeGeneration}` }),
                    { status: 201 },
                );
            }
            if (admission) return new Response(null, { status: 204 });
            const tracker = url.match(/^https:\/\/([abz])\.example\/projects\/([^/]+)\/trackers(.*)$/);
            if (tracker) {
                worked.push(tracker[1]);
                // This fixture mints admissions with a generation, so the tracker
                // lane asserts the same shape the workspace lanes do.
                expect(new Headers(init?.headers).get("x-gaugewright-home-admission")).toBe(`token-${tracker[1]}-${homeGeneration}`);
                const descriptor = { project_id: tracker[2], workspace_id: `workspace-${tracker[1]}`, queue: "tutorials", resource_id: `tracker-${tracker[1]}`, can_complete: true };
                return new Response(JSON.stringify(tracker[3].endsWith("/complete")
                    ? { snapshot: { admission: { instance_ref: "closing-root" }, instance_status: "completed" }, executed_effect: "effect", recovered_effect: null }
                    : tracker[3].endsWith("/tasks") ? { actor: "person", tracker: descriptor, issues: [] }
                    : tracker[3].endsWith("/issues") ? { tracker: descriptor, issues: [] } : { trackers: [descriptor] }));
            }
            const events = url.match(/^https:\/\/([abcz])\.example\/workspace\/events$/);
            if (events) {
                const presented = new Headers(init?.headers).get("x-gaugewright-home-admission");
                if (presented !== `token-${events[1]}-${homeGeneration}`) {
                    const body = JSON.stringify({ error: "target Home admission required" });
                    return new Response(body, {
                        status: 401,
                        headers: { "content-type": "application/json", "content-length": String(body.length) },
                    });
                }
                streamed.push(events[1]);
                worked.push(events[1]);
                return new Response(`data: ${JSON.stringify({ type: "workspacechanged", record: "project_tracker", id: `proj-${events[1]}` })}\n\n`, { headers: { "content-type": "text/event-stream" } });
            }
            const work = url.match(/^https:\/\/([abcz])\.example\/workspace$/);
            if (work) {
                if (workRefusal) {
                    return new Response(JSON.stringify({ error: workRefusal }), {
                        status: 401,
                        headers: { "content-type": "application/json" },
                    });
                }
                const presented = new Headers(init?.headers).get("x-gaugewright-home-admission");
                if (presented !== `token-${work[1]}-${homeGeneration}`) {
                    const body = JSON.stringify({ error: "target Home admission required" });
                    return new Response(body, {
                        status: 401,
                        headers: { "content-type": "application/json", "content-length": String(body.length) },
                    });
                }
                worked.push(work[1]);
                return new Response(
                    JSON.stringify({
                        archetypes: [], projects: [], recent: [], workstreams: [],
                        work_targets: [], personal_placement: null,
                    }),
                );
            }
            const file = url.match(/^https:\/\/([abcz])\.example\/chats\/chat\/file\?path=file$/);
            if (file) {
                const presented = new Headers(init?.headers).get("x-gaugewright-home-admission");
                if (presented !== `token-${file[1]}-${homeGeneration}`) {
                    const body = JSON.stringify({ error: "target Home admission required" });
                    return new Response(body, {
                        status: 401,
                        headers: { "content-type": "application/json", "content-length": String(body.length) },
                    });
                }
                return new Response("contents");
            }
            throw new Error(`unexpected fetch ${url}`);
        });
        vi.stubGlobal("fetch", fetch);
        const api = new WorkbenchControlPlane("https://hub.example", { splitHomes: true });
        api.setBearer("person-token");
        return {
            api,
            admitted,
            worked,
            streamed,
            publishNewProject: () => { includeNewProject = true; },
            restartHomes: () => { homeGeneration += 1; },
            refuseWork: (reason: string) => { workRefusal = reason; },
        };
    }

    it("sends a project's work to that project's Home, not to a selected one", async () => {
        const { api, worked } = twoHomes();
        api.setCurrentProject("proj-a" as never);
        await api.getWorkspace();
        expect(worked).toEqual(["a"]);
    });

    it("opens and completes a tracker on its owning Home while another project stays selected", async () => {
        const { api, worked } = twoHomes();
        api.setCurrentProject("proj-a" as never);
        expect(await api.listProjectTrackers("proj-b" as never)).toHaveLength(1);
        expect((await api.readProjectTrackerBacklog("proj-b" as never, "tutorials")).tracker.workspaceId).toBe("workspace-b");
        expect((await api.completeProjectTrackerIssue("proj-b" as never, "tutorials", "WS-1", { subjectId: "subject", summary: "done", claim: { kind: "override" }, requestId: "original" })).status).toBe("completed");
        await api.getWorkspace();
        expect(worked).toEqual(["b", "b", "b", "a"]);
    });

    it("listens for tracker changes on the owning Home independently of the selected chat", async () => {
        const { api, worked } = twoHomes();
        api.setCurrentProject("proj-a" as never);
        let changed = 0;
        const stop = await api.subscribeProjectTrackerChanges("proj-b" as never, () => changed++);
        try {
            await vi.waitFor(() => expect(changed).toBe(1));
            await api.getWorkspace();
            expect(worked).toEqual(["b", "a"]);
        } finally { stop(); }
    });

    it("reads personal tracker tasks on their owning Home without changing the selected project", async () => {
        const { api, worked } = twoHomes();
        api.setCurrentProject("proj-a" as never);
        const tasks = await api.readProjectTrackerTasks("proj-b" as never, "tutorials");
        expect(tasks.actor).toBe("person");
        expect(tasks.tracker.workspaceId).toBe("workspace-b");
        await api.getWorkspace();
        expect(worked).toEqual(["b", "a"]);
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

    it("moves a live workspace subscription when the open project changes Home", async () => {
        const { api, admitted, streamed } = twoHomes();
        api.setCurrentProject("proj-a" as never);
        const stop = api.subscribeWorkspace(() => undefined);
        await vi.waitFor(() => expect(streamed).toEqual(["a"]));

        api.setCurrentProject("proj-b" as never);
        await vi.waitFor(() => expect(streamed).toEqual(["a", "b"]));
        expect(admitted).toEqual(["a", "b"]);
        stop();
    });

    it("re-admits once when a Home restart expires its admission", async () => {
        const { api, admitted, worked, restartHomes } = twoHomes();
        api.setCurrentProject("proj-a" as never);
        await api.getWorkspace();
        restartHomes();

        await expect(api.getWorkspace()).resolves.toBeDefined();
        expect(worked).toEqual(["a", "a"]);
        expect(admitted).toEqual(["a", "a"]);
    });

    it("re-admits before retrying a raw Home read after restart", async () => {
        const { api, admitted, restartHomes } = twoHomes();
        api.setCurrentProject("proj-a" as never);
        await api.getWorkspace();
        restartHomes();

        const file = await api.getFileBytes("chat" as never, "file");
        expect(new TextDecoder().decode(file.bytes)).toBe("contents");
        expect(admitted).toEqual(["a", "a"]);
    });

    it("does not turn an account-authentication refusal into a Home reconnect", async () => {
        const { api, admitted, refuseWork } = twoHomes();
        api.setCurrentProject("proj-a" as never);
        refuseWork("authenticate to access your account");

        await expect(api.getWorkspace()).rejects.toThrow(/authenticate to access your account/);
        expect(admitted).toEqual(["a"]);
    });

    it("bounds an expired-admission recovery to one retry", async () => {
        const { api, admitted, refuseWork } = twoHomes();
        api.setCurrentProject("proj-a" as never);
        refuseWork("target Home admission required");

        await expect(api.getWorkspace()).rejects.toThrow(/target Home admission required/);
        expect(admitted).toEqual(["a", "a"]);
    });

    it("refreshes the route projection before opening a project created after the pool", async () => {
        const { api, admitted, worked, publishNewProject } = twoHomes();
        api.setCurrentProject("proj-a" as never);
        await api.getWorkspace();
        publishNewProject();
        api.setCurrentProject("proj-c" as never);
        await api.getWorkspace();
        expect(worked).toEqual(["a", "c"]);
        expect(admitted).toEqual(["a", "c"]);
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

describe("work carried to a relay-only Home (DESK-7, HOME-1)", () => {
    afterEach(() => {
        setTunnelModuleLoader(null);
        setDirectoryModuleLoader(null);
    });

    /** Stand in for the two wasm modules and the relay socket, so the app's own
     * `routeJson` wiring builds the tunnel. The Home behind it answers the way
     * `require_home_admission` does: a work call without the admission it
     * minted is refused, whatever bearer comes with it. */
    function relayOnlyHome() {
        const carried: Array<{ call: string; headers: Record<string, string> | undefined }> = [];
        class Tunnel implements TunnelFacade {
            private reply: { status: number; body: string } | null = null;
            receiveFrame(): void {}
            takeOutgoing(): Uint8Array { return new Uint8Array(); }
            isHandshaking(): boolean { return false; }
            isPaired(): boolean { return true; }
            pollStatus(): number | undefined { return this.reply?.status; }
            takeBody(): string {
                const body = this.reply?.body ?? "";
                this.reply = null;
                return body;
            }
            sendRequest(method: string, path: string, _body?: string,
                        headers?: Record<string, string>): void {
                const call = `${method} ${path}`;
                carried.push({ call, headers });
                const admitted = headers?.["x-gaugewright-home-admission"] === "minted"
                    && headers?.authorization === "Bearer person-token";
                if (call === "POST /home/admissions") {
                    this.reply = { status: 201, body: '{"home":"home:r","admission":"minted"}' };
                } else if (!admitted) {
                    this.reply = { status: 401, body: '{"error":"present the Home admission"}' };
                } else if (call === "GET /workspace") {
                    this.reply = {
                        status: 200,
                        body: JSON.stringify({
                            archetypes: [], projects: [], recent: [], workstreams: [],
                            work_targets: [], personal_placement: null,
                        }),
                    };
                } else {
                    this.reply = { status: 204, body: "" };
                }
            }
        }
        setTunnelModuleLoader(async () => ({
            BrowserTunnel: Object.assign(Tunnel, {
                relayHandshake: () => new Uint8Array([1]),
            }) as never,
        }));
        setDirectoryModuleLoader(async () => ({ verify_signed_put_json: () => true }));
        class Socket {
            readonly OPEN = 1;
            readyState = 1;
            binaryType = "blob";
            onopen: (() => void) | null = null;
            onclose: (() => void) | null = null;
            onmessage: ((event: MessageEvent) => void) | null = null;
            onerror: (() => void) | null = null;
            constructor() { setTimeout(() => this.onopen?.(), 0); }
            send(): void {}
            close(): void { this.readyState = 3; this.onclose?.(); }
        }
        vi.stubGlobal("WebSocket", Socket);
        const held = new Map<string, string>();
        vi.stubGlobal("localStorage", {
            getItem: (key: string) => held.get(key) ?? null,
            setItem: (key: string, value: string) => void held.set(key, value),
        });
        const locator = {
            endpoint: "wss://relay.example",
            handle: "A".repeat(43),
            proof: "B".repeat(42) + "A",
            route_epoch: 1,
            home_fingerprint: "ab".repeat(32),
        };
        vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
            const url = String(input);
            if (url === "https://hub.example/account/directory") {
                return new Response(JSON.stringify({
                    root_pubkey: "ed25519:root",
                    origin: "https://dir.example",
                    subject: "person-1",
                }));
            }
            if (url === `https://dir.example/directory/${encodeURIComponent("ed25519:root")}`) {
                return new Response(JSON.stringify({
                    entry: { directory: {
                        root_pubkey: "ed25519:root",
                        home_routes: [{
                            project: "proj-relay", home_id: "home:r", endpoint: "", relay: locator,
                        }],
                    } },
                }));
            }
            if (url === "https://hub.example/account/home-routes") {
                return new Response(JSON.stringify({ routes: [] }));
            }
            throw new Error(`unexpected fetch ${url}`);
        }));
        const api = new WorkbenchControlPlane("https://hub.example", { splitHomes: true });
        api.setBearer("person-token");
        api.setCurrentProject("proj-relay" as never);
        return { api, carried };
    }

    it("carries the bearer and the Home's admission on the work after admission", async () => {
        // The direct route sent both and the tunnel sent neither, so a Home
        // that gates its work routes admitted a caller over the relay and then
        // refused every call it made.
        const { api, carried } = relayOnlyHome();
        await api.getWorkspace();
        expect(carried.map((c) => c.call)).toEqual(["POST /home/admissions", "GET /workspace"]);
        const [admission, work] = carried;
        expect(admission?.headers?.["x-gaugewright-home-admission"]).toBeUndefined();
        expect(admission?.headers?.authorization).toBe("Bearer person-token");
        expect(work?.headers).toMatchObject({
            authorization: "Bearer person-token",
            "x-gaugewright-home-admission": "minted",
        });
    });
});

describe("a selected Home with no address (DESK-8, ADR 0134)", () => {
    /** The account's only Home is reachable through the relay, so its record in
     * the Home table carries no endpoint. Its reachability comes from the route
     * set instead, and the pool is what reads that. */
    function relayOnlySelected(routeEndpoint: string | null, onRoutes?: () => void) {
        const worked: string[] = [];
        const admitted: string[] = [];
        vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = String(input);
            if (url === "https://hub.example/account/homes") {
                return new Response(JSON.stringify({
                    // No endpoint, and a locator that must be read past: this
                    // table is writable by anyone holding the session, so its
                    // pin proves nothing (ADR 0134 §2).
                    homes: [{
                        id: "home:r",
                        kind: "registered",
                        endpoint: "",
                        relay: {
                            endpoint: "wss://forged.example",
                            handle: "C".repeat(43),
                            proof: "D".repeat(43),
                            route_epoch: 9,
                            home_fingerprint: "cd".repeat(32),
                        },
                    }],
                    selected_home: "home:r",
                }));
            }
            if (url === "https://hub.example/account/directory") {
                return new Response(null, { status: 404 });
            }
            if (url === "https://hub.example/account/home-routes") {
                onRoutes?.();
                return new Response(JSON.stringify({
                    routes: routeEndpoint
                        ? [{ project: "proj-r", home_id: "home:r", endpoint: routeEndpoint }]
                        : [],
                }));
            }
            if (url === "https://r.example/home/admissions" && init?.method === "POST") {
                admitted.push("r");
                return new Response(
                    JSON.stringify({ home: "home:r", admission: "t" }),
                    { status: 201 },
                );
            }
            if (url === "https://r.example/workspace") {
                worked.push("r");
                return new Response(JSON.stringify({
                    archetypes: [], projects: [], recent: [], workstreams: [],
                    work_targets: [], personal_placement: null,
                }));
            }
            throw new Error(`unexpected fetch ${url}`);
        }));
        const api = new WorkbenchControlPlane("https://hub.example", { splitHomes: true });
        api.setBearer("person-token");
        return { api, worked, admitted };
    }

    it("serves work with no project open, through the route set", async () => {
        // Before this, the account-scoped call dialed `selected.endpoint` — the
        // empty string — and every request went to desk's own origin. Nothing
        // could reach a relay-only Home, so nothing could open a project on one.
        const { api, worked } = relayOnlySelected("https://r.example");
        await api.getWorkspace();
        expect(worked).toEqual(["r"]);
    });

    it("shares its connection with the project work on the same Home", async () => {
        const { api, admitted } = relayOnlySelected("https://r.example");
        await api.getWorkspace();
        api.setCurrentProject("proj-r" as never);
        await api.getWorkspace();
        expect(admitted).toEqual(["r"]);
    });

    it("resolves again when the first refresh lands mid-resolution, rather than failing", async () => {
        // After a reload the page has no in-memory bearer, Home discovery starts
        // on the cookie at once, and the first `/auth/refresh` sets the bearer
        // while the routes are still being read. Every hosted load hit this and
        // showed "We couldn't load your Homes" (2026-09-24).
        let refreshes = 0;
        const holder: { api?: WorkbenchControlPlane } = {};
        const { api } = relayOnlySelected("https://r.example", () => {
            if (refreshes++ === 0) holder.api?.setBearer("refreshed-token");
        });
        holder.api = api;
        api.setBearer(null); // a reload: the cookie survives, the bearer does not
        await expect(api.bootstrapHome()).resolves.toMatchObject({ kind: "connected" });
        expect(refreshes).toBe(2);
    });

    it("still refuses when one bearer is replaced by another mid-resolution", async () => {
        // That is a change of person as far as this client can tell, and work
        // begun for one account must never be admitted under the next.
        const holder: { api?: WorkbenchControlPlane } = {};
        const { api } = relayOnlySelected("https://r.example", () => {
            holder.api?.setBearer("someone-else");
        });
        holder.api = api;
        const state = await api.bootstrapHome().catch((error: unknown) => String(error));
        expect(String(state)).toContain("Account session changed while resolving Home routes");
    });

    it("reports a Home that has published nothing as having no Home yet", async () => {
        // Not a failed connection: the Home has to publish a route before
        // anything can reach it, so this belongs with the other "nobody is
        // serving you yet" states rather than with an outage (ADR 0134 §5).
        const { api } = relayOnlySelected(null);
        const state = await api.bootstrapHome();
        expect(state.kind).toBe("none");
    });
});
