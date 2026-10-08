import { afterEach, describe, expect, it, vi } from "vitest";
import {
    type ArchetypeId,
    type ProjectId,
    setDirectoryModuleLoader,
    setTunnelModuleLoader,
    type RawTunnelFacade,
} from "@gaugewright/control-plane-client";
import { modelKey, modelOptions } from "@gaugewright/workbench-ui";
import { composerModelSource, type OwnModelAccess } from "./composer-model-source";
import { MINE, OWNERS, releaseSharedMember, sharedMember } from "./shared-member.fixture";
import { WorkbenchControlPlane } from "./workbench-control-plane";

afterEach(() => vi.unstubAllGlobals());

describe("desktop-only route placement (WS-675)", () => {
    it("refuses native session and federation reads without contacting a hosted plane", async () => {
        const fetch = vi.fn();
        vi.stubGlobal("fetch", fetch);
        const api = new WorkbenchControlPlane("https://hub.example", { splitHomes: true });
        expect(api.desktopSessionAvailable).toBe(false);
        expect(api.desktopFederationAvailable).toBe(false);
        await expect(api.hubSessionStatus()).rejects.toThrow("unavailable in this composition");
        await expect(api.hubSessionAccounts()).rejects.toThrow("unavailable in this composition");
        await expect(api.listPeers()).rejects.toThrow("unavailable in this composition");
        expect(fetch).not.toHaveBeenCalled();
    });

    it.each([false, true])("keeps desktop reads local when remote-selected=%s", async (remote) => {
        vi.stubGlobal("window", { __TAURI_INTERNALS__: {} });
        const paths: string[] = [];
        vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
            const url = String(input);
            paths.push(url);
            if (url === "http://127.0.0.1:4919/account/hub-session") return new Response(JSON.stringify({ linked: true, person: "alice" }));
            if (url === "http://127.0.0.1:4919/federation/peers") return new Response(JSON.stringify({ peers: [] }));
            throw new Error(`unexpected fetch ${url}`);
        }));
        const api = new WorkbenchControlPlane("http://127.0.0.1:4919");
        api.setNativeRemote(remote);
        expect(api.desktopSessionAvailable).toBe(true);
        expect(api.desktopFederationAvailable).toBe(true);
        await expect(api.hubSessionStatus()).resolves.toMatchObject({ linked: true, person: "alice" });
        await expect(api.listPeers()).resolves.toEqual([]);
        expect(paths).toEqual([
            "http://127.0.0.1:4919/account/hub-session",
            "http://127.0.0.1:4919/federation/peers",
        ]);
    });
});

describe("engagement invites", () => {
    afterEach(() => vi.unstubAllGlobals());
    it.each(["relocate", "join"] as const)("sends the %s disposition the pane asked for", async (disposition) => {
        vi.stubGlobal("window", { __TAURI_INTERNALS__: {} });
        const bodies: unknown[] = [];
        vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = String(input);
            if (url !== "http://127.0.0.1:4919/federation/invite") throw new Error(`unexpected fetch ${url}`);
            bodies.push(JSON.parse(String(init?.body)));
            return new Response(JSON.stringify({
                invite_id: "invite-1",
                invite_url: "gaugewright://invite?d=00",
                confirm_code: "1-2-3",
                project: "proj-a",
                disposition,
            }));
        }));
        const api = new WorkbenchControlPlane("http://127.0.0.1:4919");
        await api.invite("proj-a" as ProjectId, disposition);
        // "Add an operator" once minted a relocating invite: the wrapper
        // dropped the disposition and the Home defaulted to relocate.
        expect(bodies).toEqual([{ project: "proj-a", disposition }]);
    });
});

describe("unpublished directory discovery (WS-675)", () => {
    afterEach(() => setDirectoryModuleLoader(null));
    it("reads once per route resolution, reusing the fallback until the project or account changes", async () => {
        setDirectoryModuleLoader(async () => ({ verify_signed_put_json: () => true }));
        const paths: string[] = [];
        vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
            const url = String(input);
            paths.push(url);
            if (url === "https://hub.example/account/homes") return new Response(JSON.stringify({
                homes: [{ id: "home:cloud", kind: "cloud", endpoint: "https://home.example" }], selected_home: "home:cloud",
            }));
            if (url === "https://hub.example/account/home-routes") return new Response(JSON.stringify({ routes: [] }));
            if (url === "https://hub.example/account/directory") return new Response(null, { status: 404 });
            if (url === "https://home.example/home/admissions") return new Response(JSON.stringify({ home: "home:cloud", admission: "home-token" }));
            if (url === "https://home.example/workspace") return new Response(JSON.stringify({
                archetypes: [], projects: [], recent: [], workstreams: [], work_targets: [], personal_placement: null,
            }));
            throw new Error(`unexpected fetch ${url}`);
        }));
        const api = new WorkbenchControlPlane("https://hub.example", { splitHomes: true });
        api.setBearer("account-token");
        api.setCurrentProject("project:a" as ProjectId);
        for (let i = 0; i < 6; i++) await expect(api.getWorkspace()).resolves.toMatchObject({ projects: [] });
        const discoveryCount = () => paths.filter((path) => path.endsWith("/account/directory")).length;
        // The pool's own discovery began after the project was asked about,
        // so it answers for the ungranted project too: no repair read (WS-891).
        expect(discoveryCount()).toBe(1);
        expect(paths.filter((path) => path.endsWith("/home/admissions"))).toHaveLength(1);
        api.setCurrentProject("project:b" as ProjectId);
        await api.getWorkspace();
        expect(discoveryCount()).toBe(2);
        api.setBearer("next-account-token");
        await api.getWorkspace();
        expect(discoveryCount()).toBe(3);
        expect(paths.filter((path) => path.endsWith("/home/admissions"))).toHaveLength(2);
    });
});

describe("organization shared project creation", () => {
    it("keeps Desktop organization account calls on the sealed local account route", async () => {
        const paths: string[] = [];
        vi.stubGlobal("window", { __TAURI_INTERNALS__: {} });
        vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
            const url = String(input);
            paths.push(url);
            if (url.endsWith("/account/tenants")) {
                return new Response(JSON.stringify({ tenant: {
                    id: "organization:abc", display_name: "Acme", role: "owner", personal: false,
                } }), { status: 201 });
            }
            if (url.endsWith("/account/hub-session/reach")) {
                return new Response(JSON.stringify({
                    person: "alice", device: "desktop",
                    homes: { homes: [], selected_home: null }, routes: { routes: [] },
                }));
            }
            if (url.endsWith("/account/tenants/organization%3Aabc/shared-project")) {
                return new Response(JSON.stringify({ project: {
                    id: "shared", project_id: "proj-org-abc", founding_owner: "alice",
                    display_name: "Acme", home_id: null,
                } }));
            }
            throw new Error(`unexpected account route: ${url}`);
        }));
        const api = new WorkbenchControlPlane("http://127.0.0.1:4919");
        api.setNativeRemote(true);
        await expect(api.createOrganization("Acme")).resolves.toMatchObject({
            sharedProject: { projectId: "proj-org-abc", homeId: null },
        });
        await expect(api.organizationSharedProject("organization:abc")).resolves.toMatchObject({
            projectId: "proj-org-abc", homeId: null,
        });
        // One reach: the routes it read to build the pool are already newer
        // than the question about the Personal project (WS-891).
        expect(paths).toEqual([
            "http://127.0.0.1:4919/account/tenants",
            "http://127.0.0.1:4919/account/hub-session/reach",
            "http://127.0.0.1:4919/account/tenants/organization%3Aabc/shared-project",
            "http://127.0.0.1:4919/account/tenants/organization%3Aabc/shared-project",
        ]);
    });

    it("tries the Personal Home and keeps a pending reservation if that Home is ineligible", async () => {
        const paths: string[] = [];
        vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
            const url = String(input);
            paths.push(url);
            if (url.endsWith("/account/tenants")) {
                return new Response(JSON.stringify({ tenant: {
                    id: "organization:abc", display_name: "Acme", role: "owner", personal: false,
                } }), { status: 201 });
            }
            if (url.endsWith("/organizations/organization%3Aabc/shared-project/materialize")) {
                return new Response(JSON.stringify({ error: "Personal Home is ineligible" }), { status: 409 });
            }
            if (url.endsWith("/account/tenants/organization%3Aabc/shared-project")) {
                return new Response(JSON.stringify({ project: {
                    id: "shared", project_id: "proj-org-abc", founding_owner: "alice",
                    display_name: "Acme", home_id: null,
                } }));
            }
            throw new Error(`unexpected fetch ${url}`);
        }));
        const api = new WorkbenchControlPlane("http://127.0.0.1:4919");
        await expect(api.createOrganization("Acme")).resolves.toMatchObject({
            id: "organization:abc", sharedProject: { projectId: "proj-org-abc", homeId: null },
        });
        await expect(api.organizationSharedProject("organization:abc")).resolves.toMatchObject({
            projectId: "proj-org-abc", homeId: null,
        });
        expect(paths).toEqual([
            "http://127.0.0.1:4919/account/tenants",
            "http://127.0.0.1:4919/organizations/organization%3Aabc/shared-project/materialize",
            "http://127.0.0.1:4919/account/tenants/organization%3Aabc/shared-project",
            "http://127.0.0.1:4919/account/tenants/organization%3Aabc/shared-project",
        ]);
    });
});

describe("selected desktop account outside the local Home", () => {
    it("serves work through the sealed broker and reuses one Home admission", async () => {
        vi.stubGlobal("window", { __TAURI_INTERNALS__: {} });
        const calls: Array<[string, RequestInit | undefined]> = [];
        vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = String(input);
            calls.push([url, init]);
            if (url === "http://127.0.0.1:4919/account/hub-session/reach") {
                return new Response(JSON.stringify({
                    person: "account:b", device: "device:desk",
                    homes: { homes: [{ id: "home:b", kind: "registered", endpoint: "https://b.example" }],
                        selected_home: "home:b" },
                    routes: { routes: [{ project: "project:b", home_id: "home:b",
                        endpoint: "https://b.example" }] },
                }));
            }
            if (url === "http://127.0.0.1:4919/account/hub-session/home/home%3Ab/home/admissions"
                && init?.method === "DELETE") return new Response(null, { status: 204 });
            if (url === "http://127.0.0.1:4919/account/hub-session/home/home%3Ab/home/admissions") {
                return new Response(JSON.stringify({ home: "home:b", admission: "admission:b" }),
                    { status: 201 });
            }
            if (url === "http://127.0.0.1:4919/account/hub-session/home/home%3Ab/workspace") {
                return new Response(JSON.stringify({ archetypes: [], projects: [], recent: [],
                    workstreams: [], work_targets: [], personal_placement: null }));
            }
            if (url === "http://127.0.0.1:4919/account/hub-session/home/home%3Ab/account/settings") {
                return new Response(JSON.stringify({ settings: { theme: "account:b" } }));
            }
            throw new Error(`work escaped the selected account broker: ${url}`);
        }));
        const api = new WorkbenchControlPlane("http://127.0.0.1:4919");
        api.setNativeRemote(true);
        await expect(api.bootstrapHome()).resolves.toMatchObject({ kind: "connected",
            home: { id: "home:b" } });
        api.setCurrentProject("project:b" as never);
        await api.getWorkspace();
        await expect(api.accountSettings()).resolves.toEqual({ theme: "account:b" });
        expect(calls.filter(([url, init]) => url.endsWith("/home/admissions")
            && init?.method === "POST")).toHaveLength(1);
        const work = calls.find(([url]) => url.endsWith("/workspace"));
        const headers = new Headers(work?.[1]?.headers);
        expect(headers.get("x-gaugewright-home-admission")).toBe("admission:b");
        expect(headers.has("authorization")).toBe(false);
        await api.closeAccountConnections();
        expect(calls.some(([url, init]) => url.endsWith("/home/admissions")
            && init?.method === "DELETE")).toBe(true);
    });

    it("opens a relay-only selected Home through the native broker", async () => {
        vi.stubGlobal("window", { __TAURI_INTERNALS__: {} });
        const calls: string[] = [];
        vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
            const url = String(input);
            calls.push(url);
            if (url.endsWith("/account/hub-session/reach")) {
                return new Response(JSON.stringify({
                    person: "account:b", device: "device:desk",
                    homes: { homes: [{ id: "home:b", kind: "registered", endpoint: "" }],
                        selected_home: "home:b" },
                    routes: { routes: [] },
                    signed_routes: { routes: [{ project: "project:b", home_id: "home:b", relay: {
                        endpoint: "wss://relay.example.test", handle: "a".repeat(43),
                        proof: "b".repeat(43), route_epoch: 1,
                        home_fingerprint: "ab".repeat(32),
                    } }] },
                }));
            }
            if (url.endsWith("/home/admissions")) {
                return new Response(JSON.stringify({ home: "home:b", admission: "admission:b" }),
                    { status: 201 });
            }
            if (url.endsWith("/workspace")) {
                return new Response(JSON.stringify({ archetypes: [], projects: [], recent: [],
                    workstreams: [], work_targets: [], personal_placement: null }));
            }
            throw new Error(`work escaped the native broker: ${url}`);
        }));
        const api = new WorkbenchControlPlane("http://127.0.0.1:4919");
        api.setNativeRemote(true);
        await expect(api.bootstrapHome()).resolves.toMatchObject({ kind: "connected",
            home: { id: "home:b" } });
        api.setCurrentProject("project:b" as never);
        await api.getWorkspace();
        expect(calls.some((url) => url.endsWith("/home/home%3Ab/workspace"))).toBe(true);
    });

    // selects-a-registered-native-home: the recovery action uses the production
    // client, changes the account choice, then admits the relay-only Home.
    it("selects a registered native Home in the signed-in account before opening its relay", async () => {
        vi.stubGlobal("window", { __TAURI_INTERNALS__: {} });
        const calls: string[] = [];
        let selected: string | null = null;
        vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = String(input);
            calls.push(url);
            if (url.endsWith("/account/hub-session/homes/selected")) {
                expect(init?.method).toBe("PUT");
                expect(JSON.parse(String(init?.body))).toEqual({ home_id: "home:b" });
                expect(new Headers(init?.headers).has("authorization")).toBe(false);
                selected = "home:b";
                return new Response("{}", { status: 200 });
            }
            if (url.endsWith("/account/hub-session/reach")) {
                return new Response(JSON.stringify({
                    person: "account:b", device: "device:desk",
                    homes: { homes: [{ id: "home:b", kind: "registered", endpoint: "" }],
                        selected_home: selected },
                    routes: { routes: [] },
                    signed_routes: { routes: [{ project: "project:b", home_id: "home:b", relay: {
                        endpoint: "wss://relay.example.test", handle: "a".repeat(43),
                        proof: "b".repeat(43), route_epoch: 1,
                        home_fingerprint: "ab".repeat(32),
                    } }] },
                }));
            }
            if (url.endsWith("/home/admissions")) {
                return new Response(JSON.stringify({ home: "home:b", admission: "admission:b" }),
                    { status: 201 });
            }
            throw new Error(`Home selection escaped the sealed account: ${url}`);
        }));
        const api = new WorkbenchControlPlane("http://127.0.0.1:4919");
        api.setNativeRemote(true);
        await expect(api.selectHome("home:b" as never)).resolves.toMatchObject({
            kind: "connected", home: { id: "home:b" },
        });
        expect(calls[0]).toBe("http://127.0.0.1:4919/account/hub-session/homes/selected");
    });
});

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

    it("sends federation to the admitted Home, never to the blind Hub", async () => {
        // The Hub composes no `/federation/*` route. Sent there without the
        // Home admission, People & sharing's reads failed their preflight on a
        // 404 and the page read "Loading access…" forever (2026-10-07).
        const calls: Array<[string, RequestInit | undefined]> = [];
        vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = String(input);
            calls.push([url, init]);
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
                return new Response(JSON.stringify({ home: "home:cloud", admission: "home-token" }), { status: 201 });
            }
            if (url === "https://home.example/federation/handoff/participants?project=proj-a") {
                return new Response(JSON.stringify({ participants: [] }));
            }
            if (url.startsWith("https://home.example/federation/handoff/status?project=proj-a")) {
                return new Response(JSON.stringify({ project: "proj-a", phase: "draft", home_origin: true, home_target: false, target_has_log: false }));
            }
            throw new Error(`unexpected fetch ${url}`);
        }));
        const api = new WorkbenchControlPlane("https://hub.example", { splitHomes: true });
        api.setBearer("account-token");

        await api.handoffParticipants("proj-a" as never);
        await api.handoffStatus("proj-a" as never);

        const federation = calls.filter(([url]) => url.includes("/federation/"));
        expect(federation.map(([url]) => new URL(url).origin)).toEqual([
            "https://home.example",
            "https://home.example",
        ]);
        for (const [, init] of federation) {
            expect(new Headers(init?.headers).get("x-gaugewright-home-admission")).toBe("home-token");
        }
        expect(calls.some(([url]) => url.startsWith("https://hub.example/federation/"))).toBe(false);
    });

    it("reuses the selected Home admission when switching unrouted projects", async () => {
        const calls: string[] = [];
        vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = String(input);
            calls.push(`${init?.method ?? "GET"} ${url}`);
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
                return new Response(JSON.stringify({ home: "home:cloud", admission: "home-token" }), { status: 201 });
            }
            if (url === "https://home.example/workspace") {
                return new Response(JSON.stringify({
                    archetypes: [], projects: [], recent: [], workstreams: [], work_targets: [], personal_placement: null,
                }));
            }
            throw new Error(`unexpected fetch ${url}`);
        }));
        const api = new WorkbenchControlPlane("https://hub.example", { splitHomes: true });
        api.setBearer("account-token");
        api.setCurrentProject("project:a" as never);
        await api.getWorkspace();
        api.setCurrentProject("project:b" as never);
        await api.getWorkspace();
        expect(calls.filter((call) => call === "POST https://home.example/home/admissions")).toHaveLength(1);
        expect(calls.filter((call) => call === "GET https://home.example/workspace")).toHaveLength(2);
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

    // An asleep laptop is the commonest way a selected Home stops serving, and
    // it used to fail discovery outright: "We couldn't load your Homes", which
    // blamed the account service, hid the other Homes, and offered a Retry that
    // replayed the cached rejection without dialing again.
    it("reports a selected Home that does not answer as not serving, and dials it again on retry", async () => {
        let laptopAwake = false;
        const dialed: string[] = [];
        vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
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
                dialed.push(url);
                if (!laptopAwake) throw new TypeError("Failed to fetch");
                return new Response(JSON.stringify({ home: "home:laptop", admission: "t" }), { status: 201 });
            }
            throw new Error(`unexpected fetch ${url}`);
        }));
        const api = new WorkbenchControlPlane("https://hub.example", { splitHomes: true });
        // The unrouted-project fallback keeps one attempted transport, but a
        // failed bootstrap still clears it so Retry can establish a fresh one.
        api.setCurrentProject("project:unpublished" as ProjectId);

        const asleep = await api.bootstrapHome();
        expect(asleep).toMatchObject({ kind: "none", selectedHome: "home:laptop" });
        expect(asleep.kind === "none" && asleep.homes.map((home) => home.id))
            .toEqual(["home:laptop", "home:studio"]);

        laptopAwake = true;
        await expect(api.bootstrapHome()).resolves.toMatchObject({
            kind: "connected",
            home: { id: "home:laptop" },
        });
        expect(dialed).toHaveLength(2);
    });

    it("gives up on a selected Home that accepts the connection and never answers", async () => {
        vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
            const url = String(input);
            if (url === "https://hub.example/account/homes") {
                return new Response(JSON.stringify({
                    homes: [{ id: "home:laptop", kind: "registered", endpoint: "https://laptop.example" }],
                    selected_home: "home:laptop",
                }));
            }
            if (url === "https://hub.example/account/home-routes") {
                return new Response(JSON.stringify({ routes: [] }));
            }
            if (url === "https://laptop.example/home/admissions") {
                return new Promise<Response>(() => {});
            }
            throw new Error(`unexpected fetch ${url}`);
        }));
        const api = new WorkbenchControlPlane("https://hub.example", {
            splitHomes: true,
            homeDialTimeoutMs: 10,
        });
        await expect(api.bootstrapHome()).resolves.toMatchObject({
            kind: "none",
            selectedHome: "home:laptop",
        });
    });

    it("still fails discovery when the account service itself does not answer", async () => {
        vi.stubGlobal("fetch", vi.fn(async () => {
            throw new TypeError("Failed to fetch");
        }));
        const api = new WorkbenchControlPlane("https://hub.example", { splitHomes: true });
        await expect(api.bootstrapHome()).rejects.toThrow("Failed to fetch");
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
        let workRefusalStatus = 401;
        let workRefusalOnce = false;
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
                    const reason = workRefusal;
                    if (workRefusalOnce) workRefusal = null;
                    return new Response(JSON.stringify({ error: reason }), {
                        status: workRefusalStatus,
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
            refuseWork: (reason: string, status = 401, once = false) => {
                workRefusal = reason;
                workRefusalStatus = status;
                workRefusalOnce = once;
            },
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

    it("re-admits when another connection replaced this Home admission", async () => {
        const { api, admitted, refuseWork } = twoHomes();
        api.setCurrentProject("proj-a" as never);
        await api.getWorkspace();
        refuseWork("Home admission does not match this Home and identity", 403, true);

        await expect(api.getWorkspace()).resolves.toBeDefined();
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

    it("reads the routes once, not per call, for a project with no granted route", async () => {
        const { api, worked, publishNewProject } = twoHomes();
        const routeReads = () => vi.mocked(fetch).mock.calls
            .filter(([url]) => String(url) === "https://hub.example/account/home-routes").length;
        api.setCurrentProject("proj-a" as never);
        await api.getWorkspace();
        const built = routeReads();
        for (let call = 0; call < 3; call += 1) {
            expect(await api.listProjectTrackers("proj-unrouted" as never)).toHaveLength(1);
        }
        expect(worked).toEqual(["a", "z", "z", "z"]);
        expect(routeReads()).toBe(built + 1);
        // A project created after that read is still found by the next miss.
        publishNewProject();
        api.setCurrentProject("proj-c" as never);
        await api.getWorkspace();
        expect(worked.at(-1)).toBe("c");
        expect(routeReads()).toBe(built + 2);
    });
});

describe("projects no route names, asked about all at once (WS-891)", () => {
    /** Six projects served by the selected Home with no route between them,
     * the shape of the chat-turn canary's account. The task bar lists every
     * project's trackers at once, several times while a page settles, and a
     * route read is slow: each is three account and directory requests the
     * Hub answers one after another. Until every read was shared, a new chat
     * waited about a minute for its own route behind ninety of them. */
    function unroutedAccount() {
        const projects = ["proj-1", "proj-2", "proj-3", "proj-4", "proj-5", "proj-6"] as ProjectId[];
        const counts = { routeReads: 0, homeReads: 0, admissions: 0, trackers: 0 };
        const servedBy: string[] = [];
        const streamed: string[] = [];
        let published: { project: string; home_id: string; endpoint: string }[] = [];
        let release: () => void = () => undefined;
        let held: Promise<void> | null = null;
        const hold = () => { held = new Promise((resolve) => { release = resolve; }); };
        vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = String(input);
            if (url === "https://hub.example/account/home-routes") {
                counts.routeReads += 1;
                const routes = published;
                if (held) await held;
                return Response.json({ routes });
            }
            if (url === "https://hub.example/account/directory") return new Response(null, { status: 404 });
            if (url === "https://hub.example/account/homes") {
                counts.homeReads += 1;
                return Response.json({
                    homes: [{ id: "home:z", kind: "cloud", endpoint: "https://z.example" }],
                    selected_home: "home:z",
                });
            }
            const admission = url.match(/^https:\/\/([zn])\.example\/home\/admissions$/);
            if (admission && init?.method === "POST") {
                counts.admissions += 1;
                return Response.json({ home: `home:${admission[1]}`, admission: `token-${admission[1]}` }, { status: 201 });
            }
            const tracker = url.match(/^https:\/\/z\.example\/projects\/([^/]+)\/trackers$/);
            if (tracker) {
                counts.trackers += 1;
                return Response.json({ trackers: [{
                    project_id: tracker[1], workspace_id: "workspace-z", queue: "tasks",
                    resource_id: `tracker-${tracker[1]}`, can_complete: true,
                }] });
            }
            const events = url.match(/^https:\/\/([zn])\.example\/workspace\/events$/);
            if (events) {
                streamed.push(events[1]!);
                return new Response(new ReadableStream({ start(controller) {
                    init?.signal?.addEventListener("abort", () => { try { controller.close(); } catch { /* closed */ } });
                } }), { headers: { "content-type": "text/event-stream" } });
            }
            const workspace = url.match(/^https:\/\/([zn])\.example\/workspace$/);
            if (workspace) {
                servedBy.push(workspace[1]!);
                return Response.json({
                    archetypes: [], projects: [], recent: [], workstreams: [],
                    work_targets: [], personal_placement: null,
                });
            }
            throw new Error(`unexpected fetch ${url}`);
        }));
        const api = new WorkbenchControlPlane("https://hub.example", { splitHomes: true });
        api.setBearer("person-token");
        return {
            api, projects, counts, servedBy, streamed, hold,
            release: () => { const open = release; held = null; open(); },
            publish: (project: string) => {
                published = [...published, { project, home_id: "home:n", endpoint: "https://n.example" }];
            },
        };
    }

    it("shares one route read and one selected Home among every project asked about meanwhile", async () => {
        const { api, projects, counts, servedBy, hold, release } = unroutedAccount();
        hold();
        const taskBar = () => Promise.all(projects.map((project) => api.listProjectTrackers(project)));
        // Three passes of the task bar, and the new chat's route moving to its
        // project, all before the first route read has answered.
        const pending = [taskBar(), taskBar(), taskBar()];
        api.setCurrentProject(projects[0]!);
        const chat = api.getWorkspace();
        await vi.waitFor(() => expect(counts.routeReads).toBe(1));
        release();
        await Promise.all([...pending, chat]);

        expect(counts.routeReads).toBe(1);
        expect(counts.homeReads).toBe(1);
        expect(counts.admissions).toBe(1);
        expect(counts.trackers).toBe(18);
        expect(servedBy).toEqual(["z"]);

        // Once known, an unrouted project is not read about again.
        await taskBar();
        api.setCurrentProject(projects[1]!);
        await api.getWorkspace();
        expect(counts.routeReads).toBe(1);
        expect(counts.homeReads).toBe(1);
    });

    it("leaves the workbench's streams open when the open project keeps the same Home", async () => {
        const { api, projects, streamed, publish } = unroutedAccount();
        const stop = api.subscribeWorkspace(() => undefined);
        try {
            await vi.waitFor(() => expect(streamed).toEqual(["z"]));
            // Opening a chat in a project no route names: still the selected Home.
            api.setCurrentProject(projects[0]!);
            await api.getWorkspace();
            api.setCurrentProject(projects[1]!);
            await api.getWorkspace();
            api.setCurrentProject(null);
            await api.getWorkspace();
            await new Promise((resolve) => setTimeout(resolve, 300));
            expect(streamed).toEqual(["z"]);
            // A project another Home serves still moves them.
            publish("proj-new");
            api.setCurrentProject("proj-new" as ProjectId);
            await vi.waitFor(() => expect(streamed).toEqual(["z", "n"]));
        } finally { stop(); }
    });

    it("still finds a project routed after a read that was already in flight", async () => {
        const { api, projects, counts, servedBy, hold, release, publish } = unroutedAccount();
        await api.listProjectTrackers(projects[0]!);
        expect(counts.routeReads).toBe(1);
        // A read the pool did not answer begins for an older project...
        hold();
        const older = api.listProjectTrackers("proj-older" as ProjectId);
        await vi.waitFor(() => expect(counts.routeReads).toBe(2));
        // ...and a project created on another Home is opened while it runs.
        // That read may predate the project, so it is not the one trusted:
        // the read after it is.
        publish("proj-new");
        api.setCurrentProject("proj-new" as ProjectId);
        const opened = api.getWorkspace();
        release();
        await older;
        await expect(opened).resolves.toBeDefined();
        expect(counts.routeReads).toBe(3);
        // Served by its own Home, not by the selected one.
        expect(servedBy).toEqual(["n"]);
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
        class Tunnel implements RawTunnelFacade {
            private reply: { status: number; body: string } | null = null;
            private raw: { status: number; body: Uint8Array } | null = null;
            private rawHeaders: Record<string, string> = {};
            /** A raw request, answered the way the Home's file route is. */
            sendRequestHead(method: string, path: string, headers: Record<string, string> | undefined): void {
                const call = `${method} ${path}`;
                carried.push({ call, headers });
                const admitted = headers?.["x-gaugewright-home-admission"] === "minted"
                    && headers?.authorization === "Bearer person-token";
                this.rawHeaders = { "content-type": "text/plain; charset=utf-8" };
                this.raw = admitted && path.startsWith("/chats/c1/file?")
                    ? { status: 200, body: new TextEncoder().encode("hello from the Home") }
                    : { status: 401, body: new TextEncoder().encode('{"error":"present the Home admission"}') };
            }
            sendBody(): void {}
            bufferedBytes(): number { return 0; }
            takeBodyBytes(): Uint8Array {
                const body = this.raw?.body ?? new Uint8Array();
                this.raw = null;
                return body;
            }
            takeHeaders(): Record<string, string> { return this.rawHeaders; }
            receiveFrame(): void {}
            takeOutgoing(): Uint8Array { return new Uint8Array(); }
            isHandshaking(): boolean { return false; }
            isPaired(): boolean { return true; }
            takeCredit(): Uint8Array { return new Uint8Array(); }
            pollStatus(): number | undefined { return this.reply?.status ?? this.raw?.status; }
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
        const streamed: Array<{ path: string; headers: Record<string, string> | undefined }> = [];
        /** The Home's event stream, on a session of its own: it opens and sends
         * one change once the relay has delivered a frame. */
        class EventTunnel {
            private pending: Array<{ kind: string; data?: string }> = [];
            constructor(_fingerprint: string, path: string, headers?: Record<string, string>) {
                streamed.push({ path, headers });
            }
            receiveFrame(): void {
                this.pending.push(
                    { kind: "opened" },
                    { kind: "event", data: '{"type":"workspacechanged","record":"chat","id":"c1","op":"upsert"}' },
                );
            }
            takeOutgoing(): Uint8Array { return new Uint8Array(); }
            pollEvent() { return this.pending.shift(); }
            isPaired(): boolean { return true; }
            takeCredit(): Uint8Array { return new Uint8Array(); }
        }
        setTunnelModuleLoader(async () => ({
            BrowserTunnel: Object.assign(Tunnel, {
                relayHandshake: () => new Uint8Array([1]),
            }) as never,
            BrowserEventTunnel: EventTunnel as never,
        }));
        setDirectoryModuleLoader(async () => ({ verify_signed_put_json: () => true }));
        const sockets: Socket[] = [];
        class Socket {
            readonly OPEN = 1;
            readyState = 1;
            binaryType = "blob";
            onopen: (() => void) | null = null;
            onclose: ((event: CloseEvent) => void) | null = null;
            onmessage: ((event: MessageEvent) => void) | null = null;
            onerror: (() => void) | null = null;
            constructor() {
                sockets.push(this);
                setTimeout(() => this.onopen?.(), 0);
            }
            send(): void {}
            close(): void { this.readyState = 3; this.onclose?.({ reason: "" } as CloseEvent); }
            /** The relay delivers one binary frame. */
            deliver(): void { this.onmessage?.({ data: new ArrayBuffer(1) } as MessageEvent); }
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
            // Every computer's entry under the root (DR-0359 §2); this account has one.
            if (url === `https://dir.example/directory/${encodeURIComponent("ed25519:root")}/entries`) {
                return new Response(JSON.stringify({ version: 1, puts: [JSON.stringify({
                    entry: { directory: {
                        root_pubkey: "ed25519:root",
                        home_routes: [{
                            project: "proj-relay", home_id: "home:r", endpoint: "", relay: locator,
                        }],
                    } },
                })] }));
            }
            if (url === "https://hub.example/account/home-routes") {
                return new Response(JSON.stringify({ routes: [] }));
            }
            throw new Error(`unexpected fetch ${url}`);
        }));
        const api = new WorkbenchControlPlane("https://hub.example", { splitHomes: true });
        api.setBearer("person-token");
        api.setCurrentProject("proj-relay" as never);
        return { api, carried, streamed, sockets };
    }

    it("reads a relay-only Home's files over a tunnel of their own (WS-678)", async () => {
        // The tunnel used to carry JSON alone, so every file and config read
        // from a relay-only Home said "Home raw transport unavailable".
        const { api, carried, sockets } = relayOnlyHome();
        expect(await api.getFile("c1" as never, "notes.md")).toBe("hello from the Home");
        const read = carried.find((entry) => entry.call === "GET /chats/c1/file?path=notes.md");
        expect(read?.headers).toMatchObject({
            authorization: "Bearer person-token",
            "x-gaugewright-home-admission": "minted",
        });
        // Its own carrier: one for the calls, one for the raw requests.
        expect(sockets).toHaveLength(2);
    });

    it("streams a relay-only Home's changes over a tunnel of its own (WS-634)", async () => {
        // The tunnel used to carry calls only, so desk opened no stream to such
        // a Home at all: a turn sent from the desktop appeared only on reload.
        const { api, streamed, sockets } = relayOnlyHome();
        const changes: unknown[] = [];
        const opened = vi.fn();
        const stop = api.subscribeWorkspace((change) => changes.push(change), opened);
        await vi.waitFor(() => expect(streamed).toHaveLength(1));
        expect(streamed[0]).toEqual({
            path: "/workspace/events",
            headers: {
                authorization: "Bearer person-token",
                "x-gaugewright-home-admission": "minted",
            },
        });
        // Its own carrier: one for the calls, one for the stream.
        await vi.waitFor(() => expect(sockets).toHaveLength(2));
        await vi.waitFor(() => expect(sockets[1]?.onmessage).toBeTruthy());
        sockets[1]!.deliver();
        await vi.waitFor(() => expect(opened).toHaveBeenCalledOnce());
        expect(changes).toEqual([{ record: "chat", id: "c1", op: "upsert" }]);
        stop();
        expect(sockets[1]!.readyState).toBe(3);
    });

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

describe("GaugeApp management on the one host", () => {
    it("reaches every app's routes under its own base with the same calls", async () => {
        const calls: string[] = [];
        const bodies: Record<string, unknown>[] = [];
        vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = String(input).replace("http://127.0.0.1:4919", "");
            calls.push(`${init?.method ?? "GET"} ${url.split("?")[0]}`);
            if (init?.body) bodies.push(JSON.parse(String(init.body)) as Record<string, unknown>);
            if (url.endsWith("/settings/sessions")) {
                const kind = url.startsWith("/projects/") ? "project" : "agent";
                return new Response(JSON.stringify({ session: {
                    id: `session-${kind}`, generation: "g", scope: { kind, id: "x y" }, actor: "local",
                    pages: [{ id: "overview", resource_basis: `basis-${kind}` }], update_cursor: "c",
                } }));
            }
            if (url.includes("/settings/agent/messages")) {
                return new Response(JSON.stringify({ thread: { id: "t", messages: [] } }));
            }
            return new Response(JSON.stringify({ receipt: { status: "applied" } }));
        }));
        const api = new WorkbenchControlPlane("http://127.0.0.1:4919");
        const agent = { app: "agent-settings", id: "x y" as ArchetypeId } as const;
        const session = await api.openManagement(agent);
        await expect(api.managementMessages(agent, session)).resolves.toEqual([]);
        await api.submitManagementCommand(agent, "overview", "agent.model.set", { model: "m" });
        await api.renameProject("x y" as ProjectId, "Renamed");
        expect(calls).toEqual([
            "POST /archetypes/x%20y/settings/sessions",
            "GET /archetypes/x%20y/settings/agent/messages",
            "POST /archetypes/x%20y/settings/sessions",
            "POST /archetypes/x%20y/settings/commands",
            "POST /projects/x%20y/settings/sessions",
            "POST /projects/x%20y/settings/commands",
        ]);
        const commands = bodies.filter((body) => "command_id" in body);
        expect(commands.map((body) => [body.app, body.command_id, body.expected_basis])).toEqual([
            ["agent-settings", "agent.model.set", "basis-agent"],
            ["project-settings", "project.name.set", "basis-project"],
        ]);
    });

    it("reads a Panel placement's pages and sends a person's verdict to its own command route", async () => {
        const calls: string[] = [];
        const bodies: Record<string, unknown>[] = [];
        vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = String(input).replace("http://127.0.0.1:4919", "");
            calls.push(`${init?.method ?? "GET"} ${url.split("?")[0]}`);
            if (init?.body) bodies.push(JSON.parse(String(init.body)) as Record<string, unknown>);
            if (url.endsWith("/settings/sessions")) {
                return new Response(JSON.stringify({
                    session: {
                        id: "session-panel", generation: "g", scope: { kind: "placement", id: "inst-1" }, actor: "local",
                        pages: [{ id: "inbox", resource_basis: "basis-inbox" }], update_cursor: "c",
                    },
                    pages: [{ id: "inbox", model: { pending: 1, items: [] } }],
                }));
            }
            return new Response(JSON.stringify({ receipt: { status: "applied" } }));
        }));
        const api = new WorkbenchControlPlane("http://127.0.0.1:4919");
        await expect(api.panelSettingsPages("proj-1", "inst-1")).resolves.toEqual([{ id: "inbox", model: { pending: 1, items: [] } }]);
        await api.reviewPanelInboxItem("proj-1", "inst-1", "item-1", "keep");
        expect(calls).toEqual([
            "POST /placements/inst-1/settings/sessions",
            "POST /placements/inst-1/settings/sessions",
            "POST /placements/inst-1/settings/commands",
        ]);
        const command = bodies.find((body) => "command_id" in body)!;
        expect([command.app, command.page_id, command.command_id, command.expected_basis, command.payload])
            .toEqual(["panel-settings", "inbox", "panel.inbox.review", "basis-inbox", { item_id: "item-1", verdict: "keep" }]);
    });
});

// Callback browser transport fixtures, not actual Home admission authority.
describe("task command Home binding (WS-459)", () => {
    function fixture(options: { taskActor?: boolean; renewedActor?: boolean } = {}) {
        let actor = "alice";
        let admissions = 0;
        const tasks: { body: string; key: string | null; admission: string | null }[] = [];
        vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = String(input);
            const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
                status, headers: { "content-type": "application/json" },
            });
            if (url === "https://hub.example/account/homes") return json({
                homes: [{ id: "home:a", kind: "cloud", endpoint: "https://home.example" }], selected_home: "home:a",
            });
            if (url === "https://home.example/home/admissions") {
                admissions++;
                if (admissions > 1 && options.renewedActor) actor = "bob";
                return json({ home: "home:a", admission: `admission-${admissions}` }, 201);
            }
            if (url === "https://hub.example/account/home-routes") return json({ routes: [] });
            if (url === "https://hub.example/account/directory") return json({}, 404);
            if (url === "https://home.example/file-actions/actor") return json({ home: "home:a", actor });
            if (url === "https://home.example/chats/chat-a/task") {
                const headers = new Headers(init?.headers);
                tasks.push({ body: String(init?.body), key: headers.get("idempotency-key"),
                    admission: headers.get("x-gaugewright-home-admission") });
                if (tasks.length === 1 && !options.taskActor) return json({ error: "target Home admission required" }, 401);
                if (options.taskActor) actor = "bob";
                return json({ correlation: { client_request_id: "request-a", chat_id: "chat-a", outcome: "settled" } });
            }
            throw new Error(`unexpected task fixture route ${url}`);
        }));
        const api = new WorkbenchControlPlane("https://hub.example", { splitHomes: true });
        api.setBearer("account-token");
        return { api, tasks, admissions: () => admissions };
    }
    it("renews the exact admission refusal with identical addressed key and body", async () => {
        const { api, tasks, admissions } = fixture();
        const context = await api.taskContext("chat-a" as never);
        await expect(context.runTask("hello", [], "request-a")).resolves.toMatchObject({
            correlation: { client_request_id: "request-a", chat_id: "chat-a", outcome: "settled" },
        });
        expect(tasks).toEqual([
            { body: '{"prompt":"hello"}', key: "request-a", admission: "admission-1" },
            { body: '{"prompt":"hello"}', key: "request-a", admission: "admission-2" },
        ]);
        expect(admissions()).toBe(2);
        expect((await api.taskContext("chat-a" as never)).scope.home).toBe(context.scope.home);
        api.setBearer("renewed-account-token");
        expect((await api.taskContext("chat-a" as never)).scope.home).toBe(context.scope.home);
        api.setCurrentProject("project:other" as ProjectId);
        expect((await api.taskContext("chat-a" as never)).scope.home).not.toBe(context.scope.home);
    });
    it("never resends under a different actual actor after renewal", async () => {
        const { api, tasks } = fixture({ renewedActor: true });
        const context = await api.taskContext("chat-a" as never);
        await expect(context.runTask("hello", [], "request-a")).rejects.toThrow("Task Home actor changed");
        expect(tasks).toHaveLength(1);
    });
    it("rejects a late response after a cookie-only actor switch without resending", async () => {
        const { api, tasks } = fixture({ taskActor: true });
        const context = await api.taskContext("chat-a" as never);
        await expect(context.runTask("hello", [], "request-a")).rejects.toThrow("Task Home actor changed");
        expect(tasks).toHaveLength(1);
    });
    it("cannot reroute old work to a newly selected project", async () => {
        const { api, tasks } = fixture();
        const context = await api.taskContext("chat-a" as never);
        api.setCurrentProject("project:other" as ProjectId);
        await expect(context.runTask("hello", [], "request-a")).rejects.toThrow("Task project selection changed");
        expect(tasks).toHaveLength(0);
    });
});

describe("co-resident task author preflight", () => {
    it("bootstraps the exact missing Home admission before actor proof and opens no task", async () => {
        const requests: { path: string; method: string | undefined; bearer: string | null; admission: string | null }[] = [];
        vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
            const path = new URL(String(input)).pathname;
            const headers = new Headers(init?.headers);
            requests.push({ path, method: init?.method, bearer: headers.get("authorization"),
                admission: headers.get("x-gaugewright-home-admission") });
            if (path === "/home/admissions") return Response.json({ home: "home:a", admission: "renewed" });
            if (path === "/file-actions/actor") return headers.get("x-gaugewright-home-admission") === "renewed"
                ? Response.json({ home: "home:a", actor: "alice" })
                : Response.json({ error: "target Home admission required" }, { status: 401 });
            throw new Error(`unexpected preflight route ${path}`);
        }));
        const api = new WorkbenchControlPlane("https://local.example", { splitHomes: false });
        api.setBearer("alice-login");
        const context = await api.taskContext("chat-a" as never);
        expect(context.scope.authority).toEqual({ home_id: "home:a", actor_id: "alice" });
        expect(requests).toEqual([
            { path: "/file-actions/actor", method: "GET", bearer: "Bearer alice-login", admission: null },
            { path: "/home/admissions", method: "POST", bearer: "Bearer alice-login", admission: null },
            { path: "/file-actions/actor", method: "GET", bearer: "Bearer alice-login", admission: "renewed" },
        ]);
    });

    it("keeps the admission in use while a late refusal renews it (WS-936)", async () => {
        // A desktop window's first message proves the chat's Home actor more
        // than once at a time — its snapshot, its stream and its turn each
        // take a task context — and each is refused before the first admission
        // lands. One refusal can arrive after another caller has re-admitted
        // and gone on to its turn.
        vi.stubGlobal("window", { __TAURI_INTERNALS__: {} });
        const gate = () => {
            let open!: () => void;
            const opened = new Promise<void>((resolve) => { open = resolve; });
            return { open, opened };
        };
        const lateRefusal = gate();
        const renewalAsked = gate();
        const renewal = gate();
        const sent: string[] = [];
        let admissions = 0;
        let unadmittedActorReads = 0;
        vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
            const path = new URL(String(input)).pathname;
            const admission = new Headers(init?.headers).get("x-gaugewright-home-admission");
            sent.push(`${init?.method ?? "GET"} ${path} ${admission ?? "(none)"}`);
            if (path === "/home/admissions") {
                const minted = `admission-${++admissions}`;
                if (admissions === 2) {
                    renewalAsked.open();
                    await renewal.opened;
                }
                return Response.json({ home: "home:a", admission: minted }, { status: 201 });
            }
            if (path === "/file-actions/actor") {
                if (admission) return Response.json({ home: "home:a", actor: "alice" });
                if (++unadmittedActorReads === 2) await lateRefusal.opened;
                return Response.json({ error: "target Home admission required" }, { status: 401 });
            }
            if (path === "/chats/chat-a/task") return Response.json({ run_phase: "Settled" });
            throw new Error(`unexpected route ${path}`);
        }));
        const api = new WorkbenchControlPlane("http://127.0.0.1:4919", { splitHomes: false });
        api.setBearer("alice-session");
        const turn = api.taskContext("chat-a" as never);
        const stream = api.taskContext("chat-a" as never);
        const context = await turn;
        // The stream's refusal arrives now, and it renews while the turn runs.
        lateRefusal.open();
        await renewalAsked.opened;
        await expect(context.runTask("hello", [], "request-a")).resolves.toEqual({ run_phase: "Settled" });
        renewal.open();
        expect((await stream).scope.authority).toEqual({ home_id: "home:a", actor_id: "alice" });
        expect(sent).toEqual([
            "GET /file-actions/actor (none)",
            "GET /file-actions/actor (none)",
            "POST /home/admissions (none)",
            "GET /file-actions/actor admission-1",
            "POST /home/admissions admission-1",
            "GET /file-actions/actor admission-1",
            "POST /chats/chat-a/task admission-1",
            "GET /file-actions/actor admission-1",
            "GET /file-actions/actor admission-2",
        ]);
    });
});

describe("scoped task stream lifetime", () => {
    it("owns one reconnect loop and closes every stream on disposal", async () => {
        vi.useFakeTimers();
        const streams: ReadableStreamDefaultController<Uint8Array>[] = [];
        const flush = async () => { for (let i = 0; i < 40; i++) await Promise.resolve(); };
        vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
            const path = new URL(String(input)).pathname;
            if (path === "/file-actions/actor") return Response.json({ home: "home:a", actor: "alice" });
            if (path === "/chats/chat-a/events") {
                const body = new ReadableStream<Uint8Array>({ start(controller) {
                    streams.push(controller);
                    controller.enqueue(new TextEncoder().encode('data: {"type":"text","delta":"hello"}\n\n'));
                    init?.signal?.addEventListener("abort", () => { try { controller.close(); } catch { /* Already closed. */ } });
                } });
                return new Response(body, { headers: { "content-type": "text/event-stream" } });
            }
            throw new Error(`unexpected stream fixture ${path}`);
        }));
        let close: (() => void) | undefined;
        try {
            const api = new WorkbenchControlPlane("https://local.example", { splitHomes: false });
            api.setBearer("alice-login"); api.setHomeAdmission("minted");
            const context = await api.taskContext("chat-a" as never);
            const event = vi.fn(); const opened = vi.fn();
            close = context.subscribe(event, opened); await flush();
            expect(streams).toHaveLength(1); expect(opened).toHaveBeenCalledTimes(1);
            expect(event).toHaveBeenCalledWith({ type: "text", delta: "hello" });
            streams[0]!.close(); await flush(); await vi.advanceTimersByTimeAsync(251); await flush();
            expect(streams).toHaveLength(2); expect(opened).toHaveBeenCalledTimes(2);
            close(); await flush(); await vi.advanceTimersByTimeAsync(10_000); await flush();
            expect(streams).toHaveLength(2);
        } finally { close?.(); vi.useRealTimers(); }
    });
});

describe("account change releases event stream connections (WS-581)", () => {
    // A desktop shell's streams share one origin with its logout routes, and
    // WebKit opens at most six connections to an origin. Six held streams left
    // the sign-out POST queued forever with the account menu stuck busy.
    function streamingFetch() {
        const live: AbortSignal[] = [];
        const requests: string[] = [];
        vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = new URL(String(input));
            requests.push(`${init?.method ?? "GET"} ${url.pathname}`);
            if (url.pathname === "/workspace/events") {
                const signal = init?.signal;
                if (signal) live.push(signal);
                const body = new ReadableStream<Uint8Array>({ start(controller) {
                    signal?.addEventListener("abort", () => {
                        try { controller.error(new DOMException("aborted", "AbortError")); } catch { /* Already closed. */ }
                    });
                } });
                return new Response(body, { headers: { "content-type": "text/event-stream" } });
            }
            throw new Error(`unexpected fetch ${url.pathname}`);
        }));
        return { live: () => live.filter((signal) => !signal.aborted), requests };
    }
    const flush = async () => { for (let i = 0; i < 40; i++) await Promise.resolve(); };

    it("closes every stream before an account change and holds reconnects until resumed", async () => {
        vi.useFakeTimers();
        const { live, requests } = streamingFetch();
        const stops: (() => void)[] = [];
        try {
            const api = new WorkbenchControlPlane("https://local.example", { splitHomes: false });
            for (let i = 0; i < 6; i++) stops.push(api.subscribeWorkspace(() => undefined));
            await flush();
            expect(live()).toHaveLength(6);

            api.suspendEventStreams();
            expect(live()).toHaveLength(0);
            // Neither a reconnect loop nor a new subscriber reopens one under
            // the account change.
            stops.push(api.subscribeWorkspace(() => undefined));
            await vi.advanceTimersByTimeAsync(10_000); await flush();
            expect(live()).toHaveLength(0);
            expect(requests.filter((request) => request === "GET /workspace/events")).toHaveLength(6);

            // A failed sign-out hands them back: each resolves its route again.
            api.resumeEventStreams();
            await flush(); await vi.advanceTimersByTimeAsync(251); await flush();
            expect(live()).toHaveLength(7);
        } finally {
            for (const stop of stops) stop();
            vi.useRealTimers();
        }
    });

    it("releases the streams when account connections close", async () => {
        const { live } = streamingFetch();
        const api = new WorkbenchControlPlane("https://local.example", { splitHomes: false });
        const stops = [api.subscribeWorkspace(() => undefined), api.subscribeWorkspace(() => undefined)];
        try {
            await vi.waitFor(() => expect(live()).toHaveLength(2));
            await api.closeAccountConnections();
            expect(live()).toHaveLength(0);
        } finally {
            for (const stop of stops) stop();
        }
    });
});

describe("a project is shared by the Home that holds it (DR-0455)", () => {
    afterEach(() => vi.unstubAllGlobals());

    /** An invitation as a Home answers one: hex of its JSON envelope. */
    function minted(envelope: Record<string, unknown>) {
        const invite = Array.from(
            new TextEncoder().encode(JSON.stringify({
                version: 1, invitation: "hinv-1", invited_authority: "",
                invited_email: "alex@example.test", home_id: "home:d", secret: "s", ...envelope,
            })),
            (byte) => byte.toString(16).padStart(2, "0"),
        ).join("");
        return new Response(JSON.stringify({ invite, url: `https://desk.example/invite?d=${invite}`, expires_at: 9 }), { status: 201 });
    }

    it("invites from this computer's own Home without asking which Home is selected", async () => {
        // The founder's desktop answered "No reachable Home is selected" here
        // (2026-10-07): inviting read the account's Home selection first.
        const asked: Array<[string, unknown]> = [];
        vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = String(input);
            asked.push([url, init?.body ? JSON.parse(String(init.body)) : undefined]);
            if (url === "http://127.0.0.1:7878/home/invitations" && init?.method === "POST") {
                return minted({
                    project: "proj-a", endpoint: "",
                    relay: {
                        endpoint: "wss://relay.example.test", handle: "a".repeat(43), proof: "b".repeat(43),
                        route_epoch: 3, home_fingerprint: "c".repeat(64),
                    },
                    placement: { project_key: "k", host_key: "h", placement_signature: "p", locator_signature: "l" },
                    owner_root: "root",
                });
            }
            throw new Error(`unexpected fetch ${url}`);
        }));
        const api = new WorkbenchControlPlane("http://127.0.0.1:7878");

        await expect(api.createHomeInvitation({ email: "alex@example.test" }, "proj-a" as never))
            .resolves.toMatchObject({ project: "proj-a", endpoint: "" });
        // Nobody else reaches this computer at its loopback address, so the
        // Home is asked for an invitation that carries its relay route.
        expect(asked).toEqual([["http://127.0.0.1:7878/home/invitations", expect.objectContaining({ endpoint: "" })]]);
    });

    it("asks the project's own Home, whichever Home the account has selected", async () => {
        const asked: string[] = [];
        vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = String(input);
            asked.push(url);
            if (url === "https://hub.example/account/home-routes") {
                return new Response(JSON.stringify({
                    routes: [{ project: "proj-direct", home_id: "home:d", endpoint: "https://d.example" }],
                }));
            }
            if (url === "https://d.example/home/admissions" && init?.method === "POST") {
                return new Response(JSON.stringify({ home: "home:d", admission: "t" }), { status: 201 });
            }
            if (url === "https://d.example/home/invitations" && init?.method === "POST") {
                expect(JSON.parse(String(init.body))).toMatchObject({ project: "proj-direct", endpoint: "https://d.example" });
                return minted({ project: "proj-direct", endpoint: "https://d.example" });
            }
            throw new Error(`unexpected fetch ${url}`);
        }));
        const api = new WorkbenchControlPlane("https://hub.example", { splitHomes: true });
        api.setBearer("person-token");

        // No project is open and no Home selection is read: the invitation's
        // project alone decides which Home is asked.
        await expect(api.createHomeInvitation({ email: "alex@example.test" }, "proj-direct" as never))
            .resolves.toMatchObject({ homeId: "home:d", endpoint: "https://d.example" });
        expect(asked).not.toContain("https://hub.example/account/homes");
    });
});

describe("projects shared with a member, beside their own (DR-0451, DR-0455, WS-1034)", () => {
    afterEach(releaseSharedMember);
    const member = sharedMember;

    it("lists the shared project beside the member's own, each read from its own desktop", async () => {
        const { api, dialed, carried, hubWrites, projects } = member("selected");
        // The member's own desktop serves them, as their account selected it.
        await expect(api.bootstrapHome()).resolves.toMatchObject({
            kind: "connected", home: { id: "home:local-user", kind: "registered" },
        });
        expect(carried[0]).toEqual({ home: MINE, call: "POST /home/admissions" });
        expect(await projects()).toEqual(["proj-mine", "proj-shared"]);
        // Each desktop dialed once, through its own locator.
        expect([...dialed].sort()).toEqual([MINE, OWNERS]);
        expect(carried).toContainEqual({ home: OWNERS, call: "GET /workspace" });
        // Nothing about the owner's Home was written to the member's account,
        // so their own desktop stays the Home it is.
        expect(hubWrites).toEqual([]);
    });

    it("opens the shared project at the owner's desktop and keeps both projects listed", async () => {
        const { api, dialed, carried, hubWrites, projects } = member("selected");
        await projects();
        // Starting a chat from its row reaches its Home whichever project is open.
        await expect(api.createChatUnderPlacement("proj-shared" as ProjectId, "pl-shared" as never, "new chat", ["t" as never]))
            .resolves.toBe("chat-shared");
        api.setCurrentProject("proj-shared" as ProjectId);
        await expect(api.getTranscript("chat-shared" as never)).resolves.toEqual([]);
        expect(carried.filter((entry) => entry.call.includes("chat-shared") || entry.call.startsWith("POST /projects/")))
            .toEqual([
                { home: OWNERS, call: "POST /projects/proj-shared/placements/pl-shared/chats" },
                { home: OWNERS, call: "GET /chats/chat-shared/transcript" },
            ]);
        // With it open, the workspace is still the member's own beside it, and
        // a Personal chat that read lists stays on the member's own Home.
        expect(api.workspaceProject).toBeNull();
        expect(await projects()).toEqual(["proj-mine", "proj-shared"]);
        api.setCurrentProject("proj-mine" as ProjectId);
        expect(await projects()).toEqual(["proj-mine", "proj-shared"]);
        // One admission at each desktop: neither switch hung the other up,
        // which one key per Home id did.
        expect([...dialed].sort()).toEqual([MINE, OWNERS]);
        expect(carried.filter((entry) => entry.call === "POST /home/admissions").map((entry) => entry.home).sort())
            .toEqual([MINE, OWNERS]);
        expect(hubWrites).toEqual([]);
    });

    it("opens on the shared project for a member with no Home, never reaching their old desktop", async () => {
        const { api, dialed, carried, hubWrites, projects } = member("signed out");
        // Not "no reachable Home is selected": the workbench opens.
        await expect(api.bootstrapHome()).resolves.toMatchObject({
            kind: "connected", home: { id: "home:local-user", endpoint: "" }, withoutOwnHome: true,
        });
        expect(await projects()).toEqual(["proj-shared"]);
        api.setCurrentProject("proj-shared" as ProjectId);
        await expect(api.getTranscript("chat-shared" as never)).resolves.toEqual([]);
        // Their own desktop's entry still names `home:local-user`, and it is
        // never what answers for the owner's project.
        expect(dialed).toEqual([OWNERS]);
        expect(carried.every((entry) => entry.home === OWNERS)).toBe(true);
        expect(hubWrites).toEqual([]);
    });
});

describe("a member whose own Home is not answering keeps their shared projects (WS-1036)", () => {
    afterEach(releaseSharedMember);

    it("opens on the shared projects, says which Home is silent, and does not dial it again", async () => {
        const { api, dialed, carried, hubWrites, projects } = sharedMember("not answering");
        // Not the "is not responding" gate: the workbench opens, saying so.
        await expect(api.bootstrapHome()).resolves.toMatchObject({
            kind: "connected",
            silent: { home: "home:local-user", homes: [expect.objectContaining({ id: "home:local-user" })] },
        });
        expect(await projects()).toEqual(["proj-shared"]);
        api.setCurrentProject("proj-shared" as ProjectId);
        await expect(api.getTranscript("chat-shared" as never)).resolves.toEqual([]);
        // The silent desktop was dialed once, by bootstrap, and not on every read.
        expect(dialed.filter((home) => home === MINE)).toHaveLength(1);
        expect(carried.every((entry) => entry.home === OWNERS)).toBe(true);
        expect(hubWrites).toEqual([]);
    });

    it("keeps the gate for a member with nothing shared with them", async () => {
        const { api } = sharedMember("not answering");
        vi.stubGlobal("localStorage", { getItem: () => null, setItem: () => undefined });
        await expect(api.bootstrapHome()).resolves.toMatchObject({
            kind: "none", selectedHome: "home:local-user",
        });
    });
});

describe("a shared project's Agent is authored at that project's Home (DR-0453, WS-1048)", () => {
    afterEach(releaseSharedMember);

    /** From the Workshop, with no project open: make an authoring chat, send
     * it a message, and read it back, as the navigator and the chat do. */
    async function authorTheSharedAgent(api: ReturnType<typeof sharedMember>["api"]) {
        const listed = (await api.getWorkspaceCarriage()).value;
        expect(listed.archetypes.map((agent) => agent.id)).toEqual(["agent-shared"]);
        api.setCurrentProject(null);
        const chat = await api.createChatUnderArchetype("agent-shared" as ArchetypeId, "edit chat");
        expect(chat).toBe("chat-edit");
        // Before anything has routed the chat by its project.
        await expect(api.runTask(chat, "make it shorter")).resolves.toEqual({ accepted: true });
        await expect(api.getTranscript(chat)).resolves.toEqual([]);
        return chat;
    }

    it("reaches the owner's desktop for a member with no Home of their own", async () => {
        const { api, carried, dialed, hubWrites } = sharedMember("signed out");
        await expect(api.bootstrapHome()).resolves.toMatchObject({ kind: "connected" });
        await authorTheSharedAgent(api);
        // Not "No reachable Home is selected": every call went to the owner's.
        expect(carried.filter((entry) => entry.call.includes("agent-shared") || entry.call.includes("chat-edit")))
            .toEqual([
                { home: OWNERS, call: "POST /archetypes/agent-shared/chats" },
                { home: OWNERS, call: "POST /chats/chat-edit/task" },
                { home: OWNERS, call: "GET /chats/chat-edit/transcript" },
            ]);
        expect(dialed).toEqual([OWNERS]);
        expect(hubWrites).toEqual([]);
    });

    it.each(["signed out", "selected"] as const)(
        "renames, previews and publishes it at the owner's desktop (own Home %s)",
        async (own) => {
            const { api, carried } = sharedMember(own);
            await api.bootstrapHome();
            await api.getWorkspaceCarriage();
            api.setCurrentProject(null);
            await api.renameArchetype("agent-shared" as ArchetypeId, "Shorter writer");
            const preview = await api.previewAgent("agent-shared" as ArchetypeId);
            expect(preview).toBe("chat-preview");
            // The preview it made is the owner's Home's at once.
            await expect(api.getTranscript(preview)).resolves.toEqual([]);
            await api.publishArchetype("agent-shared" as ArchetypeId);
            expect(carried.filter((entry) => /agent-shared|chat-preview/.test(entry.call))).toEqual([
                { home: OWNERS, call: "PUT /archetypes/agent-shared" },
                { home: OWNERS, call: "POST /archetypes/agent-shared/preview" },
                { home: OWNERS, call: "GET /chats/chat-preview/transcript" },
                { home: OWNERS, call: "POST /archetypes/agent-shared/publish" },
            ]);
        },
    );

    it("reaches the owner's desktop, not the member's own, when the member's Home is selected", async () => {
        const { api, carried, hubWrites } = sharedMember("selected");
        await api.bootstrapHome();
        await authorTheSharedAgent(api);
        // The member's own desktop carries the same Home id and never answers
        // for the owner's Agent.
        expect(carried.filter((entry) => entry.home === MINE && /agent-shared|chat-edit/.test(entry.call))).toEqual([]);
        expect(carried.filter((entry) => entry.home === OWNERS && /agent-shared|chat-edit/.test(entry.call)))
            .toHaveLength(3);
        // While the shared project is open, a new project is still the
        // member's own, made on their own desktop.
        api.setCurrentProject("proj-shared" as ProjectId);
        await expect(api.createProject("next")).resolves.toBe("proj-new");
        expect(carried).toContainEqual({ home: MINE, call: "POST /projects" });
        expect(carried).not.toContainEqual({ home: OWNERS, call: "POST /projects" });
        expect(hubWrites).toEqual([]);
    });
});

describe("a member's composer offers the shared project's models (WS-1026)", () => {
    afterEach(releaseSharedMember);

    /** What the composer's picker lists, as `provider:id` keys, with the
     * default row as its label. */
    const offered = (source: ReturnType<typeof composerModelSource>) =>
        modelOptions(source.providers, source.enabled, undefined, source.catalog, source.resolvedDefault)
            .map((option) => (option.id ? modelKey(option) : option.label));

    /** What the person's own account answers the picker, as App reads it. */
    async function ownAccount(api: ReturnType<typeof sharedMember>["api"]): Promise<OwnModelAccess> {
        return {
            credentials: await api.accountCredentials().catch(() => []),
            codexLinked: false,
            settings: {},
            resolvedDefault: await api.defaultModel().catch(() => null),
        };
    }

    it.each(["signed out", "selected"] as const)(
        "reads what the project's key runs from the owner's desktop (own Home %s)",
        async (own) => {
            const { api, carried } = sharedMember(own);
            await api.bootstrapHome();
            await api.getWorkspaceCarriage();
            // An authoring chat of the shared Agent names no project: none is open.
            api.setCurrentProject(null);
            const account = await ownAccount(api);
            // What the composer offered: the member's own account's models —
            // none with no Home of their own, their own key's on their own
            // desktop, which no turn on the owner's computer can spend.
            expect(offered(composerModelSource(null, account))).not.toContain("anthropic:claude-opus-5-5");

            const shared = await api.sharedProjectModels("proj-shared" as ProjectId);
            const models = offered(composerModelSource(shared, account));
            expect(models[0]).toBe("Claude Opus 5.5 (default)");
            expect(models).toContain("anthropic:claude-opus-5-5");
            expect(models.filter((key) => key.startsWith("openai"))).toEqual([]);
            expect(carried).toContainEqual({ home: OWNERS, call: "GET /projects/proj-shared/models" });
            expect(carried.filter((entry) => entry.home === MINE && entry.call.includes("proj-shared"))).toEqual([]);
        },
    );

    it("reads them from the owner's desktop with the shared project open", async () => {
        const { api } = sharedMember("selected");
        await api.bootstrapHome();
        await api.getWorkspaceCarriage();
        api.setCurrentProject("proj-shared" as ProjectId);
        const account = await ownAccount(api);
        // The open project's Home refuses the member its account routes.
        expect(account.credentials).toEqual([]);
        const shared = await api.sharedProjectModels("proj-shared" as ProjectId);
        expect(offered(composerModelSource(shared, account))).toContain("anthropic:claude-opus-5-5");
    });

    it("offers the project's credentials from an owner's desktop that predates the route", async () => {
        const { api, carried } = sharedMember("signed out", { ownerHome: "before project models" });
        await api.bootstrapHome();
        await api.getWorkspaceCarriage();
        const shared = await api.sharedProjectModels("proj-shared" as ProjectId);
        expect(shared).toEqual({
            providers: ["anthropic"],
            endpointModels: {},
            defaultModel: { provider: null, model: null },
        });
        const models = offered(composerModelSource(shared, await ownAccount(api)));
        expect(models).toContain("anthropic:claude-opus-5-5");
        expect(models[0]).not.toMatch(/\(default\)$/);
        expect(carried).toContainEqual({ home: OWNERS, call: "GET /projects/proj-shared/credentials" });
    });

    it("leaves the person's own project to their own account", async () => {
        const { api } = sharedMember("selected");
        await api.bootstrapHome();
        await api.getWorkspaceCarriage();
        await expect(api.sharedProjectModels("proj-mine" as ProjectId)).resolves.toBeNull();
        api.setCurrentProject("proj-mine" as ProjectId);
        const models = offered(composerModelSource(null, await ownAccount(api)));
        expect(models[0]).toBe("GPT-6.1 Sol (default)");
        expect(models).toContain("openai:gpt-6.1-sol");
    });

    it("offers nothing of the person's own while the project's answer is outstanding", () => {
        const own: OwnModelAccess = {
            credentials: [{ provider: "openai", linked: true }],
            codexLinked: true,
            settings: {},
            resolvedDefault: { provider: "openai-codex", model: "gpt-6.1-sol" },
        };
        expect(offered(composerModelSource(undefined, own))).toEqual([]);
    });
});
