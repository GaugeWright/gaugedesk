import { describe, expect, it, vi } from "vitest";
import type { HomeId, ProjectId } from "./control-plane-domain";
import {
    holdsSharedProjects,
    pinSharedProject,
    sharedProjectPins,
    sharedProjectRoutes,
    sharedProjectHoldings,
    withSharedProjects,
    withSharedRoutes,
    type SharedProjectPin,
    type SharedRouteWire,
} from "./shared-project-routes";

function memory(): Pick<Storage, "getItem" | "setItem"> {
    const values = new Map<string, string>();
    return {
        getItem: (key) => values.get(key) ?? null,
        setItem: (key, value) => void values.set(key, value),
    };
}

function locator(epoch: number) {
    return {
        endpoint: "wss://relay.example.test",
        handle: "a".repeat(43),
        proof: String.fromCharCode(97 + epoch).repeat(43),
        route_epoch: epoch,
        home_fingerprint: "c".repeat(64),
    };
}

function route(epoch: number, overrides: Partial<SharedRouteWire> = {}): SharedRouteWire {
    return {
        project: "proj-shared",
        home_id: "home:owner",
        endpoint: "",
        relay: locator(epoch),
        placement: { project_key: "project-key", host_key: "host-key", placement_signature: "placed" },
        ...overrides,
    };
}

/** Holds for a placement the pinned key signed, and nothing else. */
const placementVerified = vi.fn(async (wire: unknown, key: string) =>
    key === "project-key"
    && (wire as SharedRouteWire).placement?.placement_signature === "placed");

function pin(overrides: Partial<SharedProjectPin> = {}): SharedProjectPin {
    return {
        project: "proj-shared" as ProjectId,
        homeId: "home:owner" as HomeId,
        projectKey: "project-key",
        ownerRoot: "owner-root",
        route: route(3),
        ...overrides,
    };
}

/** The owning account's directory entries, as the blind directory lists them. */
function entries(...routes: SharedRouteWire[][]): string {
    return JSON.stringify({
        puts: routes.map((home_routes) => JSON.stringify({ entry: { directory: { home_routes } } })),
    });
}

describe("routes to projects on someone else's relay-only Home", () => {
    it("pins only a route its project's key placed, and never a second key", async () => {
        const options = { subject: "invitee", storage: memory(), placementVerified };
        await expect(pinSharedProject(options, pin({
            route: route(3, { placement: { project_key: "project-key", placement_signature: "forged" } }),
        }))).rejects.toThrow(/not signed by its key/);
        expect(sharedProjectPins(options)).toEqual([]);

        await pinSharedProject(options, pin());
        expect(sharedProjectPins(options)).toHaveLength(1);
        await expect(pinSharedProject(options, pin({ projectKey: "another-key" })))
            .rejects.toThrow(/different key/);
        // Pins are per person.
        expect(sharedProjectPins({ ...options, subject: "someone-else" })).toEqual([]);
    });

    it("reads the route again from the owner's directory as the locator rotates", async () => {
        const storage = memory();
        const fetchJson = vi.fn(async (url: string) => {
            expect(url).toBe("https://directory.example.test/directory/owner-root/entries");
            return entries(
                [route(4)],
                [
                    route(5),
                    // Another project's route, and one under another key, are not this one's.
                    route(9, { project: "proj-other" }),
                    route(8, { placement: { project_key: "intruder-key", placement_signature: "placed" } }),
                ],
            );
        });
        const options = {
            subject: "invitee",
            storage,
            placementVerified,
            fetchJson,
            directoryOrigin: "https://directory.example.test/",
        };
        await pinSharedProject(options, pin());
        const routes = await sharedProjectRoutes(options);
        expect(routes).toEqual([expect.objectContaining({
            project: "proj-shared",
            homeId: "home:owner",
            endpoint: "",
            relay: expect.objectContaining({ routeEpoch: 5 }),
        })]);
        // Kept, so an unreachable directory later still leaves the newest route.
        fetchJson.mockRejectedValueOnce(new Error("offline"));
        expect((await sharedProjectRoutes(options))[0]?.relay?.routeEpoch).toBe(5);
        expect(sharedProjectPins(options)[0]?.route.relay).toMatchObject({ route_epoch: 5 });
    });

    it("keeps the pinned route when the owner publishes no root", async () => {
        const fetchJson = vi.fn();
        const options = { subject: "invitee", storage: memory(), placementVerified, fetchJson };
        await pinSharedProject(options, pin({ ownerRoot: undefined }));
        expect((await sharedProjectRoutes(options))[0]?.relay?.routeEpoch).toBe(3);
        expect(fetchJson).not.toHaveBeenCalled();
    });

    it("stands in for the Hub's endpoint-less row for the same project", () => {
        const hub = [
            { project: "proj-mine" as ProjectId, homeId: "home:mine" as HomeId, endpoint: "https://mine.example" },
            { project: "proj-shared" as ProjectId, homeId: "home:owner" as HomeId, endpoint: "https://stale.example" },
        ];
        const shared = [{
            project: "proj-shared" as ProjectId,
            homeId: "home:owner" as HomeId,
            endpoint: "",
            relay: {
                endpoint: "wss://relay.example.test",
                handle: "a".repeat(43),
                proof: "b".repeat(43),
                routeEpoch: 3,
                homeFingerprint: "c".repeat(64),
            },
        }];
        expect(withSharedRoutes(hub, shared)).toEqual([hub[0], shared[0]]);
    });
});

describe("a browser holding no shared project", () => {
    it("says so without asking who is signed in", async () => {
        const storage = memory();
        expect(holdsSharedProjects({ storage })).toBe(false);
        await pinSharedProject({ subject: "invitee", storage, placementVerified }, pin());
        expect(holdsSharedProjects({ storage })).toBe(true);
    });
});

describe("a member's workspace lists the projects shared with them (DR-0451, DR-0455)", () => {
    const empty = {
        archetypes: [], projects: [], recent: [], workstreams: [], workTargets: [],
        personalPlacement: null, homeOrganization: null,
    };
    const project = (id: string, placement: string, target: string, isPersonal = false) => ({
        id, homeId: "home:local-user", name: id, isPersonal, organization: null, networkIsolated: false,
        targets: [{ id: target }], placements: [{ placementId: placement, targetIds: [target], chats: [] }],
    });
    const own = {
        ...empty,
        projects: [project("proj-mine", "pl-mine", "t-mine")],
        workTargets: [{ id: "t-mine" }],
        personalPlacement: "pl-personal",
    } as never;
    const ownersHome = {
        ...empty,
        projects: [project("proj-shared", "pl-shared", "t-shared"), project("proj-owners", "pl-owners", "t-owners")],
        archetypes: [
            { id: "agent-shared", sharedThrough: ["proj-shared"] },
            { id: "agent-owners", sharedThrough: [] },
        ],
        recent: [
            { id: "chat-shared", placement: "pl-shared" },
            { id: "chat-owners", placement: "pl-owners" },
        ],
        workstreams: [
            { id: "ws-shared", projectId: "proj-shared", placementId: "pl-shared" },
            { id: "ws-owners", projectId: "proj-owners", placementId: "pl-owners" },
        ],
        workTargets: [{ id: "t-shared" }, { id: "t-owners" }],
        personalPlacement: "pl-owners-personal",
    } as never;

    it("adds the pinned project from its Home, and nothing else that Home shows", () => {
        const listed = withSharedProjects(own, [{ project: "proj-shared" as ProjectId, workspace: ownersHome }]);
        expect(listed.projects.map((p) => p.id)).toEqual(["proj-mine", "proj-shared"]);
        // So the navigator can say why it is there.
        expect(listed.projects.map((p) => p.sharedWithYou ?? false)).toEqual([false, true]);
        expect(listed.archetypes.map((a) => a.id)).toEqual(["agent-shared"]);
        expect(listed.recent.map((c) => c.id)).toEqual(["chat-shared"]);
        expect(listed.workstreams.map((w) => w.id)).toEqual(["ws-shared"]);
        expect(listed.workTargets.map((t) => t.id)).toEqual(["t-mine", "t-shared"]);
        // The person's own quick-start stays their own Home's.
        expect(listed.personalPlacement).toBe("pl-personal");
    });

    it("lists it for a person with no Home of their own", () => {
        const listed = withSharedProjects(empty as never, [{ project: "proj-shared" as ProjectId, workspace: ownersHome }]);
        expect(listed.projects.map((p) => p.id)).toEqual(["proj-shared"]);
    });

    it("keeps a project the person's own Home already lists as that Home lists it", () => {
        const mine = { ...empty, projects: [{ ...project("proj-shared", "pl-shared", "t-shared"), name: "as listed here" }] } as never;
        const listed = withSharedProjects(mine, [{ project: "proj-shared" as ProjectId, workspace: ownersHome }]);
        expect(listed.projects).toHaveLength(1);
        expect(listed.projects[0]?.name).toBe("as listed here");
    });

    it("never takes a Personal project, or one the Home did not list, from another Home", () => {
        const personal = { ...empty, projects: [project("proj-default", "pl-default", "t-default", true)] } as never;
        const listed = withSharedProjects(own, [
            { project: "proj-default" as ProjectId, workspace: personal },
            { project: "proj-gone" as ProjectId, workspace: ownersHome },
        ]);
        expect(listed.projects.map((p) => p.id)).toEqual(["proj-mine"]);
    });
});

describe("what a shared project brings is held to that project (WS-1048)", () => {
    const empty = {
        archetypes: [], projects: [], recent: [], workstreams: [], workTargets: [],
        personalPlacement: null, homeOrganization: null,
    };
    const agent = (id: string, sharedThrough: string[], chats: string[]) => ({
        id, instanceId: `inst-${id}`, authoringTargetId: `target-${id}`, sharedThrough,
        chats: chats.map((chat) => ({ id: chat })), previews: [{ chat: { id: `preview-${id}` } }],
    });
    const ownersHome = {
        ...empty,
        projects: [{
            id: "proj-shared", isPersonal: false, targets: [{ id: "t-shared" }],
            placements: [{ placementId: "pl-shared", targetIds: ["t-shared"], chats: [{ id: "chat-work" }] }],
        }],
        archetypes: [
            agent("agent-shared", ["proj-shared"], ["chat-edit"]),
            agent("agent-default", ["proj-shared"], ["chat-default-edit"]),
            agent("agent-owners", [], ["chat-owners"]),
        ],
        recent: [{ id: "chat-edit", placement: "inst-agent-shared" }, { id: "chat-owners", placement: "inst-agent-owners" }],
        workstreams: [{ id: "ws-edit", projectId: null, placementId: "inst-agent-shared" }],
        workTargets: [{ id: "t-shared" }, { id: "target-agent-shared" }, { id: "target-agent-owners" }],
    } as never;
    const mine = { ...empty, archetypes: [agent("agent-default", [], [])] } as never;

    it("names the project, its placements and chats, and the Agents placed in it with their chats", () => {
        const held = new Map(sharedProjectHoldings(mine, [{ project: "proj-shared" as ProjectId, workspace: ownersHome }]));
        expect([...held.keys()].sort()).toEqual([
            "archetypes/agent-shared",
            "chats/chat-edit",
            "chats/chat-work",
            "chats/preview-agent-shared",
            "placements/inst-agent-shared",
            "placements/pl-shared",
            "projects/proj-shared",
            "targets/t-shared",
            "targets/target-agent-shared",
            "workstreams/ws-edit",
        ]);
        expect(new Set(held.values())).toEqual(new Set(["proj-shared"]));
        // An Agent the person's own Home lists by the same id stays theirs,
        // and lists as theirs.
        const listed = withSharedProjects(mine, [{ project: "proj-shared" as ProjectId, workspace: ownersHome }]);
        expect(listed.archetypes.map((a) => a.id)).toEqual(["agent-default", "agent-shared"]);
        expect(listed.recent.map((c) => c.id)).toEqual(["chat-edit"]);
    });
});

