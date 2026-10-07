import { describe, expect, it } from "vitest";
import { parseWorkspace, type ProjectId } from "./control-plane-domain";
import { ownsAgent, sharedAgentProject, workRouteProject } from "./shared-agent";

const project = (id: string) => id as ProjectId;

function workspaceWith(agent: Record<string, unknown>) {
    return parseWorkspace({
        archetypes: [{
            id: "agent-1",
            name: "Customer panel",
            kind: "panel",
            authoring_target_id: "target-1",
            is_default: false,
            chats: [],
            ...agent,
        }],
        projects: [],
        recent: [],
        work_targets: [],
    });
}

describe("an Agent shared through a project (DR-0453)", () => {
    it("reads the projects a member authors it through", () => {
        const [agent] = workspaceWith({ shared_through: ["proj-shared"] }).archetypes;
        expect(agent.sharedThrough).toEqual(["proj-shared"]);
        expect(sharedAgentProject(agent)).toBe("proj-shared");
        expect(ownsAgent(agent)).toBe(false);
    });

    it("is the person's own when the Home names no project", () => {
        const [agent] = workspaceWith({}).archetypes;
        expect(agent.sharedThrough).toEqual([]);
        expect(sharedAgentProject(agent)).toBeNull();
        expect(ownsAgent(agent)).toBe(true);
    });

    it("drops what is not a project id", () => {
        const [agent] = workspaceWith({ shared_through: ["", 7, "proj-shared"] }).archetypes;
        expect(agent.sharedThrough).toEqual(["proj-shared"]);
    });
});

describe("the Home that serves the work in hand", () => {
    const none = { requested: null, agentSettings: null, chatProject: null, authoring: null };

    it("keeps a shared Agent's edit chat or preview on the shared project's Home", () => {
        expect(workRouteProject({ ...none, authoring: project("proj-shared") })).toBe("proj-shared");
    });

    it("keeps a shared Agent's settings on the shared project's Home over an open chat", () => {
        expect(workRouteProject({
            ...none,
            agentSettings: project("proj-shared"),
            chatProject: project("proj-other"),
        })).toBe("proj-shared");
    });

    it("lets settings opened over the chat, then the chat's own project, decide first", () => {
        expect(workRouteProject({
            requested: project("proj-settings"),
            agentSettings: project("proj-shared"),
            chatProject: project("proj-chat"),
            authoring: project("proj-shared"),
        })).toBe("proj-settings");
        expect(workRouteProject({
            ...none,
            chatProject: project("proj-chat"),
            authoring: project("proj-shared"),
        })).toBe("proj-chat");
    });

    it("returns to the selected Home for the person's own Agent", () => {
        expect(workRouteProject(none)).toBeNull();
    });
});
