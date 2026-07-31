import { describe, expect, it } from "vitest";
import { parseWorkspace } from "./control-plane-domain";
import { applyWorkspaceDelta, parseWorkspaceDelta } from "./workspace-delta";

const target = {
    id: "target-a",
    name: "Files",
    owner_kind: "project",
    owner_id: "project-a",
    authority: "local",
    parties: ["local"],
    kind: "managed",
    adapter: "whipplescript",
    adapter_family: "whipplescript-v1",
    vcs_posture: "managed",
    current_basis: "cut-a",
    path_scope: ["."],
    capabilities: { read: true, propose: true, apply: true, publish: false, release: false },
    status: "available",
    concurrency: "serialized",
};

const chat = (id: string, title: string, workstream: string | null = null) => ({
    id,
    title,
    kind: "work",
    placement: "placement-a",
    workstream,
    workspace_root: "placement-a::target-a::whipplescript-v1",
    target_id: "target-a",
    target_basis: "cut-a",
    target_kind: "managed",
    target_adapter: "whipplescript",
    target_path_scope: ["."],
    target_capabilities: target.capabilities,
    candidate_revision: "cut-candidate",
    available_acts: ["read", "propose", "apply"],
});

const stream = {
    id: "ws-a",
    name: "Sprint",
    placement_id: "placement-a",
    workspace_root: "placement-a::target-a::whipplescript-v1",
    target_id: "target-a",
    members: ["chat-moved"],
};

const base = () =>
    parseWorkspace({
        archetypes: [
            {
                id: "agent-a",
                name: "Alpha",
                instance_id: "placement-author",
                authoring_target_id: "target-author",
                is_default: false,
                chats: [],
                workstreams: [],
            },
        ],
        projects: [
            {
                id: "project-a",
                name: "Project",
                targets: [target],
                placements: [
                    {
                        placement_id: "placement-a",
                        archetype_id: "agent-a",
                        archetype_name: "Alpha",
                        target_ids: ["target-a"],
                        chats: [
                            chat("chat-old", "Old"),
                            chat("chat-moved", "Moved"),
                        ],
                        workstreams: [],
                    },
                ],
            },
        ],
        recent: [
            chat("chat-moved", "Moved"),
            chat("chat-old", "Old"),
        ],
        workstreams: [],
        work_targets: [target],
        personal_placement: "placement-personal",
    });

describe("workspace delta projection", () => {
    it("moves a chat into a workstream across every denormalized facet", () => {
        const delta = parseWorkspaceDelta(
            {
                archetypes: [],
                projects: [
                    {
                        id: "project-a",
                        name: "Project",
                        targets: [target],
                        placements: [
                            {
                                placement_id: "placement-a",
                                archetype_id: "agent-a",
                                archetype_name: "Alpha",
                                target_ids: ["target-a"],
                                chats: [
                                    chat("chat-old", "Old"),
                                    chat("chat-moved", "Moved", "ws-a"),
                                ],
                                workstreams: [stream],
                            },
                        ],
                    },
                ],
                recent: [
                    chat("chat-moved", "Moved", "ws-a"),
                ],
                workstreams: [stream],
                work_targets: [target],
                personal_placement: "placement-personal",
                order: {
                    archetypes: ["agent-a"],
                    projects: ["project-a"],
                    recent: ["chat-moved", "chat-old"],
                    workstreams: ["ws-a"],
                    work_targets: ["target-a"],
                },
            },
            { record: "chat", id: "chat-moved", op: "upsert" },
        );

        const next = applyWorkspaceDelta(base(), delta);
        expect(next.recent.map((chat) => chat.id)).toEqual(["chat-moved", "chat-old"]);
        expect(next.recent[0]?.workstream).toBe("ws-a");
        expect(next.projects[0]?.placements[0]?.chats[1]?.workstream).toBe("ws-a");
        expect(next.workstreams[0]?.members).toEqual(["chat-moved"]);
    });

    it("applies a tombstone even when the server has no surviving parent", () => {
        const delta = parseWorkspaceDelta(
            {
                archetypes: [],
                projects: [],
                recent: [],
                workstreams: [],
                work_targets: [],
                personal_placement: "placement-personal",
                order: {
                    archetypes: ["agent-a"],
                    projects: ["project-a"],
                    recent: ["chat-moved"],
                    workstreams: [],
                    work_targets: ["target-a"],
                },
            },
            { record: "chat", id: "chat-old", op: "tombstone" },
        );

        const next = applyWorkspaceDelta(base(), delta);
        expect(next.recent.map((chat) => chat.id)).toEqual(["chat-moved"]);
        expect(next.projects[0]?.placements[0]?.chats.map((chat) => chat.id)).toEqual(["chat-moved"]);
    });

    it("rejects an unbranded server order", () => {
        expect(() =>
            parseWorkspaceDelta(
                { work_targets: [], order: { archetypes: [1], projects: [], recent: [], workstreams: [], work_targets: [] } },
                { record: "project", id: "project-a", op: "upsert" },
            ),
        ).toThrow("order.archetypes");
    });
});
