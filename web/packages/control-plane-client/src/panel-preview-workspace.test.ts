import { describe, expect, it } from "vitest";
import { parseWorkspace } from "./control-plane-domain";

/** A Panel agent's previews are listed only under that agent (DR-0272). */
describe("parseWorkspace — Panel-agent previews", () => {
    const chat = (id: string) => ({
        id,
        title: "Preview of the draft",
        kind: "work",
        placement: "inst-preview",
        workstream: null,
        workspace_root: "project-workspace-panel-preview-1",
        target_id: null,
        target_basis: null,
        target_kind: null,
        target_adapter: null,
        target_path_scope: null,
        target_capabilities: null,
        target_set_revision: 1,
        collaboration_workspace_id: "project-workspace-panel-preview-1",
        targets: [{
            target_id: "target-preview",
            root: "targets/t-target-preview",
            name: "workspace",
            kind: "managed",
            adapter: "whipplescript",
            adapter_family: "whipplescript-v1",
            basis: "cut-preview",
            path_scope: ["."],
            capability_ceiling: { read: true, propose: true, apply: true, publish: false, release: false },
            participation: "writable",
        }],
        candidate_revision: "cut-candidate",
        available_acts: ["read"],
    });
    const agent = (previews?: unknown[]) => ({
        id: "agent-panel",
        name: "Intake",
        kind: "panel",
        panel_profile: null,
        instance_id: "inst-authoring",
        authoring_target_id: "target-authoring",
        is_default: false,
        chats: [],
        workstreams: [],
        ...(previews ? { previews } : {}),
    });
    const workspace = (previews?: unknown[]) => ({
        archetypes: [agent(previews)],
        recent: [],
        projects: [],
        work_targets: [],
    });

    it("parses a draft preview and a version preview with their chats", () => {
        const ws = parseWorkspace(workspace([
            { chat: chat("chat-draft"), placement_id: null, version: null },
            { chat: chat("chat-v2"), placement_id: "inst-placed", version: 2 },
        ]));
        const [draft, version] = ws.archetypes[0].previews;
        expect(draft.chat.id).toBe("chat-draft");
        expect(draft.placementId).toBeNull();
        expect(draft.version).toBeNull();
        expect(version.placementId).toBe("inst-placed");
        expect(version.version).toBe(2);
    });

    it("reads an older projection without previews as none", () => {
        expect(parseWorkspace(workspace()).archetypes[0].previews).toEqual([]);
    });
});
