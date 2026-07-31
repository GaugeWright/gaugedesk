import { describe, expect, it } from "vitest";
import { parseWorkspace } from "./control-plane-domain";

/** A minimal workspace envelope with one project holding the given placements. */
function workspaceWith(placements: unknown[]) {
    const target = {
        id: "target-1",
        name: "Files",
        owner_kind: "project",
        owner_id: "p1",
        authority: "local",
        parties: ["local"],
        kind: "managed",
        adapter: "whipplescript",
        adapter_family: "whipplescript-v1",
        vcs_posture: "managed",
        current_basis: "cut-1",
        path_scope: ["."],
        capabilities: { read: true, propose: true, apply: true, publish: false, release: false },
        status: "available",
        concurrency: "serialized",
    };
    return {
        archetypes: [],
        recent: [],
        projects: [{ id: "p1", name: "acme", targets: [target], placements }],
        work_targets: [target],
    };
}

describe("parseWorkspace — placement admission (APPROVE-1)", () => {
    it("parses a pending placement's flag through to the domain node", () => {
        const ws = parseWorkspace(
            workspaceWith([
                { placement_id: "i1", archetype_id: "a1", archetype_name: "Reviewer", pinned_version: null, pending: true, target_ids: ["target-1"], chats: [] },
            ]),
        );
        expect(ws.projects[0].placements[0].pending).toBe(true);
    });

    it("defaults pending to false when the field is absent (frictionless / older projection)", () => {
        const ws = parseWorkspace(
            workspaceWith([
                { placement_id: "i1", archetype_id: "a1", archetype_name: "Reviewer", pinned_version: null, target_ids: ["target-1"], chats: [] },
            ]),
        );
        expect(ws.projects[0].placements[0].pending).toBe(false);
    });
});
