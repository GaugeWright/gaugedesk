import { describe, expect, it } from "vitest";
import { parseWorkTarget, parseWorkspace } from "./control-plane-domain";

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
    locator_handle: "managed:secret-server-handle",
};

describe("work-target transport boundary", () => {
    it("never carries a protected locator into the client node", () => {
        expect(parseWorkTarget(target)).not.toHaveProperty("locator_handle");
    });

    it("rejects a pre-target workspace instead of manufacturing compatibility defaults", () => {
        expect(() =>
            parseWorkspace({
                archetypes: [],
                projects: [{ id: "project-a", name: "Project", targets: [], placements: [] }],
                recent: [],
                workstreams: [],
            }),
        ).toThrow("work_targets");
    });

    it("rejects incomplete target records", () => {
        const { adapter_family: _, ...incomplete } = target;
        expect(() => parseWorkTarget(incomplete)).toThrow("adapter_family");
    });
});
