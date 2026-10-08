import { describe, expect, it } from "vitest";
import { parseWorkspace, type PlacementId } from "@gaugewright/control-plane-client";
import { noReadableTargetReason, readableTargets } from "./placement-targets";

const target = (id: string, name: string, status = "available", read = true) => ({
    id,
    name,
    owner_kind: "project",
    owner_id: "proj-a",
    authority: "local",
    parties: ["local"],
    kind: "external-folder",
    adapter: "folder",
    adapter_family: "folder-v1",
    vcs_posture: "unversioned",
    current_basis: null,
    path_scope: ["."],
    capabilities: { read, propose: read, apply: false, publish: false, release: false },
    status,
    concurrency: "compare-before-write-weak",
});

const workspace = (targetIds: string[], targets: ReturnType<typeof target>[]) => parseWorkspace({
    archetypes: [],
    projects: [{
        id: "proj-a",
        name: "Launch plan",
        targets,
        placements: [{
            placement_id: "inst-general-proj-a",
            archetype_id: "agent-default",
            archetype_name: "Default",
            is_default: true,
            target_ids: targetIds,
            chats: [],
            workstreams: [],
        }],
    }],
    recent: [],
    workstreams: [],
    work_targets: targets,
});
const placement = "inst-general-proj-a" as PlacementId;

describe("the targets a new chat can work on", () => {
    it("are the placement's available, readable targets", () => {
        const listed = workspace(["t-a", "t-b", "t-c"], [
            target("t-a", "Frontend"),
            target("t-b", "Archive", "retired"),
            target("t-c", "Vault", "available", false),
        ]);
        expect(readableTargets(listed, placement).map((item) => item.id)).toEqual(["t-a"]);
    });

    it("say why there is none, naming each target", () => {
        const listed = workspace(["t-a", "t-b"], [target("t-a", "Frontend", "unavailable"), target("t-b", "Vault", "available", false)]);
        expect(readableTargets(listed, placement)).toEqual([]);
        expect(noReadableTargetReason(listed, placement)).toBe(
            'no work target of this Agent can be read: "Frontend" is unavailable; "Vault" cannot be read',
        );
    });

    it("say so when the placement names no target, or one the Home does not list", () => {
        expect(noReadableTargetReason(workspace([], []), placement)).toBe("this Agent has no work target here");
        expect(noReadableTargetReason(workspace(["t-gone"], []), placement)).toBe(
            "no work target of this Agent can be read: one of its work targets is not listed on this Home",
        );
    });
});
