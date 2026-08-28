import { describe, expect, it } from "vitest";
import type {
    EngagementId,
    PlacementId,
    WorkspaceRootId,
    WorkstreamId,
    WorkstreamNode,
} from "@gaugewright/control-plane-client";
import { canTransferToMain, canTransferToWorkstream } from "./workstream-transfer";

const root = (id: string) => id as WorkspaceRootId;
const stream = (id: string, workspaceRoot: string): WorkstreamNode => ({
    id: id as WorkstreamId,
    name: id,
    placementId: workspaceRoot as PlacementId,
    projectId: null,
    workspaceRoot: root(workspaceRoot),
    targetId: "target:test" as never,
    status: "active",
    collaboration: "active",
    promotionManifestRef: null,
    promotionTargets: [],
    targetSettlement: "not-requested",
    targetSettlementDeclaration: null,
    targetSettlementMembers: [],
    members: [],
});
const chat = (workspaceRoot: string, workstream: string | null, rehomeBlocked = false) => ({
    id: "chat" as EngagementId,
    workspaceRoot: root(workspaceRoot),
    workstream: workstream as WorkstreamId | null,
    rehomeBlocked,
});

describe("workstream transfer eligibility", () => {
    it("allows a settled chat only onto another line with the exact same root", () => {
        expect(canTransferToWorkstream(chat("placement:a", null), stream("next", "placement:a"))).toBe(true);
        expect(canTransferToWorkstream(chat("placement:a", null), stream("next", "placement:b"))).toBe(false);
        expect(canTransferToWorkstream(chat("archetype:a", null), stream("next", "placement:a"))).toBe(false);
    });

    it("refuses the current line and every move while a candidate is active", () => {
        expect(canTransferToWorkstream(chat("root", "same"), stream("same", "root"))).toBe(false);
        expect(canTransferToWorkstream(chat("root", "old", true), stream("next", "root"))).toBe(false);
        expect(canTransferToMain(chat("root", "old", true), root("root"))).toBe(false);
    });

    it("qualifies each rendered Main header by its own root", () => {
        expect(canTransferToMain(chat("root:a", "old"), root("root:a"))).toBe(true);
        expect(canTransferToMain(chat("root:a", "old"), root("root:b"))).toBe(false);
        expect(canTransferToMain(chat("root:a", null), root("root:a"))).toBe(false);
    });
});
