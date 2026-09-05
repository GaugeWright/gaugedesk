import { describe, expect, it } from "vitest";
import { parseWorkspace } from "./control-plane-domain";
import {
    abandonTargetSettlement,
    cancelTargetSettlement,
    compensateTargetSettlement,
    createChatUnderPlacement,
    createWorkstream,
    forkChatAt,
    getTargetSettlement,
    queryTargetSettlementMember,
    retryTargetSettlementMember,
    reviseChatTargets,
    settleChatTargets,
    supersedeTargetSettlementMember,
    type WorkbenchTransport,
} from "./control-plane-workbench";

const capabilities = { read: true, propose: true, apply: true, publish: false, release: false };
const target = (id: string, name: string) => ({
    id,
    name,
    owner_kind: "project",
    owner_id: "project-a",
    authority: "local",
    parties: ["local"],
    kind: "managed",
    adapter: "whipplescript",
    adapter_family: "whipplescript-v1",
    vcs_posture: "managed",
    current_basis: `cut-${id}`,
    path_scope: ["."],
    capabilities,
    status: "available",
    concurrency: "serialized",
});

const member = (id: string, name: string, participation: "read-only" | "writable") => ({
    target_id: id,
    root: `targets/t-${id}`,
    name,
    kind: "managed",
    adapter: "whipplescript",
    adapter_family: "whipplescript-v1",
    basis: `cut-${id}`,
    path_scope: ["."],
    capability_ceiling: capabilities,
    participation,
});

describe("multi-target product wire contract", () => {
    it("parses a chat target set and a target-independent project workstream", () => {
        const rawChat = {
            id: "chat-a",
            title: "Across repos",
            kind: "work",
            placement: "placement-a",
            workstream: "ws-a",
            workspace_root: "project-workspace-a",
            target_id: null,
            target_basis: null,
            target_kind: null,
            target_adapter: null,
            target_path_scope: null,
            target_capabilities: null,
            target_set_revision: 3,
            collaboration_workspace_id: "project-workspace-a",
            targets: [member("target-a", "Frontend", "writable"), member("target-b", "API", "read-only")],
            candidate_revision: "cut-candidate",
            available_acts: ["read", "propose", "apply"],
        };
        const workstream = {
            id: "ws-a",
            name: "Launch",
            placement_id: "placement-a",
            project_id: "project-a",
            workspace_root: "project-workspace-a",
            target_id: null,
            status: "promoted",
            collaboration: "promoted",
            promotion_manifest_ref: "manifest-a",
            promotion_targets: ["target-a", "target-b"],
            target_settlement: "partially-applied",
            target_settlement_declaration: "settlement-a",
            target_settlement_members: [{ member_id: "m-a", target_id: "target-a", act: "apply", phase: "succeeded" }],
            members: [],
        };
        const workspace = parseWorkspace({
            archetypes: [],
            projects: [{
                id: "project-a",
                name: "Project",
                targets: [target("target-a", "Frontend"), target("target-b", "API")],
                placements: [{
                    placement_id: "placement-a",
                    archetype_id: "agent-a",
                    archetype_name: "Agent",
                    target_ids: ["target-a", "target-b"],
                    chats: [rawChat],
                    workstreams: [workstream],
                }],
            }],
            recent: [{ ...rawChat, archetype: "Agent" }],
            workstreams: [workstream],
            work_targets: [target("target-a", "Frontend"), target("target-b", "API")],
        });

        const chat = workspace.projects[0].placements[0].chats[0];
        expect(chat.targetId).toBeNull();
        expect(chat.targets.map((item) => [item.targetId, item.participation])).toEqual([
            ["target-a", "writable"],
            ["target-b", "read-only"],
        ]);
        expect(chat.targetSetRevision).toBe(3);
        expect(workspace.workstreams[0]).toMatchObject({
            projectId: "project-a",
            targetId: null,
            promotionTargets: ["target-a", "target-b"],
            targetSettlement: "partially-applied",
        });
    });

    it("refuses raw substrate workstream and settlement phases at the product boundary", () => {
        const raw = {
            archetypes: [],
            projects: [],
            recent: [],
            work_targets: [],
            workstreams: [{
                id: "ws-raw",
                name: "Raw",
                placement_id: "placement-a",
                project_id: "project-a",
                workspace_root: "project-workspace-a",
                status: "archived",
                collaboration: "archived",
                target_settlement: "partially_applied",
            }],
        };
        expect(() => parseWorkspace(raw as never)).toThrow(/bad collaboration status/);
    });

    it("sends explicit target arrays, target-free workstreams, and fork destinations", async () => {
        const calls: { method: string; path: string; body: unknown }[] = [];
        const transport: WorkbenchTransport = {
            base: "https://home.example",
            json: async (method, path, body) => {
                calls.push({ method, path, body });
                if (path.endsWith("/workstreams")) {
                    return { id: "ws-a", name: "Launch", placement_id: "placement-a", project_id: "project-a", workspace_root: "project-workspace-a", target_id: null };
                }
                return { id: path.includes("fork") ? "chat-fork" : "chat-a" };
            },
        };

        await createChatUnderPlacement(transport, "project-a" as never, "placement-a" as never, "Across", ["target-a" as never, "target-b" as never]);
        await createWorkstream(transport, "placement-a" as never, "Launch");
        await forkChatAt(transport, "chat-a" as never, 42, { kind: "main" });
        await reviseChatTargets(transport, "chat-a" as never, [
            { targetId: "target-a" as never, participation: "writable" },
            { targetId: "target-b" as never, participation: "read-only" },
        ]);
        await getTargetSettlement(transport, "settlement-a");
        await queryTargetSettlementMember(transport, "settlement-a", "member-a");
        await retryTargetSettlementMember(transport, "settlement-a", "member-a");
        await supersedeTargetSettlementMember(transport, "settlement-a", "member-a", "settlement-b", "member-b");
        const compensationLink = {
            original_receipt_ref: "receipt-original",
            compensation_declaration_id: "settlement-repair",
            compensation_member_id: "member-repair",
            compensation_receipt_ref: "receipt-compensation",
        };
        await compensateTargetSettlement(transport, "settlement-a", [compensationLink]);
        await abandonTargetSettlement(transport, "settlement-a", "operator chose forward repair");
        await cancelTargetSettlement(transport, "settlement-a", "not started");

        expect(calls[0].body).toEqual({ title: "Across", target_ids: ["target-a", "target-b"] });
        expect(calls[1].body).toEqual({ name: "Launch" });
        expect(calls[2].body).toEqual({ destination: { kind: "main" } });
        expect(calls[3].body).toEqual({ targets: [
            { target_id: "target-a", participation: "writable" },
            { target_id: "target-b", participation: "read-only" },
        ] });
        expect(calls.slice(4).map((call) => [call.method, call.path, call.body])).toEqual([
            ["GET", "/target-settlements/settlement-a", undefined],
            ["POST", "/target-settlements/settlement-a/members/member-a/query", {}],
            ["POST", "/target-settlements/settlement-a/members/member-a/retry", {}],
            ["POST", "/target-settlements/settlement-a/members/member-a/supersede", { later_declaration_id: "settlement-b", later_member_id: "member-b" }],
            ["POST", "/target-settlements/settlement-a/compensate", { receipt_links: [compensationLink] }],
            ["POST", "/target-settlements/settlement-a/abandon", { reason: "operator chose forward repair" }],
            ["POST", "/target-settlements/settlement-a/cancel", { reason: "not started" }],
        ]);
    });

    it("preflights one chat declaration before executing each admitted member", async () => {
        const calls: { method: string; path: string; body: unknown }[] = [];
        const transport: WorkbenchTransport = {
            base: "https://home.example",
            json: async (method, path, body) => {
                calls.push({ method, path, body });
                if (path === "/chats/chat-a/settlements") {
                    return {
                        declaration: {
                            declaration_id: "settlement-a",
                            members: [{ member_id: "member-a" }, { member_id: "member-b" }],
                        },
                    };
                }
                return { phase: "completed" };
            },
        };
        await settleChatTargets(transport, "chat-a" as never, [
            { target_id: "target-a" as never, act: "apply" },
            { target_id: "target-b" as never, act: "publish" },
        ]);
        expect(calls).toEqual([
            { method: "POST", path: "/chats/chat-a/settlements", body: { members: [
                { target_id: "target-a", act: "apply" },
                { target_id: "target-b", act: "publish" },
            ] } },
            { method: "POST", path: "/target-settlements/settlement-a/members/member-a/execute", body: {} },
            { method: "POST", path: "/target-settlements/settlement-a/members/member-b/execute", body: {} },
            { method: "GET", path: "/target-settlements/settlement-a", body: undefined },
        ]);
    });
});
