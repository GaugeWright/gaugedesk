import { describe, expect, it, vi } from "vitest";
import { engagementId, scopeId } from "./control-plane-domain";
import type { PlacementId, ProjectId } from "./control-plane-domain";
import type { WorkbenchTransport } from "./control-plane-workbench";
import {
    exportResourceToDisk,
    forkProject,
    projectUpstream,
    pullProjectUpstream,
    getPlacementDistribution,
    getPlacementDistributionAudit,
    getResourceExport,
    getResourceReview,
    getChatNotices,
    getRunCarriage,
    resourceExportCommand,
    resourceReviewCommand,
    renewPlacementDistribution,
    revokePlacementDistribution,
    runTask,
    setPlacementDistribution,
    subscribeWorkspace,
} from "./control-plane-workbench";

describe("workspace refresh references", () => {
    it("carries an identifier-free refresh to the subscriber", () => {
        let accept: ((data: string) => void) | undefined;
        const changed = vi.fn();
        const stop = vi.fn();
        const transport = {
            base: "", json: vi.fn(),
            events: (_path: string, callback: (data: string) => void) => { accept = callback; return stop; },
        } as WorkbenchTransport;
        const unsubscribe = subscribeWorkspace(transport, changed);
        accept!(JSON.stringify({ type: "workspacechanged", record: "project", id: "", op: "upsert" }));
        expect(changed).toHaveBeenCalledExactlyOnceWith({ record: "project", id: "", op: "upsert" });
        unsubscribe();
        expect(stop).toHaveBeenCalledOnce();
    });
});

describe("placement distribution profiles", () => {
    it("keeps licensed distribution explicit and addresses the full commercial lifecycle", async () => {
        const licensed = {
            placement_id: "placement-1",
            profile: "licensed",
            recipient_authority: "",
            service_origin: "https://auth.gaugewright.com",
            lease_seconds: 0,
            max_runs: 0,
            state: "licensed",
        };
        const json = vi.fn().mockResolvedValue(licensed);
        const transport = { base: "", json } as WorkbenchTransport;
        const placement = "placement-1" as PlacementId;

        await getPlacementDistribution(transport, placement);
        await setPlacementDistribution(transport, placement, {
            profile: "protected_commercial",
            recipient_authority: "tenant:recipient",
            recipient_display_name: "Recipient & Co",
            lease_seconds: 86_400,
            max_runs: 5,
        });
        await renewPlacementDistribution(transport, placement);
        await revokePlacementDistribution(transport, placement);
        await getPlacementDistributionAudit(transport, placement);

        expect(json.mock.calls).toEqual([
            ["GET", "/placements/placement-1/distribution"],
            ["PUT", "/placements/placement-1/distribution", {
                profile: "protected_commercial",
                recipient_authority: "tenant:recipient",
                recipient_display_name: "Recipient & Co",
                lease_seconds: 86_400,
                max_runs: 5,
            }],
            ["POST", "/placements/placement-1/distribution/renew", {}],
            ["POST", "/placements/placement-1/distribution/revoke", {}],
            ["GET", "/placements/placement-1/distribution/audit"],
        ]);
    });
});

describe("resource protection routes", () => {
    it("addresses review and export through the encoded resource, never a caller scope", async () => {
        const review = { phase: "Proposed", required: ["owner"], consented: [] };
        const exp = {
            phase: "Requested",
            source_required: ["owner"],
            source_consented: [],
            target_admitted: false,
        };
        const json = vi.fn()
            .mockResolvedValueOnce(review)
            .mockResolvedValueOnce(exp)
            .mockResolvedValueOnce({ ...review, phase: "Cleared", consented: ["owner"] })
            .mockResolvedValueOnce({ ...exp, source_consented: ["owner"] });
        const transport = { base: "", json } as WorkbenchTransport;
        const chat = engagementId("chat-1");

        await getResourceReview(transport, chat, "out/chat 1");
        await getResourceExport(transport, chat, "out/chat 1");
        await resourceReviewCommand(transport, chat, "out/chat 1", "consent", "review-key");
        await resourceExportCommand(transport, chat, "out/chat 1", "consent", "export-key");

        expect(json.mock.calls).toEqual([
            ["GET", "/chats/chat-1/resources/out%2Fchat%201/review"],
            ["GET", "/chats/chat-1/resources/out%2Fchat%201/export"],
            ["POST", "/chats/chat-1/resources/out%2Fchat%201/review/command", { action: "consent" }, { idempotencyKey: "review-key" }],
            ["POST", "/chats/chat-1/resources/out%2Fchat%201/export/command", { action: "consent" }, { idempotencyKey: "export-key" }],
        ]);
    });
});

describe("exportResourceToDisk", () => {
    it("posts the exact desktop egress route and decodes its result", async () => {
        const json = vi.fn().mockResolvedValue({
            exported: ["deliverable.txt"],
            dest: "/tmp/delivery",
        });
        const transport = { base: "", json } as WorkbenchTransport;

        await expect(
            exportResourceToDisk(
                transport,
                engagementId("chat-1"),
                "out/chat 1",
                "/tmp/delivery",
            ),
        ).resolves.toEqual({ exported: ["deliverable.txt"], dest: "/tmp/delivery" });
        expect(json).toHaveBeenCalledWith(
            "POST",
            "/chats/chat-1/resources/out%2Fchat%201/export-to-disk",
            { dest: "/tmp/delivery" },
        );
    });

    it("fails closed on a malformed response", async () => {
        const transport = {
            base: "",
            json: vi.fn().mockResolvedValue({ exported: [7], dest: "/tmp/delivery" }),
        } as WorkbenchTransport;
        await expect(
            exportResourceToDisk(transport, engagementId("chat-1"), "out-1", "/tmp/delivery"),
        ).rejects.toThrow("malformed exported files");
    });
});

describe("running a turn", () => {
    it("keys the turn on the composed id, so a resend is the same command", async () => {
        // ADR 0137 §3. The key has to be the id the message was *composed* under,
        // not one minted per attempt — that is the difference between a resend the
        // host recognises and a second turn.
        const json = vi.fn().mockResolvedValue({});
        const transport = { base: "", json } as WorkbenchTransport;
        await runTask(transport, engagementId("chat-1"), "go", [], "outbox-7");
        expect(json).toHaveBeenCalledWith(
            "POST",
            "/chats/chat-1/task",
            { prompt: "go" },
            { idempotencyKey: "outbox-7" },
        );
    });

    it("leaves the key to the transport when no composed id is offered", async () => {
        // A caller with no outbox still gets a fresh key per attempt from the
        // request edge. Sending `undefined` here rather than a fabricated id keeps
        // "this is one identified message" from being claimed falsely.
        const json = vi.fn().mockResolvedValue({});
        const transport = { base: "", json } as WorkbenchTransport;
        await runTask(transport, engagementId("chat-1"), "go");
        expect(json).toHaveBeenCalledWith("POST", "/chats/chat-1/task", { prompt: "go" }, undefined);
    });
});

describe("chat notices", () => {
    it("reads each understood notice and drops the rest", async () => {
        const json = vi.fn().mockResolvedValue({
            notices: [
                { chat: "chat-1", title: "Plan", signal: "question", settle: 2, failed: false },
                { chat: "chat-2", title: "Fix", signal: "turn-settled", settle: 3, failed: true },
                { chat: "chat-3", title: "Later", signal: "celebration", settle: 1 },
                { chat: "chat-4", title: "No count", signal: "conflict" },
                { chat: "chat-5", title: "Odd count", signal: "conflict", settle: 1.5 },
                { title: "No chat", signal: "conflict", settle: 1 },
            ],
        });
        const transport = { base: "", json } as WorkbenchTransport;

        const notices = await getChatNotices(transport);

        expect(json).toHaveBeenCalledWith("GET", "/notices");
        expect(notices).toEqual([
            { chat: "chat-1", title: "Plan", signal: "question", settle: 2, failed: false },
            { chat: "chat-2", title: "Fix", signal: "turn-settled", settle: 3, failed: true },
        ]);
    });

    it("reads a reply without notices as none", async () => {
        const json = vi.fn().mockResolvedValue({});
        const transport = { base: "", json } as WorkbenchTransport;

        expect(await getChatNotices(transport)).toEqual([]);
    });
});

describe("project fork and pull", () => {
    it("forks with an idempotency key and reports Agents that were not placed", async () => {
        const json = vi.fn().mockResolvedValue({
            id: "proj-fork-1",
            skipped_agents: [{ agent_id: "a", name: "Reviewer", reason: "this Agent belongs to another account" }],
        });
        const transport = { base: "", json } as WorkbenchTransport;
        const forked = await forkProject(transport, "proj-1" as ProjectId, undefined, "op-1");
        expect(json).toHaveBeenCalledWith("POST", "/projects/proj-1/fork", { operation_id: "op-1" });
        expect(forked).toEqual({
            id: "proj-fork-1",
            skippedAgents: [{ name: "Reviewer", reason: "this Agent belongs to another account" }],
        });
    });

    it("reads an unavailable original as unavailable, never as up to date", async () => {
        const json = vi.fn().mockResolvedValue({ upstream: { available: false, reason: "you can no longer open the original" } });
        const upstream = await projectUpstream({ base: "", json } as WorkbenchTransport, "proj-2" as ProjectId);
        expect(upstream).toEqual({ available: false, projectId: null, name: null, reason: "you can no longer open the original" });
    });

    it("pulls against the previewed cut with a choice for every conflict", async () => {
        const json = vi.fn()
            .mockResolvedValueOnce({ upstream: { available: true, project_id: "proj-1", name: "Peach", source_cut: "cut-9", take: ["a.md"], remove: [], conflicts: ["b.md"] } })
            .mockResolvedValueOnce({ pulled: 2 });
        const transport = { base: "", json } as WorkbenchTransport;
        const upstream = await projectUpstream(transport, "proj-2" as ProjectId);
        expect(upstream).toMatchObject({ available: true, sourceCut: "cut-9", take: ["a.md"], conflicts: ["b.md"] });
        const result = await pullProjectUpstream(transport, "proj-2" as ProjectId, "cut-9", { "b.md": "theirs" });
        expect(json).toHaveBeenLastCalledWith("POST", "/projects/proj-2/upstream/pull", { source_cut: "cut-9", resolutions: { "b.md": "theirs" } });
        expect(result.pulled).toBe(2);
    });
});

describe("run projection carriage (UX-13)", () => {
    it("reads the run through the freshness carriage and keeps a non-live marker", async () => {
        const json = vi.fn(async () => ({
            value: { phase: "Running", admitted_once: true },
            freshness: { marker: "partial", generated_at: 7, repair_hint: "refresh run for chat-1" },
            client_request_id: null,
        }));
        const transport = { base: "", json } as WorkbenchTransport;
        const carriage = await getRunCarriage(transport, scopeId("chat-1"));
        expect(json).toHaveBeenCalledExactlyOnceWith("GET", "/projections/chat-1/run?freshness=live");
        expect(carriage.value.phase).toBe("Running");
        expect(carriage.freshness.marker).toBe("partial");
        expect(carriage.freshness.repairHint).toBe("refresh run for chat-1");
    });
});
