import { describe, expect, it } from "vitest";
import { describeChatWhip, getShippedTutorial, listChatWhipRuns, stopChatWhip, launchProjectWorkflow, runChatWhip, startShippedTutorial, type ProjectWorkflowLaunchIntent } from "./project-workflow";
import type { WorkbenchTransport } from "./control-plane-workbench";

const intent: ProjectWorkflowLaunchIntent = { target: "target-personal", path: "tutorials/basics.whip", cut: "cut-1", inputs: { learner: { authority: "learner" } }, requestId: "basics-once" };
const launched = { project: "personal", workspace: "workspace-personal", product_scope: "scope", command: {}, admission: { instance_ref: "workflow-root" } };

describe("project workflow launch client", () => {
    it("retains the same launch intent and request key across retries", async () => {
        const requests: unknown[] = [];
        const transport: WorkbenchTransport = { base: "", json: async (...args) => { requests.push(args); return launched; } };
        const first = await launchProjectWorkflow(transport, "personal", intent);
        const again = await launchProjectWorkflow(transport, "personal", intent);
        expect(first).toEqual({ project: "personal", workspace: "workspace-personal", instanceId: "workflow-root" });
        expect(again).toEqual(first);
        const expected = ["POST", "/projects/personal/workflows", { target: "target-personal", path: "tutorials/basics.whip", cut: "cut-1", inputs: { learner: { authority: "learner" } } }, { idempotencyKey: "basics-once" }];
        expect(requests).toEqual([expected, expected]);
    });
    it("encodes the project as one path segment and never names an actor", async () => {
        const requests: unknown[] = [];
        const transport: WorkbenchTransport = { base: "", json: async (...args) => { requests.push(args); return { ...launched, project: "a/b" }; } };
        await launchProjectWorkflow(transport, "a/b", intent);
        expect((requests[0] as unknown[])[1]).toBe("/projects/a%2Fb/workflows");
        expect(JSON.stringify(requests[0])).not.toContain("actor");
    });
    it("refuses a missing key or a result for another project", async () => {
        const response = (raw: unknown): WorkbenchTransport => ({ base: "", json: async () => raw });
        for (const requestId of ["", " "]) {
            await expect(launchProjectWorkflow(response(launched), "personal", { ...intent, requestId })).rejects.toThrow();
        }
        await expect(launchProjectWorkflow(response({ ...launched, project: "other" }), "personal", intent)).rejects.toThrow("requested project");
        await expect(launchProjectWorkflow(response({ ...launched, admission: {} }), "personal", intent)).rejects.toThrow();
    });
    it("starts a shipped tutorial by name alone, never naming a learner", async () => {
        const requests: unknown[] = [];
        const transport: WorkbenchTransport = { base: "", json: async (...args) => { requests.push(args); return launched; } };
        expect(await startShippedTutorial(transport, "basics")).toEqual({ project: "personal", workspace: "workspace-personal", instanceId: "workflow-root" });
        expect(requests).toEqual([["POST", "/tutorials/basics/start"]]);
        await expect(startShippedTutorial(transport, " ")).rejects.toThrow();
    });
    it("reads installed tutorial source and status by name without a local file path", async () => {
        const requests: unknown[] = [];
        const transport: WorkbenchTransport = { base: "", json: async (...args) => {
            requests.push(args);
            return { project: "tutorials-abc", run_project: "tutorials-abc", publisher: "GaugeWright", file: "basics.whip", source: "workflow Basics()", status: "ready", open_tasks: 0 };
        } };
        expect(await getShippedTutorial(transport, "basics")).toMatchObject({ project: "tutorials-abc", file: "basics.whip", status: "ready" });
        expect(requests).toEqual([["GET", "/tutorials/basics"]]);
    });
    it("describes a chat's whip at the kept revision, keeping unknown kinds runnable as JSON", async () => {
        const requests: unknown[] = [];
        const transport: WorkbenchTransport = { base: "", json: async (...args) => {
            requests.push(args);
            return { project: "personal", target: "target-project-personal", path: "lessons/hello.whip", cut: "cut-9", workflow: "Greeting", inputs: [
                { name: "learner", type: { kind: "object", name: "Learner", fields: [{ name: "authority", type: { kind: "string" } }] } },
                { name: "mood", type: { kind: "enum", variants: ["Calm", "Busy"] } },
                { name: "later", type: { kind: "something-new" } },
            ] };
        } };
        const described = await describeChatWhip(transport, "chat 1", "lessons/hello.whip");
        expect(requests).toEqual([["GET", "/chats/chat%201/whips/inputs?path=lessons%2Fhello.whip"]]);
        expect(described.cut).toBe("cut-9");
        expect(described.inputs.map((i) => i.type.kind)).toEqual(["object", "enum", "json"]);
    });
    it("runs a chat's whip at the described revision under one request key", async () => {
        const requests: unknown[] = [];
        const transport: WorkbenchTransport = { base: "", json: async (...args) => { requests.push(args); return launched; } };
        await runChatWhip(transport, "chat-1", { path: "lessons/hello.whip", cut: "cut-9", inputs: { learner: { authority: "me" } }, requestId: "run-1" });
        expect(requests).toEqual([["POST", "/chats/chat-1/whips/run", { path: "lessons/hello.whip", cut: "cut-9", inputs: { learner: { authority: "me" } } }, { idempotencyKey: "run-1" }]]);
        await expect(runChatWhip(transport, "chat-1", { path: "p.whip", cut: "c", inputs: {}, requestId: " " })).rejects.toThrow();
    });
    it("lists a chat's whip runs, optionally for one file", async () => {
        const requests: unknown[] = [];
        const transport: WorkbenchTransport = { base: "", json: async (...args) => {
            requests.push(args);
            return { runs: [
                { path: "targets/t-a/standup.whip", request_id: "r2", launched_by: "sam", by_you: false, state: "running", started_at: "2026-09-24T10:00:00Z", cut: "c2" },
                { path: "targets/t-a/standup.whip", request_id: "r1", launched_by: "me", by_you: true, state: "paused-somehow", started_at: null, cut: "c1" },
            ] };
        } };
        const runs = await listChatWhipRuns(transport, "chat 1", "targets/t-a/standup.whip");
        const all = await listChatWhipRuns(transport, "chat 1");
        expect(requests).toEqual([
            ["GET", "/chats/chat%201/whips/runs?path=targets%2Ft-a%2Fstandup.whip"],
            ["GET", "/chats/chat%201/whips/runs"],
        ]);
        expect(runs.map((r) => [r.state, r.byYou, r.canStop])).toEqual([["running", false, false], ["unknown", true, false]]);
        expect(all).toHaveLength(2);
    });
    it("stops one run under one request key", async () => {
        const requests: unknown[] = [];
        const transport: WorkbenchTransport = { base: "", json: async (...args) => { requests.push(args); return { run: {} }; } };
        await stopChatWhip(transport, "chat-1", { path: "targets/t-a/standup.whip", launchedBy: "sam", requestId: "r2", key: "stop-1" });
        expect(requests).toEqual([["POST", "/chats/chat-1/whips/stop", { path: "targets/t-a/standup.whip", launched_by: "sam", request_id: "r2" }, { idempotencyKey: "stop-1" }]]);
        await expect(stopChatWhip(transport, "chat-1", { path: "p.whip", launchedBy: "sam", requestId: "r2", key: " " })).rejects.toThrow();
    });
});
