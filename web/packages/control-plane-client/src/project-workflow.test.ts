import { describe, expect, it } from "vitest";
import { launchProjectWorkflow, type ProjectWorkflowLaunchIntent } from "./project-workflow";
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
});
