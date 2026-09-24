import { describe, expect, it } from "vitest";
import { completeProjectTrackerIssue, listProjectTrackers, subscribeAnyProjectTrackerChanges, parseProjectTrackerBacklog, readProjectTrackerBacklog, readProjectTrackerTasks, subscribeProjectTrackerChanges, type TrackerCompletionIntent } from "./project-tracker";
import type { WorkbenchTransport } from "./control-plane-workbench";

const tracker = { project_id: "personal", workspace_id: "workspace-personal", queue: "tutorials", resource_id: "native-tracker", can_complete: true };
const item = { id: "WS-1", subject_id: "permanent-subject", title: "Create a chat", body: "Open Personal", status: "open", assigned_to: null, claimed_by: null, filed_by: "learner", labels: [], created_at: "now", updated_at: "now" };
const completion = { snapshot: { admission: { instance_ref: "human-root" }, instance_status: "completed" }, executed_effect: "closing-effect", recovered_effect: null };

describe("project tracker native client", () => {
    it("reads the Homes authenticated assignments without supplying an actor", async () => {
        const requests: unknown[] = [];
        const transport: WorkbenchTransport = { base: "", json: async (...args) => {
            requests.push(args);
            return { actor: "learner", tracker, issues: [{ ...item, assigned_to: "learner", claimed_by: "colleague" }] };
        } };
        const result = await readProjectTrackerTasks(transport, "personal", "tutorials");
        expect(result.actor).toBe("learner");
        expect(result.issues[0]).toMatchObject({ subjectId: "permanent-subject", assignedTo: "learner", claimedBy: "colleague" });
        expect(requests).toEqual([["GET", "/projects/personal/trackers/tutorials/tasks"]]);
    });
    it("refuses assignments that contradict the authenticated actor or active status", async () => {
        const response = (raw: unknown): WorkbenchTransport => ({ base: "", json: async () => raw });
        for (const actor of [undefined, null, "", " "]) {
            await expect(readProjectTrackerTasks(response({ actor, tracker, issues: [] }), "personal", "tutorials")).rejects.toThrow();
        }
        for (const assigned_to of [null, "someone-else", "agent:helper"]) {
            await expect(readProjectTrackerTasks(response({ actor: "learner", tracker, issues: [{ ...item, assigned_to }] }), "personal", "tutorials")).rejects.toThrow("authenticated actor");
        }
        for (const status of ["closed", "canceled", "archived"]) {
            await expect(readProjectTrackerTasks(response({ actor: "learner", tracker, issues: [{ ...item, assigned_to: "learner", status }] }), "personal", "tutorials")).rejects.toThrow("active status");
        }
        for (const status of ["open", "in_progress"]) {
            expect((await readProjectTrackerTasks(response({ actor: "learner", tracker, issues: [{ ...item, assigned_to: "learner", status }] }), "personal", "tutorials")).issues).toHaveLength(1);
        }
        await expect(readProjectTrackerTasks(response({ actor: "learner", tracker: { ...tracker, queue: "other" }, issues: [] }), "personal", "tutorials")).rejects.toThrow("requested tracker");
        await expect(readProjectTrackerTasks({ base: "", json: async () => { throw new Error("unavailable"); } }, "personal", "tutorials")).rejects.toThrow("unavailable");
    });
    it("hears a tracker change in any project, and nothing else", () => {
        let accept: (data: string) => void = () => {};
        const heard: string[] = [];
        const transport: WorkbenchTransport = { base: "", json: async () => null, events: (_path, receive) => { accept = receive; return () => {}; } };
        subscribeAnyProjectTrackerChanges(transport, project => heard.push(project));
        for (const frame of ["malformed", JSON.stringify({ type: "workspacechanged", record: "chat", id: "personal" }), JSON.stringify({ type: "workspacechanged", record: "project_tracker" })]) accept(frame);
        accept(JSON.stringify({ type: "workspacechanged", record: "project_tracker", id: "personal" }));
        accept(JSON.stringify({ type: "workspacechanged", record: "project_tracker", id: "work" }));
        expect(heard).toEqual(["personal", "work"]);
    });
    it("refreshes only for native tracker references in the requested project", () => {
        let accept: (data: string) => void = () => {};
        let changed = 0;
        let closed = false;
        const transport: WorkbenchTransport = { base: "", json: async () => null, events: (path, receive) => {
            expect(path).toBe("/workspace/events");
            accept = receive;
            return () => { closed = true; };
        } };
        const stop = subscribeProjectTrackerChanges(transport, "personal", () => changed++);
        for (const frame of ["malformed", "null", JSON.stringify({ type: "workspacechanged", record: "project_tracker", id: "other" }), JSON.stringify({ type: "workspacechanged", record: "chat", id: "personal" })]) accept(frame);
        expect(changed).toBe(0);
        accept(JSON.stringify({ type: "workspacechanged", record: "project_tracker", id: "personal" }));
        expect(changed).toBe(1);
        stop();
        expect(closed).toBe(true);
    });
    it("reads discovered trackers and ordinary backlog through their owning project routes", async () => {
        const requests: unknown[] = [];
        const transport: WorkbenchTransport = { base: "", json: async (method, path) => {
            requests.push([method, path]);
            return path.endsWith("/trackers") ? { trackers: [tracker] } : { tracker, issues: [item] };
        } };
        expect(await listProjectTrackers(transport, "personal")).toEqual([{ projectId: "personal", workspaceId: "workspace-personal", queue: "tutorials", resourceId: "native-tracker", canComplete: true }]);
        const backlog = await readProjectTrackerBacklog(transport, "personal", "tutorials");
        expect(backlog.issues[0].assignedTo).toBeNull();
        expect(backlog.issues[0].subjectId).toBe("permanent-subject");
        expect(requests).toEqual([["GET", "/projects/personal/trackers"], ["GET", "/projects/personal/trackers/tutorials/issues"]]);
    });
    it("retains the same explicit completion intent and request key across retries", async () => {
        const requests: unknown[] = [];
        const transport: WorkbenchTransport = { base: "", json: async (...args) => { requests.push(args); return completion; } };
        const intent: TrackerCompletionIntent = { subjectId: "permanent-subject", summary: "I did it", claim: { kind: "holder", holder: "claimed-worker" }, requestId: "original-request" };
        const first = await completeProjectTrackerIssue(transport, "personal", "tutorials", "WS-1", intent);
        expect(first).toEqual({ instanceId: "human-root", status: "completed", executedEffect: "closing-effect", recoveredEffect: null });
        expect(await completeProjectTrackerIssue(transport, "personal", "tutorials", "WS-1", intent)).toEqual(first);
        expect(requests[0]).toEqual(["POST", "/projects/personal/trackers/tutorials/issues/WS-1/complete", { subject_id: "permanent-subject", summary: "I did it", claim: { kind: "holder", holder: "claimed-worker" } }, { idempotencyKey: "original-request" }]);
        expect(requests[1]).toEqual(requests[0]);
    });
    it("encodes generated project queue and issue identities as single path segments", async () => {
        const parts = ["a/b", "with spaces", "?query#fragment", "a%2Fb", "日本語"];
        for (const part of parts) {
            const paths: string[] = [];
            const transport: WorkbenchTransport = { base: "", json: async (_method, path) => {
                paths.push(path);
                return path.endsWith("/complete") ? completion : path.endsWith("/trackers") ? { trackers: [] } : { actor: "learner", tracker: { ...tracker, project_id: part, queue: part }, issues: [] };
            } };
            await listProjectTrackers(transport, part);
            await readProjectTrackerBacklog(transport, part, part);
            await readProjectTrackerTasks(transport, part, part);
            await completeProjectTrackerIssue(transport, part, part, part, { subjectId: "subject", summary: "done", claim: { kind: "override" }, requestId: "same" });
            const encoded = encodeURIComponent(part);
            expect(paths).toEqual([`/projects/${encoded}/trackers`, `/projects/${encoded}/trackers/${encoded}/issues`, `/projects/${encoded}/trackers/${encoded}/tasks`, `/projects/${encoded}/trackers/${encoded}/issues/${encoded}/complete`]);
        }
    });
    it("refuses missing or contradictory payloads instead of reporting an empty backlog", async () => {
        for (const raw of [null, {}, { tracker }, { tracker, issues: null }, { tracker, issues: [{ ...item, assigned_to: undefined }] }, { tracker, issues: [{ ...item, subject_id: "" }] }, { tracker, issues: [{ ...item, status: "done" }] }, { tracker, issues: [item, item] }]) {
            expect(() => parseProjectTrackerBacklog(raw)).toThrow();
        }
        const wrong: WorkbenchTransport = { base: "", json: async () => ({ tracker: { ...tracker, project_id: "other" }, issues: [] }) };
        await expect(readProjectTrackerBacklog(wrong, "personal", "tutorials")).rejects.toThrow("requested tracker");
        const unavailable: WorkbenchTransport = { base: "", json: async () => { throw new Error("Tracker is unavailable"); } };
        await expect(readProjectTrackerBacklog(unavailable, "personal", "tutorials")).rejects.toThrow("unavailable");
    });
});
