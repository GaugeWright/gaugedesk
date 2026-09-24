import { describe, expect, it } from "vitest";
import { readAssignedTrackerTasks, type AssignedTrackerTaskApi } from "./assigned-tracker-tasks";
import type { ProjectId } from "@gaugewright/control-plane-client";

const personal = { id: "personal" as ProjectId, name: "Personal" };
const work = { id: "work" as ProjectId, name: "Work" };
const tracker = (project: string, queue: string) => ({ projectId: project, workspaceId: `ws-${project}`, queue, resourceId: `r-${queue}`, canComplete: true });
const issue = (id: string, title: string) => ({ id, subjectId: `subject-${id}`, title, body: "", status: "open" as const, assignedTo: "learner", claimedBy: null, claimExpiresAt: null, closedBy: null, closingSummary: null, filedBy: "learner", labels: [], createdAt: "t", updatedAt: "t" });

describe("assigned tracker tasks", () => {
    it("gathers each readable tracker's assignments with the context that opens them", async () => {
        const api: AssignedTrackerTaskApi = {
            listProjectTrackers: async (project) => project === "personal" ? [tracker("personal", "tutorials")] : [tracker("work", "backlog")],
            readProjectTrackerTasks: async (project, queue) => ({
                actor: "learner",
                tracker: tracker(project, queue),
                issues: project === "personal" ? [issue("WS-2", "Make your assistant"), issue("WS-1", "Create a chat")] : [issue("WS-9", "Review the draft")],
            }),
        };
        const { tasks, unavailable } = await readAssignedTrackerTasks(api, [personal, work]);
        expect(unavailable).toEqual([]);
        expect(tasks.map(t => [t.project, t.queue, t.itemId, t.title])).toEqual([
            ["personal", "tutorials", "WS-1", "Create a chat"],
            ["personal", "tutorials", "WS-2", "Make your assistant"],
            ["work", "backlog", "WS-9", "Review the draft"],
        ]);
        expect(tasks[0]).toMatchObject({ projectName: "Personal", subjectId: "subject-WS-1", status: "open" });
    });
    it("reports a read it could not make instead of an empty queue", async () => {
        const api: AssignedTrackerTaskApi = {
            listProjectTrackers: async (project) => {
                if (project === "work") throw new Error("Home unreachable");
                return [tracker("personal", "tutorials"), tracker("personal", "notes")];
            },
            readProjectTrackerTasks: async (project, queue) => {
                if (queue === "notes") throw new Error("store unavailable");
                return { actor: "learner", tracker: tracker(project, queue), issues: [] };
            },
        };
        const { tasks, unavailable } = await readAssignedTrackerTasks(api, [personal, work]);
        expect(tasks).toEqual([]);
        expect(unavailable).toEqual([
            { project: "personal", projectName: "Personal", queue: "notes" },
            { project: "work", projectName: "Work", queue: null },
        ]);
    });
    it("asks nothing when there are no projects", async () => {
        const api: AssignedTrackerTaskApi = {
            listProjectTrackers: async () => { throw new Error("not called"); },
            readProjectTrackerTasks: async () => { throw new Error("not called"); },
        };
        expect(await readAssignedTrackerTasks(api, [])).toEqual({ tasks: [], unavailable: [] });
    });
});
