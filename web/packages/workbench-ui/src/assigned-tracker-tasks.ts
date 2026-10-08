/**
 * The personal queue's tracker half (`experience/onboarding.md`, WHIP-4): the
 * issues assigned to the signed-in person across every readable native tracker
 * in every project they can see. Each tracker is read through its Home's own
 * assigned-task projection, which derives the actor from the request; nothing
 * here names an assignee.
 *
 * An unavailable read is reported as unavailable, never folded into an empty
 * queue — the one thing a personal queue must not do is say "nothing to do"
 * when it could not look.
 */
import type {
    ProjectId,
    ProjectTrackerTasks,
    ReadableProjectTracker,
} from "@gaugewright/control-plane-client";

export interface AssignedTrackerTaskApi {
    listProjectTrackers(project: ProjectId): Promise<ReadableProjectTracker[]>;
    readProjectTrackerTasks(project: ProjectId, queue: string): Promise<ProjectTrackerTasks>;
}

/** One assigned issue, with everything needed to open it in its own project. */
export interface AssignedTrackerTask {
    project: ProjectId;
    projectName: string;
    queue: string;
    itemId: string;
    subjectId: string;
    title: string;
    status: "open" | "in_progress";
    claimedBy: string | null;
}

/** A project, or one of its trackers, whose assignments could not be read. */
export interface UnavailableTrackerRead {
    project: ProjectId;
    projectName: string;
    queue: string | null;
}

export interface AssignedTrackerTasks {
    tasks: AssignedTrackerTask[];
    unavailable: UnavailableTrackerRead[];
}

/** How many tracker reads one pass keeps outstanding. A Home answers a
 * tracker read under its workbench lock, close to a second each on the
 * production canary Home, so a pass that asked about every project at once
 * held every other request behind all of them: a new chat's event stream
 * waited tens of seconds (WS-891). One at a time costs nothing there, since
 * the Home answers them one at a time anyway, and lets a person's own
 * request in between each. */
export const TRACKER_READS_AT_ONCE = 1;

function limited(limit: number): <T>(read: () => Promise<T>) => Promise<T> {
    let active = 0;
    const waiting: (() => void)[] = [];
    return async (read) => {
        if (active >= limit) await new Promise<void>((resolve) => waiting.push(resolve));
        active += 1;
        try {
            return await read();
        } finally {
            active -= 1;
            waiting.shift()?.();
        }
    };
}

export async function readAssignedTrackerTasks(
    api: AssignedTrackerTaskApi,
    projects: readonly { id: ProjectId; name: string }[],
): Promise<AssignedTrackerTasks> {
    const tasks: AssignedTrackerTask[] = [];
    const unavailable: UnavailableTrackerRead[] = [];
    const read = limited(TRACKER_READS_AT_ONCE);
    await Promise.all(projects.map(async (project) => {
        let trackers: ReadableProjectTracker[];
        try {
            trackers = await read(() => api.listProjectTrackers(project.id));
        } catch {
            unavailable.push({ project: project.id, projectName: project.name, queue: null });
            return;
        }
        await Promise.all(trackers.map(async (tracker) => {
            try {
                const assigned = await read(() => api.readProjectTrackerTasks(project.id, tracker.queue));
                for (const issue of assigned.issues) {
                    tasks.push({
                        project: project.id,
                        projectName: project.name,
                        queue: tracker.queue,
                        itemId: issue.id,
                        subjectId: issue.subjectId,
                        title: issue.title,
                        // The client already refuses any other status here.
                        status: issue.status as AssignedTrackerTask["status"],
                        claimedBy: issue.claimedBy,
                    });
                }
            } catch {
                unavailable.push({ project: project.id, projectName: project.name, queue: tracker.queue });
            }
        }));
    }));
    // Stable order independent of which read answered first: by project as
    // listed, then tracker, then the tracker's own issue order (WS-1, WS-2 …).
    const projectOrder = new Map(projects.map((project, index) => [project.id, index]));
    const key = (task: AssignedTrackerTask) => projectOrder.get(task.project) ?? 0;
    tasks.sort((a, b) => key(a) - key(b)
        || a.queue.localeCompare(b.queue)
        || issueNumber(a.itemId) - issueNumber(b.itemId)
        || a.itemId.localeCompare(b.itemId));
    unavailable.sort((a, b) => (projectOrder.get(a.project) ?? 0) - (projectOrder.get(b.project) ?? 0)
        || (a.queue ?? "").localeCompare(b.queue ?? ""));
    return { tasks, unavailable };
}

function issueNumber(id: string): number {
    const match = /(\d+)$/.exec(id);
    return match ? Number(match[1]) : 0;
}
