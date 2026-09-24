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

export async function readAssignedTrackerTasks(
    api: AssignedTrackerTaskApi,
    projects: readonly { id: ProjectId; name: string }[],
): Promise<AssignedTrackerTasks> {
    const tasks: AssignedTrackerTask[] = [];
    const unavailable: UnavailableTrackerRead[] = [];
    await Promise.all(projects.map(async (project) => {
        let trackers: ReadableProjectTracker[];
        try {
            trackers = await api.listProjectTrackers(project.id);
        } catch {
            unavailable.push({ project: project.id, projectName: project.name, queue: null });
            return;
        }
        await Promise.all(trackers.map(async (tracker) => {
            try {
                const read = await api.readProjectTrackerTasks(project.id, tracker.queue);
                for (const issue of read.issues) {
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
