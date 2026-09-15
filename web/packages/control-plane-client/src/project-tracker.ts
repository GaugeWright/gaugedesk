import type { WorkbenchTransport } from "./control-plane-workbench";

export interface ReadableProjectTracker {
    projectId: string;
    workspaceId: string;
    queue: string;
    resourceId: string;
    canComplete: boolean;
}
export interface ProjectTrackerIssue {
    id: string;
    subjectId: string;
    title: string;
    body: string;
    status: "open" | "in_progress" | "closed" | "canceled" | "archived";
    assignedTo: string | null;
    claimedBy: string | null;
    filedBy: string | null;
    labels: string[];
    createdAt: string;
    updatedAt: string;
}
export interface ProjectTrackerBacklog {
    tracker: ReadableProjectTracker;
    issues: ProjectTrackerIssue[];
}
export interface ProjectTrackerTasks extends ProjectTrackerBacklog {
    /** Authenticated actor projected by the serving Home. */
    actor: string;
}
export interface TrackerCompletionIntent {
    subjectId: string;
    summary: string;
    claim: { kind: "holder"; holder: string } | { kind: "override" };
    /** Created once for this exact intent and retained across delivery retries. */
    requestId: string;
}
export interface TrackerCompletionResult {
    instanceId: string;
    status: "running" | "paused" | "completed" | "failed" | "cancelled";
    executedEffect: string | null;
    recoveredEffect: string | null;
}

/** Tracker hints contain only owning project coordinates; refresh performs the admitted read. */
export function subscribeProjectTrackerChanges(transport: WorkbenchTransport, project: string, onChange: () => void): () => void {
    const accept = (data: string) => {
        try {
            const event = JSON.parse(data);
            if (event?.type === "workspacechanged" && event.record === "project_tracker" && event.id === project) onChange();
        } catch { /* malformed event frames cannot change a view */ }
    };
    if (transport.events) return transport.events("/workspace/events", accept);
    const stream = new EventSource(`${transport.base}/workspace/events`, { withCredentials: true });
    stream.onmessage = event => accept(event.data);
    return () => stream.close();
}
function record(value: unknown): Record<string, unknown> {
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Invalid tracker response");
    return value as Record<string, unknown>;
}
function text(value: unknown): string {
    if (typeof value !== "string") throw new Error("Invalid tracker text");
    return value;
}
function identity(value: unknown): string {
    const result = text(value);
    if (!result.trim()) throw new Error("Missing tracker identity");
    return result;
}
function nullable(value: unknown): string | null {
    return value === null ? null : identity(value);
}
function parseTracker(value: unknown): ReadableProjectTracker {
    const raw = record(value);
    if (typeof raw.can_complete !== "boolean") throw new Error("Missing tracker permission projection");
    return { projectId: identity(raw.project_id), workspaceId: identity(raw.workspace_id), queue: identity(raw.queue), resourceId: identity(raw.resource_id), canComplete: raw.can_complete };
}
export function parseProjectTrackerBacklog(value: unknown): ProjectTrackerBacklog {
    const raw = record(value);
    if (!Array.isArray(raw.issues)) throw new Error("Missing tracker issues");
    const issues = raw.issues.map((value): ProjectTrackerIssue => {
        const item = record(value);
        const status = text(item.status);
        if (!["open", "in_progress", "closed", "canceled", "archived"].includes(status)) throw new Error("Unknown tracker status");
        if (!Array.isArray(item.labels) || item.labels.some(label => typeof label !== "string")) throw new Error("Invalid tracker labels");
        return {
            id: identity(item.id), subjectId: identity(item.subject_id), title: text(item.title), body: text(item.body), status: status as ProjectTrackerIssue["status"],
            assignedTo: nullable(item.assigned_to), claimedBy: nullable(item.claimed_by), filedBy: nullable(item.filed_by), labels: item.labels as string[], createdAt: text(item.created_at), updatedAt: text(item.updated_at),
        };
    });
    if (new Set(issues.map(issue => issue.id)).size !== issues.length || new Set(issues.map(issue => issue.subjectId)).size !== issues.length) throw new Error("Conflicting tracker issue identities");
    return { tracker: parseTracker(raw.tracker), issues };
}
export async function listProjectTrackers(transport: WorkbenchTransport, project: string): Promise<ReadableProjectTracker[]> {
    const raw = record(await transport.json("GET", `/projects/${encodeURIComponent(project)}/trackers`));
    if (!Array.isArray(raw.trackers)) throw new Error("Missing tracker discovery");
    const trackers = raw.trackers.map(parseTracker);
    if (trackers.some(tracker => tracker.projectId !== project) || new Set(trackers.map(tracker => tracker.queue)).size !== trackers.length) throw new Error("Tracker discovery differs from its project");
    return trackers;
}
export async function readProjectTrackerBacklog(transport: WorkbenchTransport, project: string, queue: string): Promise<ProjectTrackerBacklog> {
    const result = parseProjectTrackerBacklog(await transport.json("GET", `/projects/${encodeURIComponent(project)}/trackers/${encodeURIComponent(queue)}/issues`));
    if (result.tracker.projectId !== project || result.tracker.queue !== queue) throw new Error("Backlog differs from its requested tracker");
    return result;
}
export async function readProjectTrackerTasks(transport: WorkbenchTransport, project: string, queue: string): Promise<ProjectTrackerTasks> {
    const raw = record(await transport.json("GET", `/projects/${encodeURIComponent(project)}/trackers/${encodeURIComponent(queue)}/tasks`));
    const actor = identity(raw.actor);
    const result = parseProjectTrackerBacklog(raw);
    if (result.tracker.projectId !== project || result.tracker.queue !== queue) throw new Error("Tasks differ from their requested tracker");
    if (result.issues.some(issue => issue.assignedTo !== actor || !["open", "in_progress"].includes(issue.status))) throw new Error("Tasks contradict their authenticated actor or active status");
    return { ...result, actor };
}
export async function completeProjectTrackerIssue(transport: WorkbenchTransport, project: string, queue: string, itemId: string, intent: TrackerCompletionIntent): Promise<TrackerCompletionResult> {
    identity(intent.requestId);
    const raw = record(await transport.json("POST", `/projects/${encodeURIComponent(project)}/trackers/${encodeURIComponent(queue)}/issues/${encodeURIComponent(itemId)}/complete`, {
        subject_id: intent.subjectId, summary: intent.summary, claim: intent.claim,
    }, { idempotencyKey: intent.requestId }));
    const snapshot = record(raw.snapshot);
    const admission = record(snapshot.admission);
    const status = text(snapshot.instance_status);
    if (!["running", "paused", "completed", "failed", "cancelled"].includes(status)) throw new Error("Unknown completion status");
    return { instanceId: identity(admission.instance_ref), status: status as TrackerCompletionResult["status"], executedEffect: nullable(raw.executed_effect), recoveredEffect: nullable(raw.recovered_effect) };
}
