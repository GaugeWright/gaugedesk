import { createMemo, createResource, createSignal, For, onCleanup, onMount, Show, type JSX, type Signal } from "solid-js";
import { Rejected, RouteHttpError } from "@gaugewright/control-plane-client";
import type {
    ProjectId, ProjectTrackerBacklog, ProjectTrackerIssue, ProjectTrackerTasks, ReadableProjectTracker, RosterPerson,
    TrackerCompletionIntent, TrackerCompletionResult, TrackerControlIntent, TrackerIssueControl,
} from "@gaugewright/control-plane-client";

export interface ProjectTrackerApi {
    subscribeProjectTrackerChanges(project: ProjectId, onChange: () => void): Promise<() => void>;
    listProjectTrackers(project: ProjectId): Promise<ReadableProjectTracker[]>;
    readProjectTrackerBacklog(project: ProjectId, queue: string): Promise<ProjectTrackerBacklog>;
    completeProjectTrackerIssue(project: ProjectId, queue: string, item: string, intent: TrackerCompletionIntent): Promise<TrackerCompletionResult>;
    /** Claim, renew, release or reassign (WHIP-4). Absent: the view is read-only. */
    controlProjectTrackerIssue?(project: ProjectId, queue: string, item: string, intent: TrackerControlIntent): Promise<TrackerCompletionResult>;
    /** Who the Home says is asking, from the person's own task read. */
    readProjectTrackerTasks?(project: ProjectId, queue: string): Promise<ProjectTrackerTasks>;
    /** Who a task can be directed at. */
    getRoster?(): Promise<RosterPerson[]>;
}

/** How long taking or keeping a task holds it before it frees itself. */
const LEASE_SECONDS = 4 * 60 * 60;

/** A lease as the Home reports it (UTC), in the reader's own time. */
function leaseLabel(expiresAt: string | null): string {
    if (!expiresAt) return "";
    const date = new Date(`${expiresAt.replace(" ", "T")}Z`);
    return Number.isNaN(date.getTime()) ? expiresAt : date.toLocaleString([], { weekday: "short", hour: "numeric", minute: "2-digit" });
}

type Loaded = { trackers: ReadableProjectTracker[]; backlog: ProjectTrackerBacklog | null; me: string | null };
type ReadResult = { value: Loaded } | { error: string };
export type PendingTrackerCompletion = { project: ProjectId; queue: string; item: string; intent: TrackerCompletionIntent; message: string; busy: boolean };

/** The same ordinary backlog is opened from a project or an assigned task. */
export function ProjectTrackerPanel(props: {
    api: ProjectTrackerApi;
    project: ProjectId;
    projectName: string;
    initialQueue?: string;
    initialSubject?: string;
    refreshKey?: unknown;
    /** Session-owned intent survives closing the view, but never changes actor. */
    completions: Signal<PendingTrackerCompletion[]>;
    onClose: () => void;
}): JSX.Element {
    const [queue, setQueue] = createSignal(props.initialQueue ?? "");
    const [subject, setSubject] = createSignal(props.initialSubject ?? "");
    const [all, setAll] = createSignal(false);
    const [tick, setTick] = createSignal(0);
    const [summary, setSummary] = createSignal("");
    const [override, setOverride] = createSignal(false);
    const [message, setMessage] = createSignal("");
    const [liveError, setLiveError] = createSignal(false);
    let dialog: HTMLElement | undefined;
    // Key by permanent subject, not a row object replaced during refresh. The
    // retained command survives selecting another issue and re-reading the list.
    const [pending, setPending] = props.completions;
    const refresh = () => setTick(value => value + 1);
    onMount(() => {
        dialog?.focus();
        let disposed = false;
        let stop: (() => void) | undefined;
        void props.api.subscribeProjectTrackerChanges(props.project, refresh).then(unsubscribe => {
            if (disposed) unsubscribe();
            else stop = unsubscribe;
        }).catch(() => { if (!disposed) setLiveError(true); });
        onCleanup(() => { disposed = true; stop?.(); });
    });
    const [read] = createResource(
        () => [props.project, queue(), tick(), props.refreshKey] as const,
        async ([project, requested]): Promise<ReadResult> => {
            try {
                const trackers = await props.api.listProjectTrackers(project);
                const selected = requested || trackers[0]?.queue;
                if (selected && !trackers.some(tracker => tracker.queue === selected)) {
                    return { error: "This tracker is no longer readable. Choose another tracker from the project menu." };
                }
                const backlog = selected ? await props.api.readProjectTrackerBacklog(project, selected) : null;
                const me = selected && props.api.readProjectTrackerTasks
                    ? await props.api.readProjectTrackerTasks(project, selected).then(tasks => tasks.actor, () => null)
                    : null;
                return { value: { trackers, backlog, me } };
            } catch (reason) {
                if (reason instanceof RouteHttpError) {
                    if (reason.status === 401) return { error: "Sign in to read project tasks." };
                    if (reason.status === 403) return { error: "You don’t currently have access to this tracker." };
                    if (reason.status === 503) return { error: "This tracker is unavailable. Refresh to try again." };
                }
                return { error: "Couldn’t load project tasks. Check your connection and access, then refresh." };
            }
        },
    );
    // Never present the last successful payload as current during an authority
    // refresh or after an error. A successful empty read has its own presentation.
    const loaded = createMemo(() => {
        const result = read();
        return !read.loading && result && "value" in result ? result.value : undefined;
    });
    const error = () => {
        const result = read();
        return !read.loading && result && "error" in result ? result.error : "";
    };
    const backlog = () => loaded()?.backlog;
    const selected = () => backlog()?.issues.find(issue => issue.subjectId === subject());
    const currentPending = () => pending().find(item => item.project === props.project && item.queue === backlog()?.tracker.queue && item.intent.subjectId === subject());
    const active = (status: string) => status === "open" || status === "in_progress";
    const visible = () => backlog()?.issues.filter(issue => all() || active(issue.status)) ?? [];
    const select = (id: string) => {
        setSubject(id);
        setSummary("");
        setOverride(false);
        setMessage("");
    };
    const me = () => loaded()?.me ?? null;
    const [roster] = createResource(() => (props.api.getRoster ? props.api.getRoster().catch(() => []) : Promise.resolve([] as RosterPerson[])));
    const personName = (authority: string | null) =>
        !authority ? "" : authority === me() ? "you" : roster()?.find(person => person.authority === authority)?.display ?? authority;
    const [acting, setActing] = createSignal(false);
    // One key per intended change, kept across a retry of that same change.
    let controlKey: { control: string; requestId: string } | null = null;
    async function act(issue: ProjectTrackerIssue, control: TrackerIssueControl, done: string) {
        const tracker = backlog()?.tracker;
        if (!tracker || !props.api.controlProjectTrackerIssue || acting()) return;
        const intent = JSON.stringify([issue.subjectId, control]);
        if (controlKey?.control !== intent) controlKey = { control: intent, requestId: crypto.randomUUID() };
        setActing(true);
        setMessage("");
        try {
            await props.api.controlProjectTrackerIssue(props.project, tracker.queue, issue.id, {
                subjectId: issue.subjectId, control, requestId: controlKey.requestId,
            });
            controlKey = null;
            setMessage(done);
            refresh();
        } catch (reason) {
            if (reason instanceof Rejected || (reason instanceof RouteHttpError && reason.status === 409)) {
                controlKey = null;
                setMessage("The task changed since you read it. It has been refreshed; try again if you still want to.");
                refresh();
            } else {
                setMessage("Couldn’t confirm the change. Trying again repeats the same request.");
            }
        } finally {
            setActing(false);
        }
    }
    const replacePending = (command: PendingTrackerCompletion) => setPending(items => [
        ...items.filter(item => item.intent.requestId !== command.intent.requestId), command,
    ]);

    async function deliver(command: PendingTrackerCompletion) {
        if (command.busy) return;
        replacePending({ ...command, busy: true, message: "Confirming completion…" });
        try {
            const result = await props.api.completeProjectTrackerIssue(command.project, command.queue, command.item, command.intent);
            if (result.status === "completed" || result.status === "failed" || result.status === "cancelled") {
                setPending(items => items.filter(item => item.intent.requestId !== command.intent.requestId));
                if (subject() === command.intent.subjectId && backlog()?.tracker.queue === command.queue) {
                    setMessage(result.status === "completed" ? "Your completion was recorded." : "Completion did not succeed. Refresh the task before trying again.");
                }
                refresh();
            } else {
                replacePending({ ...command, busy: false, message: "Completion is still pending. Check again to confirm the same request." });
            }
        } catch {
            replacePending({ ...command, busy: false, message: "Couldn’t confirm completion. Retry will confirm the same request." });
        }
    }

    function complete(event: SubmitEvent) {
        event.preventDefault();
        const issue = selected();
        const tracker = backlog()?.tracker;
        if (!issue || !tracker?.canComplete || !active(issue.status) || currentPending() || !summary().trim()) return;
        if (!issue.claimedBy && !override()) return;
        setMessage("");
        void deliver({
            project: props.project, queue: tracker.queue, item: issue.id, busy: false, message: "",
            intent: {
                requestId: crypto.randomUUID(), subjectId: issue.subjectId, summary: summary().trim(),
                claim: override() ? { kind: "override" } : { kind: "holder", holder: issue.claimedBy! },
            },
        });
    }

    return <div class="modal-overlay" onClick={event => { if (event.target === event.currentTarget) props.onClose(); }}>
        <section class="modal project-tasks" ref={dialog} tabindex="-1" role="dialog" aria-modal="true" aria-label={`${props.projectName} tasks`}
            data-project-tasks={props.project} onKeyDown={event => { if (event.key === "Escape") props.onClose(); }}>
            <header class="modal-head">
                <h3>{props.projectName} · Tasks</h3>
                <button type="button" aria-label="Close tasks" onClick={props.onClose}>×</button>
            </header>
            <div class="project-tasks-controls">
                <Show when={loaded()?.trackers.length}>
                    <label>Tracker <select aria-label="Tracker" value={backlog()?.tracker.queue ?? ""} onChange={event => {
                        setQueue(event.currentTarget.value); select("");
                    }}><For each={loaded()?.trackers}>{tracker => <option value={tracker.queue}>{tracker.queue}</option>}</For></select></label>
                    <label><input type="checkbox" checked={all()} onChange={event => setAll(event.currentTarget.checked)} /> Show all tasks</label>
                </Show>
                <button type="button" disabled={read.loading} onClick={refresh}>Refresh tasks</button>
            </div>
            <Show when={read.loading}><p class="project-tasks-notice" role="status">Loading tasks…</p></Show>
            <Show when={liveError()}><p class="project-tasks-notice" role="status">Live updates are unavailable. Refresh to check for changes.</p></Show>
            <Show when={error()}><p class="project-tasks-notice" role="alert">{error()}</p></Show>
            <Show when={loaded() && !backlog()}><p class="project-tasks-notice">No readable trackers in this project.</p></Show>
            <Show when={message()}><p class="project-tasks-notice" role="status">{message()}</p></Show>
            <Show when={backlog()}>
                <div class="project-tasks-body">
                    <nav class="project-tasks-list" aria-label="Project tasks">
                        <For each={visible()} fallback={<p class="project-tasks-notice">{all() ? "No tasks in this tracker." : "No active tasks in this tracker."}</p>}>
                            {issue => <button type="button" class="project-task-row" classList={{ selected: subject() === issue.subjectId }}
                                aria-current={subject() === issue.subjectId ? "true" : undefined} onClick={() => select(issue.subjectId)}>
                                <strong>{issue.title || issue.id}</strong>
                                <span>{issue.assignedTo ? `Assigned to ${issue.assignedTo}` : "Unassigned"}</span>
                                <span>{issue.status.replaceAll("_", " ")}</span>
                            </button>}
                        </For>
                    </nav>
                    <article class="project-task-detail">
                        <Show when={selected()} fallback={<p class="muted">Select a task to read its instructions.</p>}>
                            {issue => <>
                                <h4>{issue().title || issue().id}</h4>
                                <dl class="project-task-facts">
                                    <dt>Status</dt><dd>{issue().status.replaceAll("_", " ")}</dd>
                                    <dt>Assigned to</dt><dd>
                                        <Show when={props.api.controlProjectTrackerIssue && backlog()?.tracker.canComplete && active(issue().status)}
                                            fallback={personName(issue().assignedTo) || "Unassigned"}>
                                            <select aria-label="Assigned to" data-task-assignee value={issue().assignedTo ?? ""} disabled={acting()}
                                                onChange={event => {
                                                    const to = event.currentTarget.value || null;
                                                    void act(issue(), { kind: "assign", expectedAssignee: issue().assignedTo, assignedTo: to },
                                                        to ? `Assigned to ${personName(to)}.` : "Unassigned.");
                                                }}>
                                                <option value="">Unassigned</option>
                                                <Show when={issue().assignedTo && !roster()?.some(person => person.authority === issue().assignedTo)}>
                                                    <option value={issue().assignedTo!}>{personName(issue().assignedTo)}</option>
                                                </Show>
                                                <For each={roster() ?? []}>{person => <option value={person.authority}>
                                                    {person.authority === me() ? `You (${person.display})` : person.display}
                                                </option>}</For>
                                            </select>
                                        </Show>
                                    </dd>
                                    <dt>Claimed by</dt><dd data-task-claim>
                                        {issue().claimedBy
                                            ? `${personName(issue().claimedBy)}${issue().claimExpiresAt ? ` until ${leaseLabel(issue().claimExpiresAt)}` : ""}`
                                            : "No current claim"}
                                    </dd>
                                    <Show when={issue().closedBy}>
                                        <dt>Closed by</dt><dd data-task-closed-by>{personName(issue().closedBy)}</dd>
                                    </Show>
                                </dl>
                                <Show when={issue().closingSummary}>
                                    <p class="project-task-instructions" data-task-closing-summary>{issue().closingSummary}</p>
                                </Show>
                                <Show when={props.api.controlProjectTrackerIssue && backlog()?.tracker.canComplete && active(issue().status)}>
                                    <div class="project-task-claim" data-task-claim-controls>
                                        <Show when={!issue().claimedBy}>
                                            <button type="button" disabled={acting()} onClick={() => void act(issue(), { kind: "claim", leaseSeconds: LEASE_SECONDS }, "You’ve taken this task.")}>Take this task</button>
                                        </Show>
                                        <Show when={issue().claimedBy && issue().claimedBy === me()}>
                                            <button type="button" disabled={acting()} onClick={() => void act(issue(), { kind: "renew", leaseSeconds: LEASE_SECONDS }, "You’ll keep it a while longer.")}>Keep it longer</button>
                                            <button type="button" disabled={acting()} onClick={() => void act(issue(), { kind: "release", expectedHolder: me() }, "You’ve let it go.")}>Let it go</button>
                                        </Show>
                                        <Show when={issue().claimedBy && issue().claimedBy !== me()}>
                                            <p class="muted">It frees itself when {personName(issue().claimedBy)}’s claim runs out.</p>
                                        </Show>
                                    </div>
                                </Show>
                                <p class="project-task-instructions">{issue().body || "No additional instructions."}</p>
                                <Show when={currentPending()} fallback={
                                    <Show when={backlog()?.tracker.canComplete && active(issue().status)}>
                                        <form class="project-task-completion" onSubmit={complete}>
                                            <label>Completion note<textarea required value={summary()} onInput={event => setSummary(event.currentTarget.value)} /></label>
                                            <p class="muted">Completing this task records your report of what you did.</p>
                                            <label><input type="checkbox" checked={override()} onChange={event => setOverride(event.currentTarget.checked)} /> Complete regardless of the current claim</label>
                                            <p class="muted">{issue().claimedBy ? `Otherwise, completion requires the claim to remain with ${issue().claimedBy}.` : "No one currently holds this task’s claim. Confirm above to complete it without holding a claim."}</p>
                                            <button type="submit" disabled={!summary().trim() || (!issue().claimedBy && !override())}>Mark complete</button>
                                        </form>
                                    </Show>
                                }>{command => <div class="project-task-completion">
                                    <p class="project-task-instructions">{command().intent.summary}</p>
                                    <p role="status">{command().message}</p>
                                    <button type="button" disabled={command().busy || !backlog()?.tracker.canComplete} onClick={() => void deliver(command())}>Retry completion</button>
                                </div>}</Show>
                                <Show when={!backlog()?.tracker.canComplete && active(issue().status)}><p class="muted">Completion isn’t available with your current access.</p></Show>
                            </>}
                        </Show>
                    </article>
                </div>
            </Show>
        </section>
    </div>;
}
