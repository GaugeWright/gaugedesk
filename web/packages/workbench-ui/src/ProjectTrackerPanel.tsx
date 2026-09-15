import { createMemo, createResource, createSignal, For, onCleanup, onMount, Show, type JSX, type Signal } from "solid-js";
import { RouteHttpError } from "@gaugewright/control-plane-client";
import type {
    ProjectId, ProjectTrackerBacklog, ReadableProjectTracker,
    TrackerCompletionIntent, TrackerCompletionResult,
} from "@gaugewright/control-plane-client";

export interface ProjectTrackerApi {
    subscribeProjectTrackerChanges(project: ProjectId, onChange: () => void): Promise<() => void>;
    listProjectTrackers(project: ProjectId): Promise<ReadableProjectTracker[]>;
    readProjectTrackerBacklog(project: ProjectId, queue: string): Promise<ProjectTrackerBacklog>;
    completeProjectTrackerIssue(project: ProjectId, queue: string, item: string, intent: TrackerCompletionIntent): Promise<TrackerCompletionResult>;
}

type Loaded = { trackers: ReadableProjectTracker[]; backlog: ProjectTrackerBacklog | null };
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
                return { value: { trackers, backlog } };
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
                                    <dt>Assigned to</dt><dd>{issue().assignedTo ?? "Unassigned"}</dd>
                                    <dt>Claimed by</dt><dd>{issue().claimedBy ?? "No current claim"}</dd>
                                </dl>
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
