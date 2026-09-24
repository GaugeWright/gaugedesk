/**
 * The human task queue (`navigation.md` B1, `15-task-queue`): the top bar surfaces
 * ask-typed work, current-first (ADR 0082 §2). Each pill's kind is the **verb**
 * the human is asked to perform — `answer` the agent's pending question, `repair`
 * a merge conflict, `reply` to a turn that settled — plus the onboarding `issue`
 * checklist (ADR 0075) and the `screen` inbound queue. Click a pill to open that
 * chat.
 *
 * **No pill carries a one-click action.** Every ask is discharged inside the chat
 * it names. The `review` ask used to be the exception, with a ✓ that kept the
 * change from the chrome; ADR 0136 retired that ask along with the per-change
 * hold, and nothing replaced the shortcut — acting on work from the bar without
 * looking at it was never the part worth keeping.
 *
 * Beside those, the issues native trackers assign to the signed-in person
 * (`experience/onboarding.md`, WHIP-4): each opens the ordinary task backlog in
 * its own project. A tracker the bar could not read says so rather than
 * reading as nothing to do.
 *
 * A thin renderer (`INV-5`): it shows projections (`GET /tasks`, and each
 * tracker's assigned-task read); it owns no truth.
 */

import { createResource, createSignal, For, Show } from "solid-js";
import type { EngagementId, HumanTask, RosterPerson } from "@gaugewright/control-plane-client";
import type { AssignedTrackerTask, AssignedTrackerTasks } from "./assigned-tracker-tasks";
import { displayChatTitle } from "./chat-title";

/** Per-ask presentation: the pill's verb chip and its hover explanation. */
const ASK_COPY: Record<string, { verb: string; hint: (title: string) => string }> = {
    answer: {
        verb: "answer",
        hint: (t) => `The agent asked a question — open "${t}" to answer it`,
    },
    repair: {
        verb: "repair",
        hint: (t) => `The merge conflicted — open "${t}" to repair it`,
    },
    reply: {
        verb: "reply",
        hint: (t) => `The agent finished — open "${t}" to continue the conversation`,
    },
    // Inbound material a project's gate parked on a person (ADR 0110 §7). The
    // chip is a noun rather than a verb because the ask is not one action on one
    // chat — it is a queue of items, each of which the reviewer keeps or flags.
    // `onboarding` is the existing precedent for a non-verb chip.
    screen: {
        verb: "inbound",
        hint: (t) => `Inbound material is waiting for you in "${t}" — review it before an agent can read it`,
    },
};

/** A stable accent colour for a task, derived from the agent it's pinned to (#22):
 *  tasks group visually by their agent. An unpinned task (no agent) stays neutral. */
function agentColor(agent: string | undefined): string | undefined {
    if (!agent) return undefined; // not pinned to an agent → neutral (the default border)
    let hue = 0;
    for (let i = 0; i < agent.length; i++) hue = (hue * 31 + agent.charCodeAt(i)) % 360;
    return `hsl(${hue} 55% 58%)`;
}

export interface TaskQueueApi {
    getTasks(): Promise<HumanTask[]>;
    getRoster(): Promise<RosterPerson[]>;
    assignWorkItem(boundary: string, item: string, to: string | null): Promise<string | null>;
}

export function TaskBar(props: {
    api: TaskQueueApi;
    selected: EngagementId | null;
    refreshKey: unknown;
    onSelect: (id: EngagementId) => void;
    /** An inbound pill opens the project's review surface as well as its chat
     *  (ADR 0110 §7). Optional: an environment with no review surface still
     *  renders the count, and clicking it just opens the chat. */
    onReviewInbound?: (project: string, id: EngagementId) => void;
    /** The signed-in person's tracker assignments, and where each opens.
     *  Absent when there is no account session: a signed-out person has no
     *  personal queue, which is different from one that could not be read. */
    assigned?: {
        read: () => Promise<AssignedTrackerTasks>;
        onOpen: (task: AssignedTrackerTask) => void;
    };
}) {
    const [tasks, { refetch: refetchTasks }] = createResource(
        () => props.refreshKey,
        () => props.api.getTasks(),
    );
    const [roster] = createResource(
        () => props.refreshKey,
        () => props.api.getRoster(),
    );
    const [assigning, setAssigning] = createSignal<string | null>(null);
    const [assignedRead] = createResource(
        () => (props.assigned ? [props.refreshKey, props.assigned] as const : false),
        async ([, assigned]) => {
            try {
                return await assigned.read();
            } catch {
                return null;
            }
        },
    );
    const assignedTasks = () => assignedRead()?.tasks ?? [];
    const unreadable = () => {
        const read = assignedRead();
        if (read === undefined || !props.assigned) return [];
        if (read === null) return [{ projectName: "your projects", queue: null }];
        return read.unavailable;
    };
    const empty = () =>
        (tasks() ?? []).length === 0 && assignedTasks().length === 0 && unreadable().length === 0;

    return (
        <div class="taskbar" data-testid="taskbar">
            <span class="taskbar-label">tasks</span>
            <div class="task-tabs">
                <Show when={empty()}>
                    <span class="status">nothing waiting on you</span>
                </Show>
                <For each={assignedTasks()}>
                    {(task) => {
                        const open = () => props.assigned?.onOpen(task);
                        return (
                            <span
                                class="task-tab task-tracker"
                                data-task={task.itemId}
                                data-task-kind="tracker"
                                data-task-project={task.project}
                                data-task-queue={task.queue}
                                role="button"
                                tabindex="0"
                                aria-label={`open task ${task.title} in ${task.projectName}`}
                                title={`Assigned to you in ${task.projectName} — open it to do it, then mark it complete`}
                                onKeyDown={(e) => {
                                    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); }
                                }}
                                onClick={open}
                            >
                                <span class="task-kind">task</span>
                                <span class="task-title">{task.title}</span>
                                <span class="task-agent">{task.projectName}</span>
                            </span>
                        );
                    }}
                </For>
                <Show when={unreadable().length > 0}>
                    <span
                        class="task-tab task-unavailable"
                        data-task-kind="unavailable"
                        role="note"
                        title={`Could not read tasks in ${unreadable()
                            .map((u) => (u.queue ? `${u.projectName} (${u.queue})` : u.projectName))
                            .join(", ")}. Nothing here means they are empty.`}
                    >
                        <span class="task-kind">tasks</span>
                        <span class="task-title">some tasks could not be read</span>
                    </span>
                </Show>
                <For each={tasks() ?? []}>
                    {(t: HumanTask) => {
                        // Onboarding issue (ADR 0075): its id is a whip work-item
                        // id (`WS-N`), not an engagement, so it neither jumps to a
                        // chat nor offers a keep — it's a first-run checklist pill.
                        if (t.kind === "issue") {
                            const title = () => displayChatTitle(t.title);
                            const assign = async (to: string) => {
                                if (!t.boundary) return;
                                setAssigning(t.id);
                                try {
                                    await props.api.assignWorkItem(t.boundary, t.id, to || null);
                                    await refetchTasks();
                                } finally {
                                    setAssigning(null);
                                }
                            };
                            return (
                                <span
                                    class="task-tab task-issue"
                                    data-task={t.id}
                                    data-task-kind="issue"
                                    role="listitem"
                                    aria-label={`onboarding step: ${title()}`}
                                    title={title()}
                                >
                                    <span class="task-kind">onboarding</span>
                                    <span class="task-title">{title()}</span>
                                    <Show when={t.boundary}>
                                        <select
                                            class="task-assignee"
                                            data-task-assignee
                                            aria-label={`assign ${title()}`}
                                            value={t.assignee ?? ""}
                                            disabled={assigning() === t.id}
                                            onChange={(event) => void assign(event.currentTarget.value)}
                                        >
                                            <option value="">unassigned</option>
                                            <For each={roster() ?? []}>
                                                {(person) => (
                                                    <option value={person.authority}>
                                                        {person.display} ({person.role})
                                                    </option>
                                                )}
                                            </For>
                                        </select>
                                    </Show>
                                </span>
                            );
                        }
                        // Chat ask (review/answer/repair/reply/screen): id is an
                        // EngagementId (narrowed by kind). A `screen` task is
                        // project-scoped — its id names the chat the reviewer
                        // goes to look in, not what the count belongs to.
                        const engagement = t.id as EngagementId;
                        const active = () => props.selected === engagement;
                        const color = agentColor(t.agent);
                        const ask = ASK_COPY[t.kind] ?? ASK_COPY.reply;
                        // One canonical title everywhere (#4): never leak the raw
                        // "new chat" placeholder — show the same "Untitled" the tree
                        // and chat header show, so the pill is recognisably the same chat.
                        const title = () => displayChatTitle(t.title);
                        // An inbound pill is a door onto the project's queue, so it
                        // opens the chat *and* the review surface. Every other kind
                        // discharges inside the chat and only needs the chat.
                        const open = () => {
                            props.onSelect(engagement);
                            if (t.kind === "screen" && t.project) {
                                props.onReviewInbound?.(t.project, engagement);
                            }
                        };
                        return (
                            <span
                                class="task-tab"
                                classList={{ active: active(), [`task-${t.kind}`]: true }}
                                data-task={t.id}
                                data-task-kind={t.kind}
                                data-task-agent={t.agent}
                                // Keyboard/SR reachable (#4 round-5): the review pills
                                // were clickable spans with no role/tabindex, so the one
                                // always-visible queue of pending decisions was a wall for
                                // keyboard users. Make each pill a real focusable button.
                                role="button"
                                tabindex="0"
                                aria-label={
                                    t.kind === "screen"
                                        ? `open ${t.waiting ?? 0} inbound item(s) awaiting review in ${title()}`
                                        : `open ${ask.verb} for ${title()}`
                                }
                                title={ask.hint(title())}
                                style={color ? { "border-left": `3px solid ${color}` } : undefined}
                                onKeyDown={(e) => {
                                    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); }
                                }}
                                onClick={open}
                            >
                                <span class="task-kind">{ask.verb}</span>
                                <span class="task-title">{title()}</span>
                                {/* The count is the point of an inbound pill: it
                                    says how much is waiting, which no other task
                                    kind needs because they are each one item. */}
                                <Show when={t.kind === "screen"}>
                                    <span class="task-count" data-task-count>{t.waiting ?? 0}</span>
                                </Show>
                                <span class="task-agent">{t.agent}</span>
                            </span>
                        );
                    }}
                </For>
            </div>
        </div>
    );
}
