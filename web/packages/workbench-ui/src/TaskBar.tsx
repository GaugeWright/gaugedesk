/**
 * The human task queue (`navigation.md` B1, `15-task-queue`): the top bar surfaces
 * ask-typed work, current-first (ADR 0082 §2). Each pill's kind is the **verb**
 * the human is asked to perform — `answer` the agent's pending question, `repair`
 * a merge conflict, `reply` to a turn that settled — plus the onboarding `issue`
 * checklist (ADR 0075) and the `screen` inbound queue. Click a pill to open that
 * chat — or, for `screen`, the Inbox that holds what is waiting, since that task
 * belongs to a project and names no chat (DR-0143 §6).
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

import { createResource, For, Show } from "solid-js";
import { isProjectTask, type EngagementId, type HumanTask } from "@gaugewright/control-plane-client";
import type { AssignedTrackerTask, AssignedTrackerTasks } from "./assigned-tracker-tasks";
import { displayChatTitle } from "./chat-title";

/** A read that keeps at most one request in flight and one waiting. A call
 * while one runs is answered by a single read begun after it finishes, shared
 * by every call made meanwhile, so the answer is never older than the call. */
export function coalescedRead<T>(read: () => Promise<T>): () => Promise<T> {
    let running: Promise<T> | null = null;
    let waiting: Promise<T> | null = null;
    const start = (): Promise<T> => {
        const current = read();
        running = current;
        const settle = () => { if (running === current) running = null; };
        current.then(settle, settle);
        return current;
    };
    return () => {
        if (!running) return start();
        waiting ??= running.then(() => undefined, () => undefined).then(() => {
            waiting = null;
            return start();
        });
        return waiting;
    };
}

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
        hint: (t) => `Inbound material is waiting for you in ${t}'s Inbox — review it before an agent can read it`,
    },
    // Background work paused because nobody used its project for 30 days
    // (DR-0312). Like `inbound` it belongs to a project, and opening that
    // project is the whole remedy: a member's use renews the work.
    resume: {
        verb: "paused",
        hint: (t) => `Background work in ${t} paused because nobody used the project for 30 days — open it to resume`,
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
    /** The signed-in person's chat-derived tasks (WHIP-4). */
    getTasks(): Promise<HumanTask[]>;
}

export function TaskBar(props: {
    api: TaskQueueApi;
    selected: EngagementId | null;
    refreshKey: unknown;
    onSelect: (id: EngagementId) => void;
    /** An inbound pill opens an Inbox (DR-0110 §7): the Panel placement's
     *  when every waiting item came from it, otherwise the project's. Optional:
     *  an environment with no Inbox still shows the count, as a note. */
    onOpenInbox?: (inbox: { project: string; projectName: string; placement?: string }) => void;
    /** A paused pill opens the project's background work (DR-0312). Reading
     *  it is a member using the project, which resumes the work. */
    onOpenBackgroundWork?: (project: { project: string; projectName: string }) => void;
    /** The signed-in person's tracker assignments, and where each opens.
     *  Absent when there is no account session: a signed-out person has no
     *  personal queue, which is different from one that could not be read. */
    assigned?: {
        read: () => Promise<AssignedTrackerTasks>;
        onOpen: (task: AssignedTrackerTask) => void;
    };
}) {
    // The refresh key moves on every workspace and tracker change, several
    // times a second while a chat opens. Each move used to start a full read
    // beside the ones still running; now a move during a read waits for it and
    // is answered by the one read after it (WS-891).
    const readTasks = coalescedRead(() => props.api.getTasks());
    const readAssigned = coalescedRead(async () => {
        const assigned = props.assigned;
        if (!assigned) throw new Error("signed out");
        return assigned.read();
    });
    // A person's own queue: signed out there is none to show, and signed in a
    // read that fails says so rather than drawing an empty queue.
    const [taskRead] = createResource(
        () => [props.refreshKey, !!props.assigned] as const,
        async ([, signedIn]) => {
            if (!signedIn) return [] as HumanTask[];
            try {
                return await readTasks();
            } catch {
                return null;
            }
        },
    );
    const tasks = () => taskRead() ?? [];
    const [assignedRead] = createResource(
        () => (props.assigned ? [props.refreshKey, props.assigned] as const : false),
        async () => {
            try {
                return await readAssigned();
            } catch {
                return null;
            }
        },
    );
    const assignedTasks = () => assignedRead()?.tasks ?? [];
    const unreadable = () => {
        const read = assignedRead();
        if (read === undefined || !props.assigned) return [];
        const chats = taskRead() === null ? [{ projectName: "your chats", queue: null }] : [];
        if (read === null) return [{ projectName: "your projects", queue: null }, ...chats];
        return [...read.unavailable, ...chats];
    };
    const empty = () =>
        tasks().length === 0 && assignedTasks().length === 0 && unreadable().length === 0;

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
                <For each={tasks()}>
                    {(t: HumanTask) => {
                        // Chat ask (answer/repair/reply): id is an EngagementId
                        // (narrowed by kind). A `screen` or `resume` task is the
                        // project's: its id is the project and it names no chat.
                        const projectTask = isProjectTask(t);
                        const inbound = t.kind === "screen";
                        const engagement = t.id as EngagementId;
                        const active = () => !projectTask && props.selected === engagement;
                        const color = agentColor(t.agent);
                        const ask = ASK_COPY[t.kind] ?? ASK_COPY.reply;
                        // One canonical title everywhere (#4): never leak the raw
                        // "new chat" placeholder — show the same "Untitled" the tree
                        // and chat header show, so the pill is recognisably the same chat.
                        // An inbound pill's title is its project's name.
                        const title = () => projectTask ? t.title : displayChatTitle(t.title);
                        // An inbound pill is a door onto an Inbox and a paused
                        // pill onto the project's background work; neither needs
                        // a chat. Every other kind discharges inside its chat.
                        const openInbox = props.onOpenInbox;
                        const openBackgroundWork = props.onOpenBackgroundWork;
                        const opens = !projectTask
                            || (!!t.project && (inbound ? !!openInbox : !!openBackgroundWork));
                        const open = () => {
                            if (!projectTask) props.onSelect(engagement);
                            else if (inbound && openInbox && t.project) {
                                openInbox({ project: t.project, projectName: t.title, placement: t.placement });
                            } else if (!inbound && openBackgroundWork && t.project) {
                                openBackgroundWork({ project: t.project, projectName: t.title });
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
                                // An inbound count with no Inbox to open is a note.
                                role={opens ? "button" : "note"}
                                tabindex={opens ? "0" : undefined}
                                aria-label={
                                    inbound
                                        ? `${opens ? "open " : ""}${t.waiting ?? 0} inbound item(s) awaiting review in ${title()}`
                                        : projectTask
                                            ? `${opens ? "open " : ""}background work paused in ${title()}`
                                            : `open ${ask.verb} for ${title()}`
                                }
                                title={ask.hint(title())}
                                style={color ? { "border-left": `3px solid ${color}` } : undefined}
                                onKeyDown={opens ? (e) => {
                                    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); }
                                } : undefined}
                                onClick={opens ? open : undefined}
                            >
                                <span class="task-kind">{ask.verb}</span>
                                <span class="task-title">{title()}</span>
                                {/* The count is the point of an inbound pill: it
                                    says how much is waiting, which no other task
                                    kind needs because they are each one item. */}
                                <Show when={projectTask}>
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
