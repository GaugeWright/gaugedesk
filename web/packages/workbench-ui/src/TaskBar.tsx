/**
 * The human task queue (`navigation.md` B1, `15-task-queue`): the top bar surfaces
 * ask-typed work, current-first (ADR 0082 §2). Each pill's kind is the **verb**
 * the human is asked to perform — `review` a clean merge (keep/reject), `answer`
 * the agent's pending question, `repair` a merge conflict — plus the onboarding
 * `issue` checklist (ADR 0075). Click a pill to open that chat; ✓ on the active
 * *review* keeps it (admit→advance). `answer`/`repair` never offer a one-click
 * action: their ask is discharged inside the chat.
 *
 * A thin renderer (`INV-5`): it shows a projection (`GET /tasks`) and submits the
 * existing merge command; it owns no truth.
 */

import { createResource, createSignal, For, Show } from "solid-js";
import type { EngagementId, HumanTask, RosterPerson } from "@gaugewright/control-plane-client";
import { displayChatTitle } from "./chat-title";

/** Per-ask presentation: the pill's verb chip and its hover explanation. */
const ASK_COPY: Record<string, { verb: string; hint: (title: string) => string }> = {
    review: {
        verb: "review",
        hint: (t) => `Open "${t}" to review the agent's work — keep it or discard it`,
    },
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
    /** True when the *selected* chat's pending change loosens the assistant's
     *  permissions: the bar must route it through the in-panel review/confirm
     *  rather than expose a one-click keep (#5 round-4). */
    selectedLoosening?: boolean;
    onSelect: (id: EngagementId) => void;
    onComplete: (id: EngagementId) => void;
    /** An inbound pill opens the project's review surface as well as its chat
     *  (ADR 0110 §7). Optional: an environment with no review surface still
     *  renders the count, and clicking it just opens the chat. */
    onReviewInbound?: (project: string, id: EngagementId) => void;
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

    // Keeping a change merges it permanently into the shared copy — and there's no
    // un-merge once it's done. So the always-visible top-bar `✓ keep` is guarded by
    // a two-click confirm (round-6 #2), the same forgiveness pattern the context-menu
    // `delete` uses: the first click arms ("keep?"), the second commits. A change the
    // user hasn't even looked at can no longer be merged from the chrome in one click.
    const [arming, setArming] = createSignal<EngagementId | null>(null);

    return (
        <div class="taskbar" data-testid="taskbar">
            <span class="taskbar-label">tasks</span>
            <div class="task-tabs">
                <For
                    each={tasks() ?? []}
                    fallback={<span class="status">no reviews pending</span>}
                >
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
                        const ask = ASK_COPY[t.kind] ?? ASK_COPY.review;
                        // One canonical title everywhere (#4): never leak the raw
                        // "new chat" placeholder — show the same "Untitled" the tree
                        // and chat header show, so the pill is recognisably the same chat.
                        const title = () => displayChatTitle(t.title);
                        // An inbound pill is a door onto the project's queue, so it
                        // opens the chat *and* the review surface. Every other kind
                        // discharges inside the chat and only needs the chat.
                        const open = () => {
                            setArming(null);
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
                                {/* Only a *review* carries the one-click keep — an answer
                                    or repair is discharged inside the chat, never from
                                    the chrome. */}
                                <Show when={active() && t.kind === "review"}>
                                    {/* A change that loosens the assistant's permissions
                                        is never one-click-kept from the bar (#5): the pill
                                        opens the in-panel review, where the keep is gated
                                        behind a plain-language confirm. Safe changes keep
                                        the fast one-click path so `send → keep` stays low
                                        friction (#1). */}
                                    <Show
                                        when={props.selectedLoosening}
                                        fallback={
                                            <button
                                                class="task-keep"
                                                classList={{ confirming: arming() === engagement }}
                                                data-task-keep
                                                data-arming={arming() === engagement ? "1" : undefined}
                                                title={
                                                    arming() === engagement
                                                        ? "Click again to keep this into the shared copy — this can't be undone"
                                                        : "Keep this work into the shared copy"
                                                }
                                                onClick={(e) => {
                                                    e.stopPropagation();
                                                    if (arming() !== engagement) {
                                                        setArming(engagement);
                                                        return;
                                                    }
                                                    setArming(null);
                                                    props.onComplete(engagement);
                                                }}
                                            >
                                                {arming() === engagement ? "confirm keep" : "✓ keep"}
                                            </button>
                                        }
                                    >
                                        <button
                                            class="task-keep warn"
                                            data-task-review
                                            title="This changes the assistant's permissions — open the review to see what changed before keeping"
                                            onClick={(e) => {
                                                e.stopPropagation();
                                                props.onSelect(engagement);
                                            }}
                                        >
                                            review →
                                        </button>
                                    </Show>
                                </Show>
                            </span>
                        );
                    }}
                </For>
            </div>
        </div>
    );
}
