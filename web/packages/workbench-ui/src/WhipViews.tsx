/**
 * The two views a `.whip` file gets in the content viewer: **Structure** and
 * **Instances**.
 *
 * Structure is the program: each rule, what triggers it, and the graph of
 * effects it lowers. Instances is every run of it, the same graph with runtime
 * state painted on.
 *
 * The pair exists rather than a log view because of one thing a log cannot do.
 * An effect a firing **never requested** — a `case` arm not taken, a
 * `contended` branch on a lease that was held — has no row anywhere in the
 * runtime. From the log it is indistinguishable from an effect that is not in
 * the program at all. Only the compiled structure knows it was there to not
 * happen, and drawing it is the whole point.
 *
 * Which is why absence is never spelled as a status. `not requested` sits beside
 * `queued` and `blocked` nowhere in this file: those are states the runtime is
 * holding, and this is the absence of one. The chip is an outline with a hollow
 * dot for the same reason.
 */

import { For, Show, type JSX } from "solid-js";
import { groupFirings, laneLabel } from "./whip-lanes";
import {
    firingSummary,
    slotLabel,
    type WhipEffectSlot,
    type WhipFiring,
    type WhipInstanceView,
    type WhipStructure,
} from "./whip-view";
import { toneFor, WhipDag } from "./WhipDag";
import { WhipLanes } from "./WhipLanes";
import { WhipStructureGraph } from "./WhipStructureGraph";

function Chip(props: { readonly tone: string; readonly children: JSX.Element }): JSX.Element {
    return <span class="whip-chip" data-tone={props.tone}>{props.children}</span>;
}

/** Reasons and run detail, under the graph that shows the shape. Only the nodes
 *  with something to add appear — a completed effect with one clean run says
 *  everything it has to say in the drawing. */
function Notes(props: { readonly effects: readonly WhipEffectSlot[] }): JSX.Element {
    const noteworthy = () =>
        props.effects.filter((slot) => slot.blockReason || (slot.runs?.length ?? 0) > 0);
    return (
        <For each={noteworthy()}>
            {(slot) => (
                <div class="whip-effect-note" data-node={slot.node}>
                    <span class="whip-note-node">{slot.node}</span>
                    <Show when={slot.blockReason}>
                        <span class="whip-note-reason">{slot.blockReason}</span>
                    </Show>
                    <For each={slot.runs ?? []}>
                        {(run) => (
                            <span class="whip-note-run">
                                {run.provider} · {run.status}
                                {run.completedAt ? ` · ${run.startedAt}–${run.completedAt}` : ` · ${run.startedAt}`}
                            </span>
                        )}
                    </For>
                </div>
            )}
        </For>
    );
}

/** The rule and diamond: how this system divides sections. Never a card — "a
 *  boxed grid is the shape a page takes when its composition was not decided"
 *  (GaugeWright `brand/composition.md`). */
function Divider(): JSX.Element {
    return <div class="whip-div" aria-hidden="true"><i /></div>;
}

function Legend(): JSX.Element {
    return (
        <div class="whip-legend">
            <Chip tone="ok">completed</Chip>
            <Chip tone="run">running</Chip>
            <Chip tone="blocked">blocked</Chip>
            <Chip tone="absent">not requested</Chip>
            <span class="whip-legend-note">
                <em>not requested</em> is not a state the runtime holds — there is no record of it
                at all. It is drawn from the program, which is the only place that knows the effect
                was there to not happen.
            </span>
        </div>
    );
}

/** One firing, drawn in full. The identity is the FIRING's, not an event's:
 *  one firing commits once per `after` continuation and every one of those
 *  commits carries this same identity, which is what makes the join possible. */
function SingleFiring(props: { readonly firing: WhipFiring }): JSX.Element {
    return (
        <>
            <div class="whip-sub" title={props.firing.identity}>
                {props.firing.identity}
            </div>
            <Show when={props.firing.effects.length}>
                <WhipDag effects={props.firing.effects} slots={props.firing.effects} />
                <Notes effects={props.firing.effects} />
            </Show>
        </>
    );
}

/** Under a lane grid, the detail the marks deliberately leave out — but only
 *  for the firings that have any. Repeating a clean run's timings per row would
 *  bury the two rows that are actually stuck. */
function LaneNotes(props: { readonly firings: readonly WhipFiring[] }): JSX.Element {
    const noteworthy = () =>
        props.firings.filter((firing) => firing.effects.some((slot) => slot.blockReason));
    return (
        <For each={noteworthy()}>
            {(firing) => (
                <div class="whip-lane-note" data-identity={firing.identity}>
                    <span class="whip-note-node">{laneLabel(firing)}</span>
                    <div class="whip-lane-note-body">
                        <For each={firing.effects.filter((slot) => slot.blockReason)}>
                            {(slot) => (
                                <div class="whip-effect-note" data-node={slot.node}>
                                    <span class="whip-note-node">{slot.node}</span>
                                    <span class="whip-note-reason">{slot.blockReason}</span>
                                </div>
                            )}
                        </For>
                    </div>
                </div>
            )}
        </For>
    );
}

/** A group's headline. Firings are summed rather than listed, because the count
 *  of runs stuck somewhere is the number a reader is looking for. */
function groupSummary(firings: readonly WhipFiring[]): string {
    if (firings.length === 1) return firingSummary(firings[0]!);
    // Without every firing's compiled structure, absence is not computable, and
    // a count would be a claim the projection cannot support. `firingSummary`
    // already refuses this for one firing; a group must refuse it too, or the
    // guard is one that only holds when there is nothing much to guard.
    if (firings.some((firing) => !firing.structureAvailable)) {
        return `${firings.length} firings · structure unavailable`;
    }
    const absent = firings.reduce(
        (total, firing) => total + firing.effects.filter((slot) => slot.absent).length,
        0,
    );
    const parts = [`${firings.length} firings`];
    const blocked = firings.filter((firing) =>
        firing.effects.some((slot) => (slot.status ?? "").startsWith("blocked")),
    ).length;
    if (blocked) parts.push(`${blocked} blocked`);
    if (absent) parts.push(`${absent} never requested`);
    return parts.join(" · ");
}

export function WhipStructureView(props: {
    /** The program's structure — from the file itself when nothing has run
     *  it, which is the ordinary state of a `.whip` file just written. */
    readonly structure: WhipStructure | null | undefined;
}): JSX.Element {
    return (
        <div class="whip-panel" data-whip-structure>
            <Show
                when={props.structure?.available}
                fallback={
                    <div class="status">
                        {props.structure?.reason ??
                            "No compiled structure is available for this program yet."}
                    </div>
                }
            >
                <div class="whip-eyebrow">
                    {props.structure!.workflow}
                    <span class="whip-meta">
                        {props.structure!.rules.length} rules ·{" "}
                        {props.structure!.ruleEdges.length} couplings
                    </span>
                </div>

                {/* One figure. The coupling flow is the top-level view — it
                    is the thing no other reading of the program gives — and
                    every rule's effect graph sits inside that rule's box, so
                    "what does this rule do when that fact arrives" is answered
                    where the fact arrives. */}
                <WhipStructureGraph
                    rules={props.structure!.rules}
                    edges={props.structure!.ruleEdges}
                />
            </Show>
        </div>
    );
}

export function WhipInstancesView(props: {
    readonly instances: readonly WhipInstanceView[];
}): JSX.Element {
    return (
        <div class="whip-panel" data-whip-instances>
            <Show
                when={props.instances.length}
                fallback={<div class="status">No instance of this program is running.</div>}
            >
                <For each={props.instances}>
                    {(instance) => (
                        <div data-instance={instance.instanceId}>
                            <div class="whip-eyebrow">
                                {instance.instanceId}
                                <Chip tone={instance.status === "running" ? "run" : "idle"}>
                                    {instance.status}
                                </Chip>
                                <Show when={instance.absentTotal > 0}>
                                    <Chip tone="absent">
                                        {instance.absentTotal} never requested
                                    </Chip>
                                </Show>
                            </div>

                            {/* The projection's self-check. Non-empty means it is
                                keyed differently than the run was — a branched or
                                restored instance — so the absences below are
                                artefacts. Saying so is the difference between an
                                incomplete picture and a confident lie. */}
                            <Show when={instance.unattributedEffects.length}>
                                <div class="whip-note" data-kind="untrusted" data-whip-untrusted>
                                    {instance.unattributedEffects.length} effect(s) this instance
                                    created match no node in the program, so this view is keyed
                                    differently than the run was — the “not requested” marks below
                                    cannot be relied on.
                                </div>
                            </Show>
                            <Show when={instance.programVersionsSeen.length > 1}>
                                <div class="whip-note">
                                    Revised while running: firings span{" "}
                                    {instance.programVersionsSeen.length} program versions, each drawn
                                    against its own.
                                </div>
                            </Show>

                            {/* Grouped by the program a firing can be read
                                against, because that is what a shared column
                                axis requires. One firing keeps the full graph:
                                a single row proves no pattern, and the graph
                                says strictly more. */}
                            <For each={groupFirings(instance.firings)}>
                                {(group, index) => (
                                    <div class="whip-group" data-rule={group.rule}>
                                        <Show when={index() > 0}><Divider /></Show>
                                        <div class="whip-head">
                                            <span class="whip-title">{group.rule}</span>
                                            <span class="whip-meta">{groupSummary(group.firings)}</span>
                                        </div>
                                        <Show
                                            when={group.firings.length > 1}
                                            fallback={<SingleFiring firing={group.firings[0]!} />}
                                        >
                                            <WhipLanes firings={group.firings} />
                                            <LaneNotes firings={group.firings} />
                                        </Show>
                                    </div>
                                )}
                            </For>
                        </div>
                    )}
                </For>
                <Legend />
            </Show>
        </div>
    );
}

export { slotLabel, toneFor };
