/**
 * A rule's effects, drawn as the dependency graph they are.
 *
 * Placement comes from {@link layout}, a deterministic layered engine — this
 * component owns only the drawing. That split is deliberate: the geometry is a
 * pure function with its own tests, so "does it read well" and "is it correct"
 * are separate questions with separate answers.
 *
 * A list can tell you an effect is blocked. Only the graph tells you it is
 * blocked *behind* a claim that is still running, on the `succeeds` arm, while
 * the sibling `contended` arm was never reached. The edges carry the predicate
 * because the predicate is the reason.
 *
 * **Absent effects are drawn as nodes, not omitted.** A `case` arm never taken
 * has no runtime row, so a graph built from the log alone silently shrinks and
 * the reader never learns the arm exists. Drawn dashed and in place, it says the
 * program has this shape and the run does not.
 *
 * The drawing is split in two. {@link EffectGraphBody} is the figure itself, a
 * `<g>` that can sit inside any SVG — Structure nests one inside every rule's
 * box. {@link WhipDag} is that body in its own SVG with the plate around it,
 * which is what Instances draws for one firing.
 */

import { For, Show, type JSX } from "solid-js";
import { layout, type Layout } from "./whip-dag-layout";
import { slotLabel, type WhipEffectSlot } from "./whip-view";

export const EFFECT_NODE_W = 156;
export const EFFECT_NODE_H = 52;

const RIGHTWARD = {
    nodeWidth: EFFECT_NODE_W,
    nodeHeight: EFFECT_NODE_H,
    columnGap: 64,
    rowGap: 14,
    padding: 6,
    direction: "right" as const,
};
// Downward, the row gap holds the predicate labels — three `case` arms leaving
// one node need three staggered jogs, and each label wants ten pixels of it.
const DOWNWARD = {
    nodeWidth: EFFECT_NODE_W,
    nodeHeight: EFFECT_NODE_H,
    columnGap: 24,
    rowGap: 40,
    padding: 6,
    direction: "down" as const,
};

export interface EffectLike {
    readonly node: string;
    readonly kind: string;
    readonly arm?: string | null;
    readonly binding?: string | null;
}

export function toneFor(slot: WhipEffectSlot | undefined): string {
    if (!slot) return "static";
    if (slot.absent) return "absent";
    const status = slot.status ?? "";
    if (status === "completed") return "ok";
    if (status === "running") return "run";
    if (status.startsWith("blocked")) return "blocked";
    if (status === "failed" || status === "timed_out") return "failed";
    return "idle";
}

/** Where a rule's effects go. A node's upstream is the effect BOUND to its
 *  arm's binding, which is usually but not always the node's own name. */
export function effectPlacement(
    effects: readonly EffectLike[],
    direction: "right" | "down",
): Layout {
    const bindings = new Map<string, string>();
    for (const effect of effects) bindings.set(effect.binding ?? effect.node, effect.node);
    return layout(
        effects.map((effect) => {
            const [binding] = (effect.arm ?? "").split(":");
            return {
                id: effect.node,
                upstream: binding ? (bindings.get(binding) ?? null) : null,
            };
        }),
        direction === "down" ? DOWNWARD : RIGHTWARD,
    );
}

export function ArrowMarker(props: { readonly id: string }): JSX.Element {
    return (
        <marker
            id={props.id}
            viewBox="0 0 10 10"
            refX="9"
            refY="5"
            markerWidth="5"
            markerHeight="5"
            orient="auto-start-reverse"
        >
            <path d="M 0 0 L 10 5 L 0 10 z" class="whip-dag-arrowhead" />
        </marker>
    );
}

/** The figure: edges under nodes, in one `<g>`. */
export function EffectGraphBody(props: {
    readonly effects: readonly EffectLike[];
    readonly placement: Layout;
    /** Runtime state per node, when there is a run to paint on. Omitted by
     *  Structure, which is the program with no instance in mind. */
    readonly slots?: readonly WhipEffectSlot[];
    readonly marker?: string;
}): JSX.Element {
    const predicates = () => {
        const map = new Map<string, string>();
        for (const effect of props.effects) {
            const [, predicate] = (effect.arm ?? "").split(":");
            if (predicate) map.set(effect.node, predicate);
        }
        return map;
    };
    const kindOf = (node: string) => props.effects.find((e) => e.node === node)?.kind ?? "";
    const slotOf = (node: string) => props.slots?.find((slot) => slot.node === node);
    const marker = () => `url(#${props.marker ?? "whip-arrow"})`;

    return (
        <g class="whip-effect-graph">
            <For each={props.placement.edges}>
                {(edge) => (
                    <g
                        class="whip-dag-edge"
                        data-absent={slotOf(edge.to)?.absent ? "true" : undefined}
                    >
                        <path d={edge.path} marker-end={marker()} />
                        <text
                            x={edge.labelX}
                            y={edge.labelY}
                            text-anchor={edge.labelAnchor}
                            data-on-line={edge.labelOnLine ? "true" : undefined}
                        >
                            {predicates().get(edge.to)}
                        </text>
                    </g>
                )}
            </For>

            <For each={props.placement.nodes}>
                {(node) => {
                    const slot = () => slotOf(node.id);
                    return (
                        <g
                            class="whip-dag-node"
                            data-tone={toneFor(slot())}
                            data-node={node.id}
                            transform={`translate(${node.x}, ${node.y})`}
                        >
                            {/* Square: the system has no rounded corners. */}
                            <rect class="whip-dag-box" width={node.width} height={node.height} />
                            {/* The halo rides outside the mark, so "live"
                                reads before the colour does. */}
                            <circle class="whip-dag-halo" cx="13" cy="16" r="6" />
                            <circle class="whip-dag-dot" cx="13" cy="16" r="3.5" />
                            <text class="whip-dag-name" x="24" y="20">{node.id}</text>
                            <text class="whip-dag-kind" x="13" y="34">{kindOf(node.id)}</text>
                            <Show when={slot()}>
                                <text class="whip-dag-status" x="13" y="46">
                                    {slotLabel(slot()!)}
                                </text>
                            </Show>
                        </g>
                    );
                }}
            </For>
        </g>
    );
}

export function WhipDag(props: {
    readonly effects: readonly EffectLike[];
    readonly slots?: readonly WhipEffectSlot[];
}): JSX.Element {
    const placement = () => effectPlacement(props.effects, "right");

    // The double rule — heavy outside, fine within. The only frame in the
    // system, and this graph is the live panel it exists for.
    return (
        <div class="whip-plate">
          <div class="whip-plate-inner">
            <svg
                class="whip-dag"
                width={placement().width}
                height={placement().height}
                viewBox={`0 0 ${placement().width} ${placement().height}`}
                role="img"
                aria-label="effect dependency graph"
            >
                <defs><ArrowMarker id="whip-arrow" /></defs>
                <EffectGraphBody effects={props.effects} placement={placement()} slots={props.slots} />
            </svg>
          </div>
        </div>
    );
}
