/**
 * The whole program in one figure: rules as boxes, couplings as the edges
 * between them, and inside every box the effect graph that rule lowers to.
 *
 * The coupling flow is the top-level view because it is the thing a reader
 * cannot get any other way. A rule never calls another rule — it matches
 * facts and writes facts, and another rule's `when` is what picks them up — so
 * the coupling between two rules is a FACT, and the fact is the label on the
 * edge. A rule that writes what it matches feeds itself, and that loop is the
 * engine of the workflow; a tracker read coupled to a tracker write was
 * invisible to the compiler's own graph until DR-0085 carried a resource edge.
 *
 * Nesting the effect graph inside the rule box, rather than drawing it in a
 * separate section, keeps one question answerable in one place: "what does
 * this rule actually do when that fact arrives". The reader follows an edge
 * into a box and the answer is already there.
 *
 * Everything flows DOWN. Six layers of effects drawn rightward need a
 * horizontal scroll, which a page never asks of a reader; drawn downward they
 * need the vertical one the reader already has.
 *
 * No plate. The boxes here are the figure — a frame around a figure made of
 * frames is a frame too many.
 */

import { For, Show, type JSX } from "solid-js";
import { layout, type Layout } from "./whip-dag-layout";
import { ArrowMarker, EffectGraphBody, effectPlacement, type EffectLike } from "./WhipDag";

export interface RuleNode {
    readonly name: string;
    readonly whens: readonly string[];
    readonly effects: readonly EffectLike[];
}

export interface RuleEdge {
    readonly producer: string;
    readonly fact: string;
    readonly consumer: string;
}

/** Facts per producer/consumer pair. Two rules can be coupled by more than one
 *  fact, and the layout draws one line between them, so the line has to carry
 *  every fact rather than whichever one happened to be first. */
export function factsByPair(edges: readonly RuleEdge[]): ReadonlyMap<string, readonly string[]> {
    const map = new Map<string, string[]>();
    for (const edge of edges) {
        const key = `${edge.producer} ${edge.consumer}`;
        const list = map.get(key) ?? [];
        if (!list.includes(edge.fact)) list.push(edge.fact);
        map.set(key, list);
    }
    const sorted = new Map<string, readonly string[]>();
    for (const [key, list] of map) sorted.set(key, [...list].sort((a, b) => a.localeCompare(b)));
    return sorted;
}

// The box header: the rule's name, then one line per `when`. The engine knows
// no font, so these are allowances at the workbench's mono size, generous
// enough that a name never touches its own box.
const INSET = 12;
const HEADER_TOP = 10;
const NAME_LINE = 18;
const WHEN_LINE = 13;
const NAME_CHAR = 7.4;
const WHEN_CHAR = 6.4;
const MIN_WIDTH = 188;

export interface RuleBox {
    readonly inner: Layout | null;
    readonly headerHeight: number;
    readonly width: number;
    readonly height: number;
}

/** A rule box is sized by what it holds. */
export function ruleBox(rule: RuleNode): RuleBox {
    const inner = rule.effects.length ? effectPlacement(rule.effects, "down") : null;
    const lines = rule.whens.length + (inner ? 0 : 1);
    const headerHeight = HEADER_TOP + NAME_LINE + lines * WHEN_LINE + (inner ? 4 : 8);
    const textWidth =
        Math.max(
            rule.name.length * NAME_CHAR,
            ...rule.whens.map((when) => (when.length + 5) * WHEN_CHAR),
        ) + INSET * 2;
    const width = Math.max(MIN_WIDTH, Math.ceil(textWidth), inner ? inner.width + INSET * 2 : 0);
    const height = headerHeight + (inner ? inner.height + INSET : 0);
    return { inner, headerHeight, width, height };
}

// Between rule boxes the row gap holds fact labels, which are long —
// `schema:WorkspaceReady` is twenty-one characters — and may stack when two
// facts couple one pair.
const OUTER = {
    nodeWidth: MIN_WIDTH,
    nodeHeight: 48,
    columnGap: 40,
    rowGap: 64,
    padding: 8,
    direction: "down" as const,
};

export function WhipStructureGraph(props: {
    readonly rules: readonly RuleNode[];
    readonly edges: readonly RuleEdge[];
}): JSX.Element {
    const boxes = () => new Map(props.rules.map((rule) => [rule.name, ruleBox(rule)] as const));
    const known = () => new Set(props.rules.map((rule) => rule.name));
    const placement = () =>
        layout(
            props.rules.map((rule) => ({
                id: rule.name,
                upstreams: props.edges
                    .filter((edge) => edge.consumer === rule.name && known().has(edge.producer))
                    .map((edge) => edge.producer),
            })),
            {
                ...OUTER,
                sizeOf: (id) => {
                    const box = boxes().get(id);
                    return box
                        ? { width: box.width, height: box.height }
                        : { width: OUTER.nodeWidth, height: OUTER.nodeHeight };
                },
            },
        );
    const facts = () => factsByPair(props.edges);
    const labelFor = (from: string, to: string) => facts().get(`${from} ${to}`) ?? [];
    const ruleOf = (name: string) => props.rules.find((rule) => rule.name === name);

    return (
        <div class="whip-figure">
            <svg
                class="whip-dag whip-structure"
                width={placement().width}
                height={placement().height}
                viewBox={`0 0 ${placement().width} ${placement().height}`}
                role="img"
                aria-label="program structure"
            >
                <defs><ArrowMarker id="whip-arrow" /></defs>

                <For each={placement().edges}>
                    {(edge) => (
                        <g
                            class="whip-dag-edge whip-rule-edge"
                            data-kind={edge.kind}
                            data-from={edge.from}
                            data-to={edge.to}
                        >
                            <path d={edge.path} marker-end="url(#whip-arrow)" />
                            <For each={labelFor(edge.from, edge.to)}>
                                {(fact, index) => (
                                    <text
                                        x={edge.labelX}
                                        y={edge.labelY - index() * 11}
                                        text-anchor={edge.labelAnchor}
                                        data-on-line={edge.labelOnLine ? "true" : undefined}
                                    >
                                        {fact}
                                    </text>
                                )}
                            </For>
                        </g>
                    )}
                </For>

                <For each={placement().nodes}>
                    {(node) => {
                        const rule = () => ruleOf(node.id);
                        const box = () => boxes().get(node.id);
                        return (
                            <g
                                class="whip-rule-node"
                                data-rule={node.id}
                                transform={`translate(${node.x}, ${node.y})`}
                            >
                                <rect class="whip-rule-box" width={node.width} height={node.height} />
                                <text class="whip-rule-name" x={INSET} y={HEADER_TOP + 13}>
                                    {node.id}
                                </text>
                                <For each={rule()?.whens ?? []}>
                                    {(when, index) => (
                                        <text
                                            class="whip-rule-when"
                                            x={INSET}
                                            y={HEADER_TOP + NAME_LINE + (index() + 1) * WHEN_LINE}
                                        >
                                            <tspan class="whip-rule-keyword">when </tspan>
                                            {when}
                                        </text>
                                    )}
                                </For>
                                <Show
                                    when={box()?.inner}
                                    fallback={
                                        <text
                                            class="whip-rule-when whip-rule-empty"
                                            x={INSET}
                                            y={HEADER_TOP + NAME_LINE + ((rule()?.whens.length ?? 0) + 1) * WHEN_LINE}
                                        >
                                            records only — no effects
                                        </text>
                                    }
                                >
                                    {(inner) => (
                                        <g transform={`translate(${INSET}, ${box()!.headerHeight})`}>
                                            <EffectGraphBody effects={rule()!.effects} placement={inner()} />
                                        </g>
                                    )}
                                </Show>
                            </g>
                        );
                    }}
                </For>
            </svg>
        </div>
    );
}
