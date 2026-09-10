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
import {
    headerLines,
    isTableRule,
    tableName,
    type HeaderLine,
    type WhipRecordSource,
} from "./whip-view";

export interface RuleNode {
    readonly name: string;
    readonly whens: readonly string[];
    readonly effects: readonly EffectLike[];
    /** What the rule records, and the construct that wrote it. A `table`
     *  declaration lowers to a rule, and this is what says which boxes in the
     *  figure are data rather than behaviour. */
    readonly records: readonly WhipRecordSource[];
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
// A table holds one short line and no graph, so it takes less room — and reading
// smaller is the point: it is the data the rules act on, not one of them.
const TABLE_MIN_WIDTH = 152;

/** A table's one line: how many rows, of what. */
export function tableSummary(records: readonly WhipRecordSource[]): string {
    const schemas = [...new Set(records.map((source) => source.schema))].sort((a, b) =>
        a.localeCompare(b),
    );
    return `${records.length} row${records.length === 1 ? "" : "s"} of ${schemas.join(", ")}`;
}

export interface RuleBox {
    readonly inner: Layout | null;
    readonly headerHeight: number;
    readonly width: number;
    readonly height: number;
    /** The `when` / `where` lines under the name, already elided. Empty for a
     *  table, whose trigger is always `started` and says nothing. */
    readonly lines: readonly HeaderLine[];
    /** A table's summary line, or `null` for a rule. */
    readonly table: string | null;
    /** The name as drawn, which for a table drops the lowering's `table_`. */
    readonly name: string;
}

/** A rule box is sized by what it holds. */
export function ruleBox(rule: RuleNode): RuleBox {
    const table = isTableRule(rule) ? tableSummary(rule.records) : null;
    const name = table ? tableName(rule) : rule.name;
    const inner = rule.effects.length ? effectPlacement(rule.effects, "down") : null;
    const lines = table ? [] : headerLines(rule.whens);
    // One line beyond the triggers: a table's summary, or the note that a rule
    // with no effects only records.
    const trailing = table || !inner ? 1 : 0;
    const headerHeight =
        HEADER_TOP + NAME_LINE + (lines.length + trailing) * WHEN_LINE + (inner ? 4 : 8);
    const bodyChars = [
        ...lines.map((line) => line.keyword.length + 1 + line.text.length),
        ...(table ? [table.length] : []),
    ];
    const textWidth =
        Math.max(
            (table ? "table ".length + name.length : name.length) * NAME_CHAR,
            ...bodyChars.map((chars) => chars * WHEN_CHAR),
        ) + INSET * 2;
    const width = Math.max(
        table ? TABLE_MIN_WIDTH : MIN_WIDTH,
        Math.ceil(textWidth),
        inner ? inner.width + INSET * 2 : 0,
    );
    const height = headerHeight + (inner ? inner.height + INSET : 0);
    return { inner, headerHeight, width, height, lines, table, name };
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
                                data-kind={box()?.table ? "table" : undefined}
                                transform={`translate(${node.x}, ${node.y})`}
                            >
                                <rect class="whip-rule-box" width={node.width} height={node.height} />
                                {/* The lowered rule name stays reachable: it is
                                    what an event and a firing are attributed to. */}
                                <Show when={box()?.table}>
                                    <title>{node.id}</title>
                                </Show>
                                <text class="whip-rule-name" x={INSET} y={HEADER_TOP + 13}>
                                    <Show when={box()?.table}>
                                        <tspan class="whip-rule-keyword">table </tspan>
                                    </Show>
                                    {box()?.name ?? node.id}
                                </text>
                                <For each={box()?.lines ?? []}>
                                    {(line, index) => (
                                        <text
                                            class="whip-rule-when"
                                            classList={{ "whip-rule-guard": line.keyword === "where" }}
                                            x={INSET}
                                            y={HEADER_TOP + NAME_LINE + (index() + 1) * WHEN_LINE}
                                        >
                                            {/* Elided, so the whole clause is on
                                                the line for a reader who needs it. */}
                                            <Show when={line.full}>
                                                <title>{`${line.keyword} ${line.full}`}</title>
                                            </Show>
                                            <tspan class="whip-rule-keyword">{line.keyword} </tspan>
                                            {line.text}
                                        </text>
                                    )}
                                </For>
                                <Show when={box()?.table}>
                                    <text
                                        class="whip-rule-when"
                                        x={INSET}
                                        y={HEADER_TOP + NAME_LINE + WHEN_LINE}
                                    >
                                        {box()!.table}
                                    </text>
                                </Show>
                                <Show
                                    when={box()?.inner}
                                    fallback={
                                        <Show when={!box()?.table}>
                                            <text
                                                class="whip-rule-when whip-rule-empty"
                                                x={INSET}
                                                y={HEADER_TOP + NAME_LINE + ((box()?.lines.length ?? 0) + 1) * WHEN_LINE}
                                            >
                                                records only — no effects
                                            </text>
                                        </Show>
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
