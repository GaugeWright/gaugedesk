/**
 * The lane grid: one row per firing, one column per effect, marks in the cells.
 *
 * See `whip-lanes.ts` for why the axis is shared and what may not share it.
 * This file owns only the drawing, and one decision worth stating: a cell shows
 * a MARK, not a word. Nine columns of words is a wall of text in which no
 * column stands out, and a column standing out is the entire reason to draw
 * this instead of a stack of graphs. The words are still reachable — every cell
 * carries its status as a title, and the notes under the group say the rest.
 *
 * Absence keeps its own mark here exactly as it does in the graph: hollow, and
 * never a shade of a status. A run that never asked for an effect and a run
 * whose effect is pending are different facts, and a grid that blurs them is
 * worse than no grid.
 */

import { For, Show, type JSX } from "solid-js";
import { laneColumns, laneLabel } from "./whip-lanes";
import { effectHandle, slotLabel, type WhipFiring } from "./whip-view";
import { toneFor } from "./WhipDag";

export function WhipLanes(props: { readonly firings: readonly WhipFiring[] }): JSX.Element {
    const columns = () => laneColumns(props.firings);
    // Computed rather than a custom property: `repeat()` will not take a
    // `var()` for its count, and every row must carry the SAME template or the
    // columns stop lining up, which is the one thing the grid is for.
    const template = () => `var(--whip-lane-label) repeat(${columns().length}, 26px)`;
    const slotIn = (firing: WhipFiring, node: string) =>
        firing.effects.find((slot) => slot.node === node);

    return (
        <div class="whip-plate">
            <div class="whip-plate-inner">
                {/* Real table semantics. Visually this is a grid of marks; to a
                    screen reader, spans in a CSS grid are an undifferentiated
                    stream with no way to know which effect a mark belongs to.
                    The column and row headers are what make a cell locatable. */}
                <div class="whip-lanes" role="table" aria-label="firings by effect" data-whip-lanes>
                    <div
                        class="whip-lane-head"
                        role="row"
                        style={{ "grid-template-columns": template() }}
                    >
                        <span class="whip-lane-id" role="columnheader" />
                        <For each={columns()}>
                            {(column) => (
                                <span
                                    class="whip-lane-col"
                                    role="columnheader"
                                    data-node={column.node}
                                    title={`${column.node} — ${column.kind}`}
                                >
                                    {effectHandle(column)}
                                </span>
                            )}
                        </For>
                    </div>

                    <For each={props.firings}>
                        {(firing) => (
                            <div
                                class="whip-lane"
                                role="row"
                                data-identity={firing.identity}
                                style={{ "grid-template-columns": template() }}
                            >
                                <span
                                    class="whip-lane-id"
                                    role="rowheader"
                                    title={firing.identity}
                                >
                                    {laneLabel(firing)}
                                </span>
                                <For each={columns()}>
                                    {(column) => {
                                        const slot = () => slotIn(firing, column.node);
                                        return (
                                            <span
                                                class="whip-lane-cell"
                                                role="cell"
                                                data-node={column.node}
                                                data-tone={toneFor(slot())}
                                                data-absent={slot()?.absent ? "true" : undefined}
                                                aria-label={
                                                    slot()
                                                        ? `${column.node}: ${slotLabel(slot()!)}`
                                                        : `${column.node}: not in this firing`
                                                }
                                                title={
                                                    slot()
                                                        ? `${column.node}: ${slotLabel(slot()!)}`
                                                        : `${column.node}: not in this firing`
                                                }
                                            >
                                                <Show when={slot()}>
                                                    <i />
                                                </Show>
                                            </span>
                                        );
                                    }}
                                </For>
                            </div>
                        )}
                    </For>
                </div>
            </div>
        </div>
    );
}
