/**
 * Many firings of one rule, as rows against a shared column axis.
 *
 * A stack of full graphs answers "what happened in this firing" and nothing
 * else. The question an operator actually arrives with is the other one —
 * *which* firing is stuck, and whether the others are stuck in the same place.
 * Twelve stacked graphs make that a scrolling exercise; twelve rows on one axis
 * make it a glance, because a column of blocked marks IS the answer.
 *
 * The axis is the program, so a lane is only meaningful across firings that
 * share one. Two things can break that and both are real:
 *
 * - Firings of DIFFERENT RULES have different effects entirely.
 * - Firings of one rule across a REVISION have different effects too, because
 *   the program changed underneath a running instance. `programVersionId` is
 *   what separates them, and putting both in one grid would silently align a
 *   column of one program against a column of another.
 *
 * So {@link groupFirings} partitions on the pair, and each group gets its own
 * axis. A group of one is not a lane grid at all — one row proves no pattern,
 * and the full graph says strictly more.
 */

import { layout } from "./whip-dag-layout";
import type { WhipFiring } from "./whip-view";

/** A column of the lane grid: one effect node of the shared program. */
export interface LaneColumn {
    readonly node: string;
    readonly kind: string;
    /** Depth in the effect graph, so the header can show where the run gets to
     *  rather than only which node it is. */
    readonly layer: number;
}

export interface FiringGroup {
    readonly rule: string;
    readonly programVersionId: string;
    readonly firings: readonly WhipFiring[];
}

/**
 * Firings partitioned by the program they can be read against, in first
 * appearance order — which is the projection's order, and therefore the order
 * they ran. Grouping must never reorder firings within a group: the lane grid
 * reads top to bottom as time.
 */
export function groupFirings(firings: readonly WhipFiring[]): readonly FiringGroup[] {
    const groups: { rule: string; programVersionId: string; firings: WhipFiring[] }[] = [];
    for (const firing of firings) {
        const existing = groups.find(
            (group) =>
                group.rule === firing.rule && group.programVersionId === firing.programVersionId,
        );
        if (existing) existing.firings.push(firing);
        else
            groups.push({
                rule: firing.rule,
                programVersionId: firing.programVersionId,
                firings: [firing],
            });
    }
    return groups;
}

/**
 * The shared column axis for a group, left to right in the same order the graph
 * draws: by layer, then by the layout's own within-layer ordering.
 *
 * Reusing {@link layout} rather than sorting by name is the point. The two
 * views then agree — the third column of the lane grid is the third node of the
 * graph — so a reader who learns the shape once can carry it between them.
 */
export function laneColumns(firings: readonly WhipFiring[]): readonly LaneColumn[] {
    // The union, not the first firing's slots: a firing keyed against a program
    // this build cannot fully resolve may carry fewer, and a column that
    // disappears takes the evidence with it.
    const kinds = new Map<string, string>();
    const bindings = new Map<string, string>();
    for (const firing of firings) {
        for (const slot of firing.effects) {
            if (!kinds.has(slot.node)) kinds.set(slot.node, slot.kind);
            bindings.set(slot.binding ?? slot.node, slot.node);
        }
    }
    if (!kinds.size) return [];

    const nodes = [...kinds.keys()];
    const upstreamOf = new Map<string, string | null>();
    for (const firing of firings) {
        for (const slot of firing.effects) {
            if (upstreamOf.has(slot.node)) continue;
            const [binding] = (slot.arm ?? "").split(":");
            upstreamOf.set(slot.node, binding ? (bindings.get(binding) ?? null) : null);
        }
    }

    const placed = layout(
        nodes.map((node) => ({ id: node, upstream: upstreamOf.get(node) ?? null })),
        { nodeWidth: 1, nodeHeight: 1, columnGap: 0, rowGap: 0, padding: 0 },
    );
    return [...placed.nodes]
        .sort((a, b) => (a.layer === b.layer ? a.order - b.order : a.layer - b.layer))
        .map((node) => ({ node: node.id, kind: kinds.get(node.id) ?? "", layer: node.layer }));
}

/** A firing's short name for the row label: the identity's most specific part,
 *  which is the bit that differs between rows. The full identity stays on the
 *  row as a title, because the short form is a convenience and not the truth. */
export function laneLabel(firing: WhipFiring): string {
    const parts = firing.identity.split("|");
    const first = parts[0] ?? firing.identity;
    const segments = first.split(":");
    return segments[segments.length - 1] || first;
}
