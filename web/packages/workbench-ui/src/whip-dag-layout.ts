/**
 * A deterministic layered layout for the graphs a whip program is made of.
 *
 * Layered (Sugiyama-style) rather than ad-hoc, because the graph being drawn is
 * genuinely a DAG with branching arms: `slot --held--> turn` and
 * `slot --contended--> effect4` fan out of one node, and three `case` arms fan
 * out of another. Assigning a row per node in encounter order — the first cut
 * here — puts two nodes in one slot and routes edges through them.
 *
 * DETERMINISM IS THE POINT, and it is a correctness property, not a nicety:
 *
 * - The same program must draw identically every time it is opened, or a reader
 *   cannot learn the shape of their own workflow.
 * - Two readers looking at one instance must see the same picture.
 * - A screenshot in a bug report must match what the next person opens.
 *
 * So every step is total and order-independent: ties break on node id, sweeps
 * run a fixed number of times, and no step reads Map/Set iteration order for
 * anything that reaches the output. `layout()` on a shuffled copy of the same
 * graph returns byte-identical coordinates — asserted in the tests.
 *
 * The three passes are the standard ones:
 *
 * 1. **Layer** by longest path from a root, so every edge points strictly with
 *    the flow and a node never appears before what it waits on.
 * 2. **Order** within each layer by repeated barycentre sweeps, which is what
 *    pulls a node next to its neighbours and takes most crossings out.
 * 3. **Place**, then route edges as elbows with a per-corridor lane so two
 *    edges crossing the same gap do not draw over each other.
 *
 * FLOW HAS A DIRECTION, and the engine is written against it rather than against
 * x and y. Every coordinate below is an `along` (with the flow: layer to layer)
 * and a `cross` (across it: order to order), mapped to the screen once at the
 * end. `right` puts layers in columns; `down` puts them in rows. The two are the
 * same algorithm, and the reason for `down` is a page: a workflow with six
 * layers drawn rightward needs a horizontal scroll, which a reader never
 * expects, while drawn downward it needs the vertical one they already have.
 *
 * NODES MAY DIFFER IN SIZE. A rule box holds its own effect graph, so one rule
 * is two hundred pixels tall and its neighbour forty. `sizeOf` supplies each
 * node's extent; a layer is as deep as its deepest node, and a cross-flow slot
 * is as wide as the widest node at that index in any layer. Nodes centre in the
 * cross-flow slot. The invariant that keeps long-edge routing honest survives
 * this: slots share one cross position per index across every layer, so the gap
 * between two slots is clear all the way along the flow.
 *
 * The engine draws two different graphs. A rule's EFFECTS form a forest: every
 * effect hangs off exactly one arm, so `upstream` names it. A workflow's RULES
 * do not — a rule matches several facts and so has several producers, a rule
 * that writes a fact it also matches feeds ITSELF, and two rules can feed each
 * other, which DR-0081 admits as long as the cycle is paced. `upstreams` is the
 * general form and `upstream` is sugar for the one-parent case.
 *
 * That generality is what forces the three edge kinds. A `forward` edge is the
 * elbow above. A `self` edge is a loop over its own node, because a rule that
 * re-triggers itself is a fact about the workflow a reader must not have to
 * infer from a missing line. A `back` edge — into a node at or before its
 * source — is routed outside the whole figure rather than through it, since a
 * line drawn against the flow across the node band reads as a line into every
 * node it crosses.
 */

export interface LayoutInput {
    readonly id: string;
    /** The single node this one waits on. `null` roots it. Sugar for a
     *  one-element {@link upstreams}, which is what an effect always has. */
    readonly upstream?: string | null;
    /** Every node this one waits on. Takes precedence over {@link upstream}.
     *  An id not in the set is dropped rather than invented, and a node may
     *  name itself — that becomes a `self` edge, not a layering constraint. */
    readonly upstreams?: readonly string[];
}

export interface NodeSize {
    readonly width: number;
    readonly height: number;
}

export interface PlacedNode {
    readonly id: string;
    readonly layer: number;
    readonly order: number;
    readonly x: number;
    readonly y: number;
    readonly width: number;
    readonly height: number;
}

export interface PlacedEdge {
    readonly from: string;
    readonly to: string;
    /** `self` loops over one node; `back` points at or before its source and
     *  is routed outside the figure. Both are legal in a rule graph and neither
     *  can occur in an effect graph. */
    readonly kind: "forward" | "self" | "back";
    /** SVG path data, already routed. */
    readonly path: string;
    /** Where a label sits without landing on the line — or, when it must, with
     *  `labelOnLine` set so the renderer can knock the line out behind it. */
    readonly labelX: number;
    readonly labelY: number;
    readonly labelAnchor: "start" | "middle" | "end";
    readonly labelOnLine: boolean;
}

export interface Layout {
    readonly nodes: readonly PlacedNode[];
    readonly edges: readonly PlacedEdge[];
    readonly width: number;
    readonly height: number;
}

export interface LayoutOptions {
    readonly nodeWidth: number;
    readonly nodeHeight: number;
    readonly columnGap: number;
    readonly rowGap: number;
    readonly padding: number;
    /** Barycentre sweeps. Fixed, so the result cannot depend on convergence. */
    readonly sweeps?: number;
    /** Which way the flow runs. Default `right`. */
    readonly direction?: "right" | "down";
    /** A node's own extent, when nodes differ. Absent, every node is
     *  `nodeWidth` by `nodeHeight`. */
    readonly sizeOf?: (id: string) => NodeSize;
}

/** Every node's upstreams, normalised: deduped, sorted, self-references and
 *  unknown ids removed. A snapshot from a newer compiler can name a node this
 *  build does not have; dropping the EDGE keeps the node, where dropping the
 *  node would silently shrink the program the reader is trying to read. */
function normalise(
    nodes: readonly LayoutInput[],
    present: ReadonlySet<string>,
): ReadonlyMap<string, readonly string[]> {
    const map = new Map<string, readonly string[]>();
    for (const node of nodes) {
        const raw = node.upstreams ?? (node.upstream != null ? [node.upstream] : []);
        map.set(
            node.id,
            [...new Set(raw)]
                .filter((up) => up !== node.id && present.has(up))
                .sort((a, b) => a.localeCompare(b)),
        );
    }
    return map;
}

/** Longest-path layering: a node sits one past the deepest thing it waits on.
 *  Total on a malformed graph — an upstream that is not present, or a cycle a
 *  paced construct legitimately introduces — by treating the unresolvable as a
 *  root. Ids are visited in sorted order so that even a cyclic graph, where the
 *  break point decides the answer, decides it the same way every time. */
function assignLayers(
    ids: readonly string[],
    upstreamsOf: ReadonlyMap<string, readonly string[]>,
): ReadonlyMap<string, number> {
    const layers = new Map<string, number>();
    const resolve = (id: string, seen: ReadonlySet<string>): number => {
        const known = layers.get(id);
        if (known !== undefined) return known;
        if (seen.has(id)) return 0;
        const deeper = new Set([...seen, id]);
        let layer = 0;
        for (const up of upstreamsOf.get(id) ?? []) {
            layer = Math.max(layer, resolve(up, deeper) + 1);
        }
        layers.set(id, layer);
        return layer;
    };
    for (const id of ids) resolve(id, new Set());
    return layers;
}

/** Mean position of a node's neighbours in the adjacent layer — the pull that
 *  straightens edges. `null` when it has none, which leaves the node where it
 *  is rather than sending it to the top. */
function barycentre(
    id: string,
    neighbours: ReadonlyMap<string, readonly string[]>,
    positions: ReadonlyMap<string, number>,
): number | null {
    const adjacent = neighbours.get(id) ?? [];
    if (!adjacent.length) return null;
    let total = 0;
    let counted = 0;
    for (const other of adjacent) {
        const position = positions.get(other);
        if (position !== undefined) {
            total += position;
            counted += 1;
        }
    }
    return counted ? total / counted : null;
}

/** A point in flow coordinates: along the flow, then across it. */
type Flow = readonly [along: number, cross: number];

export function layout(nodes: readonly LayoutInput[], options: LayoutOptions): Layout {
    const { nodeWidth, nodeHeight, columnGap, rowGap, padding } = options;
    const sweeps = options.sweeps ?? 4;
    const down = options.direction === "down";
    if (!nodes.length) return { nodes: [], edges: [], width: 0, height: 0 };

    // The flow axes. Rightward, `along` is x and a layer is a column; downward,
    // `along` is y and a layer is a row. Everything after this point is written
    // in those terms and mapped back to the screen by `pt`.
    const alongGap = down ? rowGap : columnGap;
    const crossGap = down ? columnGap : rowGap;
    const sizeOf = options.sizeOf ?? (() => ({ width: nodeWidth, height: nodeHeight }));
    const extent = (id: string): { along: number; cross: number } => {
        const size = sizeOf(id);
        return down
            ? { along: size.height, cross: size.width }
            : { along: size.width, cross: size.height };
    };
    const pt = ([along, cross]: Flow): string => (down ? `${cross} ${along}` : `${along} ${cross}`);
    const xy = ([along, cross]: Flow): { x: number; y: number } =>
        down ? { x: cross, y: along } : { x: along, y: cross };

    // Work from a sorted copy: the caller's array order must not reach the
    // output, or the same graph drawn from two sources differs.
    const sorted = [...nodes].sort((a, b) => a.id.localeCompare(b.id));
    const ids = sorted.map((node) => node.id);
    const present = new Set(ids);
    const upstreamsOf = normalise(sorted, present);
    const layers = assignLayers(ids, upstreamsOf);

    // A node that names itself loops rather than layers: it is one rule
    // re-triggering on a fact it wrote, which is a cycle the compiler admits
    // when it is paced, and a shape the reader has to be able to see.
    const selfLooped = new Set(
        sorted
            .filter((node) => {
                const raw = node.upstreams ?? (node.upstream != null ? [node.upstream] : []);
                return raw.includes(node.id);
            })
            .map((node) => node.id),
    );

    const parents = new Map<string, readonly string[]>();
    const children = new Map<string, string[]>();
    for (const id of ids) {
        const ups = upstreamsOf.get(id) ?? [];
        parents.set(id, ups);
        for (const up of ups) {
            const list = children.get(up) ?? [];
            list.push(id);
            children.set(up, list);
        }
    }
    for (const [key, list] of children) children.set(key, [...list].sort((a, b) => a.localeCompare(b)));

    const depth = Math.max(...ids.map((id) => layers.get(id) ?? 0));
    const byLayer: string[][] = Array.from({ length: depth + 1 }, () => []);
    for (const id of ids) byLayer[layers.get(id) ?? 0]!.push(id);

    // Order: alternate downward and upward barycentre sweeps. A node with no
    // neighbour in the sweep direction keeps its index, and every tie breaks on
    // id, so the result is a pure function of the graph.
    const indexIn = (layerNodes: readonly string[]) =>
        new Map(layerNodes.map((id, index) => [id, index] as const));
    for (let sweep = 0; sweep < sweeps; sweep += 1) {
        const downward = sweep % 2 === 0;
        const range = downward
            ? [...byLayer.keys()].slice(1)
            : [...byLayer.keys()].slice(0, -1).reverse();
        for (const index of range) {
            const reference = indexIn(byLayer[downward ? index - 1 : index + 1]!);
            const relation = downward ? parents : children;
            const current = indexIn(byLayer[index]!);
            byLayer[index] = [...byLayer[index]!].sort((a, b) => {
                const left = barycentre(a, relation, reference) ?? current.get(a)!;
                const right = barycentre(b, relation, reference) ?? current.get(b)!;
                return left === right ? a.localeCompare(b) : left - right;
            });
        }
    }

    // Classify before placing, because self loops need headroom before the
    // first slot and back edges need a lane after the last one. Sorted, so lane
    // assignment is a function of the graph rather than of iteration order.
    const forward: { from: string; to: string }[] = [];
    const backward: { from: string; to: string }[] = [];
    for (const id of ids) {
        for (const up of upstreamsOf.get(id) ?? []) {
            const bucket = (layers.get(up) ?? 0) < (layers.get(id) ?? 0) ? forward : backward;
            bucket.push({ from: up, to: id });
        }
    }
    const byKey = (a: { from: string; to: string }, b: { from: string; to: string }) =>
        `${a.from} ${a.to}`.localeCompare(`${b.from} ${b.to}`);
    forward.sort(byKey);
    backward.sort(byKey);

    // Extents. A layer is as deep as its deepest node, and an empty one — a
    // cyclic graph can leave layer 0 empty, two rules feeding each other
    // layer as 1 and 2 — keeps a default node's depth, so the figure holds
    // its shape rather than collapsing a column to nothing.
    const defaultAlong = down ? nodeHeight : nodeWidth;
    const layerExtent = byLayer.map((layerNodes) =>
        layerNodes.length ? Math.max(...layerNodes.map((id) => extent(id).along)) : defaultAlong,
    );
    const layerStart = layerExtent.map((_, layer) =>
        padding + layerExtent.slice(0, layer).reduce((sum, e) => sum + e + alongGap, 0),
    );
    const layerEnd = (layer: number) => layerStart[layer]! + layerExtent[layer]!;

    // Across the flow each layer is packed and centred on the widest one. A
    // slot per order index — one cross position shared by every layer — was
    // the first cut, and it is exactly wrong for nodes of different sizes: a
    // narrow rule beside a wide one was pushed out to the wide one's far edge
    // and the figure grew to twice the width of anything in it. Packing puts
    // the small boxes in the room above the big one, where a reader expects
    // them. What packing gives up is a gap that is clear across every layer,
    // so an edge spanning layers is routed around the figure instead.
    const layerCross = byLayer.map((layerNodes) =>
        layerNodes.reduce((sum, id, index) => sum + extent(id).cross + (index ? crossGap : 0), 0),
    );
    const bandCross = Math.max(...layerCross);

    const loopRise = 13;
    const labelStep = 11;
    const backLaneGap = 9;
    const longLaneGap = 9;
    // Room for a label beside a lane the renderer cannot measure. The engine
    // knows no font, so this is an allowance, not a measurement.
    const sideLabelRoom = 84;
    const bottomPad = backward.length
        ? backLaneGap * (backward.length + 1) + (down ? sideLabelRoom : 0)
        : 0;

    // Placement and routing as a function of headroom, because how much
    // headroom is needed cannot be known until the labels are placed, and
    // the labels cannot be placed until the nodes are. `crossPad` shifts
    // everything uniformly, so ONE trial run measures the deficit exactly
    // and one corrected run spends exactly that much — no iterating to a
    // fixed point, and no slack reserved on a figure that does not need it.
    const build = (crossPad: number) => {
        let lowest = crossPad + padding;
        const note = (cross: number) => {
            if (cross < lowest) lowest = cross;
        };
        const bandStart = crossPad + padding;
        const bandEnd = bandStart + bandCross;

        type Placed = {
            along: number; cross: number; alongSize: number; crossSize: number; layer: number;
        };
        const placed: PlacedNode[] = [];
        const at = new Map<string, Placed>();
        byLayer.forEach((layerNodes, layerIndex) => {
            let cursor = bandStart + (bandCross - layerCross[layerIndex]!) / 2;
            layerNodes.forEach((id, order) => {
                const size = extent(id);
                const flow: Placed = {
                    along: layerStart[layerIndex]!,
                    cross: cursor,
                    alongSize: size.along,
                    crossSize: size.cross,
                    layer: layerIndex,
                };
                cursor += size.cross + crossGap;
                at.set(id, flow);
                const px = sizeOf(id);
                placed.push({ id, layer: layerIndex, order, ...xy([flow.along, flow.cross]), width: px.width, height: px.height });
            });
        });

        // Where an edge leaves and lands. Fanned across the node's edge in the
        // order the neighbours sit, so two edges into one node meet it at two
        // points rather than overdrawing each other for the last stretch. One
        // neighbour lands dead centre, which is what the single-parent effect
        // graph always had.
        const byCross = (a: string, b: string) =>
            at.get(a)!.cross - at.get(b)!.cross || a.localeCompare(b);
        const fanOut = new Map<string, string[]>();
        const fanIn = new Map<string, string[]>();
        for (const edge of forward) {
            fanOut.set(edge.from, [...(fanOut.get(edge.from) ?? []), edge.to]);
            fanIn.set(edge.to, [...(fanIn.get(edge.to) ?? []), edge.from]);
        }
        for (const [key, list] of fanOut) fanOut.set(key, list.sort(byCross));
        for (const [key, list] of fanIn) fanIn.set(key, list.sort(byCross));
        const fanned = (node: Placed, list: readonly string[], id: string) =>
            node.cross + (node.crossSize * (list.indexOf(id) + 1)) / (list.length + 1);

        // Edges sharing one corridor get distinct lanes so they never overdraw;
        // the lane index comes from a sorted key, not from encounter order.
        const corridors = new Map<number, string[]>();
        for (const edge of forward) {
            const corridor = at.get(edge.from)!.layer;
            corridors.set(corridor, [...(corridors.get(corridor) ?? []), `${edge.from} ${edge.to}`]);
        }
        for (const [key, list] of corridors) corridors.set(key, [...list].sort());

        const path = (points: readonly Flow[]) => {
            for (const point of points) note(point[1]);
            return points.map((point, index) => `${index === 0 ? "M" : "L"} ${pt(point)}`).join(" ");
        };
        const label = (
            flow: Flow,
            anchor: PlacedEdge["labelAnchor"],
            onLine: boolean,
        ): Pick<PlacedEdge, "labelX" | "labelY" | "labelAnchor" | "labelOnLine"> => {
            // Text sits above its baseline, so a label at y is ink up to y-9;
            // and beside a line, ink runs the allowance back from the anchor.
            note(
                down
                    ? flow[1] - (anchor === "end" ? sideLabelRoom : anchor === "middle" ? sideLabelRoom / 2 : 0)
                    : flow[1] - 9,
            );
            const screen = xy(flow);
            return { labelX: screen.x, labelY: screen.y, labelAnchor: anchor, labelOnLine: onLine };
        };

        const edges: PlacedEdge[] = [];
        let longIndex = 0;
        for (const edge of forward) {
            const from = at.get(edge.from)!;
            const to = at.get(edge.to)!;
            const corridor = corridors.get(from.layer) ?? [];
            const lane = corridor.indexOf(`${edge.from} ${edge.to}`);
            const lanes = Math.max(1, corridor.length);
            const a1 = from.along + from.alongSize;
            const c1 = fanned(from, fanOut.get(edge.from) ?? [], edge.to);
            const a2 = to.along;
            const c2 = fanned(to, fanIn.get(edge.to) ?? [], edge.from);
            // The jog lives in the gap between LAYERS, not between this node's
            // end and the next layer: a short node in a deep layer would
            // otherwise jog across its taller neighbour's face.
            const gapStart = layerEnd(from.layer);
            // Spread the turn across the gap rather than stacking every elbow
            // on the midpoint: with three `case` arms leaving one node, one
            // shared jog would read as a single line.
            const turn = gapStart + (alongGap * (lane + 1)) / (lanes + 1);
            if (to.layer - from.layer > 1) {
                // Around the figure, along its leading margin. Packed layers
                // leave no gap that is clear the whole way, and a run through
                // the node band reads as a line into everything it crosses.
                const laneC = bandStart - crossGap / 2 - longIndex * longLaneGap;
                longIndex += 1;
                const exit = gapStart + alongGap / 2;
                const entry = a2 - alongGap / 2;
                const d = path([[a1, c1], [exit, c1], [exit, laneC], [entry, laneC], [entry, c2], [a2, c2]]);
                const placedLabel = down
                    ? label([(exit + entry) / 2 + 4, laneC], "middle", true)
                    : label([(exit + entry) / 2, laneC - 4 - lane * labelStep], "middle", false);
                edges.push({ from: edge.from, to: edge.to, kind: "forward", path: d, ...placedLabel });
            } else {
                const straight = c1 === c2;
                const d = straight
                    ? path([[a1, c1], [a2, c2]])
                    : path([[a1, c1], [turn, c1], [turn, c2], [a2, c2]]);
                // Rightward the label rides beside the turn, staggered by lane:
                // sharing a corridor gives each edge its own turn, but that
                // only separates labels by alongGap/(lanes+1) — about 32px,
                // and `schema:WorkspaceReady` is four times that. Downward the
                // runs are vertical and text is not, so the label sits on the
                // line and knocks it out.
                const placedLabel = down
                    ? straight
                        ? label([(a1 + a2) / 2 + 4, c1], "middle", true)
                        : label([turn + 4, (c1 + c2) / 2], "middle", true)
                    : label([turn, Math.min(c1, c2) - 4 - lane * labelStep], "middle", false);
                edges.push({ from: edge.from, to: edge.to, kind: "forward", path: d, ...placedLabel });
            }
        }

        // Back edges run outside the whole figure on its trailing margin —
        // under it rightward, beside it downward. Drawn straight, they would
        // cross the node band against the flow and read as an edge into every
        // node on the way.
        backward.forEach((edge, index) => {
            const from = at.get(edge.from)!;
            const to = at.get(edge.to)!;
            const laneC = bandEnd + backLaneGap * (index + 1);
            const a1 = from.along + from.alongSize / 2;
            const a2 = to.along + to.alongSize / 2;
            const c1 = from.cross + from.crossSize;
            const c2 = to.cross + to.crossSize;
            const d = path([[a1, c1], [a1, laneC], [a2, laneC], [a2, c2]]);
            const placedLabel = down
                ? label([(a1 + a2) / 2 + 4, laneC + 4], "start", false)
                : label([(a1 + a2) / 2, laneC - 3], "middle", false);
            edges.push({ from: edge.from, to: edge.to, kind: "back", path: d, ...placedLabel });
        });

        // The self loop: a bump over the node's own leading edge, so a rule that
        // re-triggers on what it wrote says so on the node itself.
        for (const id of [...selfLooped].sort((a, b) => a.localeCompare(b))) {
            const node = at.get(id);
            if (!node) continue;
            const late = node.along + node.alongSize * 0.64;
            const early = node.along + node.alongSize * 0.36;
            const edge = node.cross;
            const rise = edge - loopRise;
            note(rise);
            const d = `M ${pt([late, edge])} C ${pt([late, rise])}, ${pt([early, rise])}, ${pt([early, edge])}`;
            const placedLabel = down
                ? label([node.along + node.alongSize / 2 + 4, rise - 3], "end", false)
                : label([node.along + node.alongSize / 2, rise - 1], "middle", false);
            edges.push({ from: id, to: id, kind: "self", path: d, ...placedLabel });
        }

        return { placed, edges, bandEnd, lowest };
    };

    const trial = build(0);
    const needed = Math.max(0, Math.ceil(padding - trial.lowest));
    const final = needed ? build(needed) : trial;

    const alongExtent =
        padding * 2 + layerExtent.reduce((sum, e) => sum + e, 0) + depth * alongGap;
    const crossExtent = final.bandEnd + padding + bottomPad;
    return {
        nodes: final.placed,
        edges: final.edges,
        width: down ? crossExtent : alongExtent,
        height: down ? alongExtent : crossExtent,
    };
}
