import { describe, expect, it } from "vitest";
import { layout, type LayoutInput } from "./whip-dag-layout";

const OPTIONS = {
    nodeWidth: 100,
    nodeHeight: 40,
    columnGap: 50,
    rowGap: 12,
    padding: 8,
};

/** `implement_ready_ticket` from gastown-lite: nine effects, two fan-outs (a
 *  lease with held/contended arms, a `case` with three), which is the shape the
 *  first layout collapsed. */
const GASTOWN: LayoutInput[] = [
    { id: "claimed", upstream: null },
    { id: "slot", upstream: "claimed" },
    { id: "turn", upstream: "slot" },
    { id: "effect4", upstream: "slot" },
    { id: "review", upstream: "turn" },
    { id: "log_entry", upstream: "review" },
    { id: "effect7", upstream: "log_entry" },
    { id: "effect8", upstream: "log_entry" },
    { id: "effect9", upstream: "log_entry" },
];

describe("layering", () => {
    it("puts every effect one past what it waits on", () => {
        const result = layout(GASTOWN, OPTIONS);
        const layerOf = new Map(result.nodes.map((node) => [node.id, node.layer]));
        expect(layerOf.get("claimed")).toBe(0);
        expect(layerOf.get("slot")).toBe(1);
        expect(layerOf.get("turn")).toBe(2);
        expect(layerOf.get("effect4")).toBe(2);
        expect(layerOf.get("log_entry")).toBe(4);
        // The three case arms share a layer: they are alternatives, and drawing
        // them in a column is what says so.
        for (const arm of ["effect7", "effect8", "effect9"]) {
            expect(layerOf.get(arm)).toBe(5);
        }
    });

    it("never draws an effect left of the one it waits on", () => {
        const result = layout(GASTOWN, OPTIONS);
        const xOf = new Map(result.nodes.map((node) => [node.id, node.x]));
        for (const node of GASTOWN) {
            if (!node.upstream) continue;
            expect(xOf.get(node.id)!).toBeGreaterThan(xOf.get(node.upstream)!);
        }
    });
});

describe("no two nodes share a slot", () => {
    it("gives siblings distinct rows", () => {
        const result = layout(GASTOWN, OPTIONS);
        const seen = new Set(result.nodes.map((node) => `${node.x},${node.y}`));
        expect(seen.size).toBe(GASTOWN.length);
    });
});

describe("determinism", () => {
    // The property that makes this a layout ENGINE rather than a heuristic: one
    // program draws identically every time, for every reader, in every
    // screenshot. Input order must not reach the output.
    const shuffle = <T>(items: readonly T[], seed: number): T[] => {
        const copy = [...items];
        let state = seed;
        for (let i = copy.length - 1; i > 0; i -= 1) {
            state = (state * 1103515245 + 12345) % 2147483648;
            const j = state % (i + 1);
            [copy[i], copy[j]] = [copy[j]!, copy[i]!];
        }
        return copy;
    };

    it("is byte-identical however the input is ordered", () => {
        const reference = JSON.stringify(layout(GASTOWN, OPTIONS));
        for (const seed of [1, 7, 42, 1337, 99991]) {
            expect(JSON.stringify(layout(shuffle(GASTOWN, seed), OPTIONS))).toBe(reference);
        }
    });

    it("is stable across repeated calls", () => {
        const once = JSON.stringify(layout(GASTOWN, OPTIONS));
        const twice = JSON.stringify(layout(GASTOWN, OPTIONS));
        expect(twice).toBe(once);
    });
});

describe("edge routing", () => {
    it("gives each edge out of one node its own turn, so they do not overdraw", () => {
        const result = layout(GASTOWN, OPTIONS);
        const arms = result.edges.filter((edge) => edge.from === "log_entry");
        expect(arms).toHaveLength(3);
        const turns = new Set(arms.map((edge) => edge.labelX));
        expect(turns.size).toBe(3);
    });

    it("draws a straight line when a node sits level with its upstream", () => {
        const result = layout(
            [
                { id: "a", upstream: null },
                { id: "b", upstream: "a" },
            ],
            OPTIONS,
        );
        // One child, one row each: an elbow here would be a kink with no cause.
        expect(result.edges[0]!.path).toBe("M 108 28 L 158 28");
    });
});

describe("total on graphs it should not receive", () => {
    it("roots a node whose upstream is not in the set", () => {
        // A snapshot from a newer compiler can name an arm this build does not
        // know. Dropping the node would silently shrink the program.
        const result = layout(
            [
                { id: "a", upstream: null },
                { id: "orphan", upstream: "missing" },
            ],
            OPTIONS,
        );
        expect(result.nodes).toHaveLength(2);
        expect(result.nodes.find((node) => node.id === "orphan")!.layer).toBe(0);
        expect(result.edges).toHaveLength(0);
    });

    it("terminates on a cycle rather than recursing forever", () => {
        const result = layout(
            [
                { id: "a", upstream: "b" },
                { id: "b", upstream: "a" },
            ],
            OPTIONS,
        );
        expect(result.nodes).toHaveLength(2);
    });

    it("returns an empty layout for an empty graph", () => {
        expect(layout([], OPTIONS)).toEqual({ nodes: [], edges: [], width: 0, height: 0 });
    });
});

/** The rule graph, which is where the general cases come from. A rule matches
 *  several facts and so has several producers; a rule that writes a fact it
 *  also matches re-triggers itself; and two rules can feed each other, which
 *  DR-0081 admits when the cycle is paced. None of this occurs in an effect
 *  graph, and all of it has to draw. */
describe("multiple upstreams", () => {
    const RULES: LayoutInput[] = [
        { id: "table_workspaces", upstreams: [] },
        { id: "file_ticket", upstreams: [] },
        { id: "implement", upstreams: ["table_workspaces", "file_ticket", "implement"] },
        { id: "report", upstreams: ["implement"] },
    ];

    it("puts a node past the DEEPEST thing it waits on, not the first", () => {
        const result = layout(RULES, OPTIONS);
        const layerOf = new Map(result.nodes.map((node) => [node.id, node.layer]));
        expect(layerOf.get("table_workspaces")).toBe(0);
        expect(layerOf.get("file_ticket")).toBe(0);
        expect(layerOf.get("implement")).toBe(1);
        expect(layerOf.get("report")).toBe(2);
    });

    it("draws an edge from every producer, not just one", () => {
        const result = layout(RULES, OPTIONS);
        const into = result.edges.filter((edge) => edge.to === "implement" && edge.kind === "forward");
        expect(into.map((edge) => edge.from).sort()).toEqual(["file_ticket", "table_workspaces"]);
    });

    it("still accepts the single-upstream sugar, and mixes the two", () => {
        const result = layout(
            [
                { id: "a", upstream: null },
                { id: "b", upstream: "a" },
                { id: "c", upstreams: ["a", "b"] },
            ],
            OPTIONS,
        );
        expect(result.nodes.find((node) => node.id === "c")!.layer).toBe(2);
        expect(result.edges.filter((edge) => edge.to === "c")).toHaveLength(2);
    });
});

describe("a rule that feeds itself", () => {
    // The absence of this line would read as "this rule runs once", which is
    // the opposite of what a self-coupled rule does.
    const SELF: LayoutInput[] = [
        { id: "seed", upstreams: [] },
        { id: "implement", upstreams: ["seed", "implement"] },
    ];

    it("draws a loop rather than dropping the edge", () => {
        const result = layout(SELF, OPTIONS);
        const loop = result.edges.filter((edge) => edge.kind === "self");
        expect(loop).toHaveLength(1);
        expect(loop[0]!.from).toBe("implement");
        expect(loop[0]!.to).toBe("implement");
    });

    it("does not let the self-reference push the node a layer right", () => {
        // Waiting on yourself is not depth. Counting it would put every
        // self-coupled rule one column further out for no reason.
        const result = layout(SELF, OPTIONS);
        expect(result.nodes.find((node) => node.id === "implement")!.layer).toBe(1);
    });

    it("buys headroom so the loop is not clipped by the top of the figure", () => {
        const withLoop = layout(SELF, OPTIONS);
        const withoutLoop = layout(
            [
                { id: "seed", upstreams: [] },
                { id: "implement", upstreams: ["seed"] },
            ],
            OPTIONS,
        );
        const topOf = (result: ReturnType<typeof layout>) =>
            Math.min(...result.nodes.map((node) => node.y));
        expect(topOf(withLoop)).toBeGreaterThan(topOf(withoutLoop));
        const loop = withLoop.edges.find((edge) => edge.kind === "self")!;
        // Every y on the loop path must be inside the figure.
        for (const y of [...loop.path.matchAll(/[ ,](-?\d+(?:\.\d+)?)(?=[ ,]|$)/g)]
            .map((match) => Number(match[1]))
            .filter((_, index) => index % 2 === 1)) {
            expect(y).toBeGreaterThanOrEqual(0);
        }
    });
});

describe("a cycle between two rules", () => {
    const PACED: LayoutInput[] = [
        { id: "propose", upstreams: ["revise"] },
        { id: "revise", upstreams: ["propose"] },
    ];

    it("routes the returning edge under the figure, not back across it", () => {
        const result = layout(PACED, OPTIONS);
        const back = result.edges.filter((edge) => edge.kind === "back");
        expect(back).toHaveLength(1);
        const band = Math.max(...result.nodes.map((node) => node.y)) + OPTIONS.nodeHeight;
        // Its horizontal run is below every node, which is the whole point: a
        // leftward line through the band reads as an edge into what it crosses.
        const ys = [...back[0]!.path.matchAll(/L (-?[\d.]+) (-?[\d.]+)/g)].map((m) => Number(m[2]));
        expect(Math.max(...ys)).toBeGreaterThan(band);
    });

    it("makes room for it rather than drawing outside the figure", () => {
        const result = layout(PACED, OPTIONS);
        const ys = [...result.edges
            .filter((edge) => edge.kind === "back")[0]!
            .path.matchAll(/L (-?[\d.]+) (-?[\d.]+)/g)].map((m) => Number(m[2]));
        expect(result.height).toBeGreaterThanOrEqual(Math.max(...ys));
    });

    it("gives each returning edge its own lane", () => {
        const result = layout(
            [
                { id: "a", upstreams: ["c"] },
                { id: "b", upstreams: ["a"] },
                { id: "c", upstreams: ["b"] },
                { id: "d", upstreams: ["b", "c"] },
            ],
            OPTIONS,
        );
        const back = result.edges.filter((edge) => edge.kind === "back");
        const lanes = new Set(back.map((edge) => edge.labelY));
        expect(lanes.size).toBe(back.length);
    });
});

describe("an edge that spans more than one layer", () => {
    // Drawn as a plain elbow it would run through whatever sits between, and
    // a line crossing a node is indistinguishable from a line into it.
    // Three in the middle layer, because layers are centred: with two, a
    // naive elbow from `a` would pass between them and this would prove
    // nothing. With three, `a` sits over the middle one.
    const SKIP: LayoutInput[] = [
        { id: "a", upstreams: [] },
        { id: "b", upstreams: ["a"] },
        { id: "mid", upstreams: ["a"] },
        { id: "mid2", upstreams: ["a"] },
        { id: "c", upstreams: ["b", "a"] },
    ];

    /** Every point on a routed path, in order. */
    const points = (path: string): { x: number; y: number }[] =>
        [...path.matchAll(/[ML] (-?[\d.]+) (-?[\d.]+)/g)].map((match) => ({
            x: Number(match[1]),
            y: Number(match[2]),
        }));

    it("never runs a segment through a node it does not touch", () => {
        // The property that matters is CROSSING, on both axes at once: the
        // stub leaving a node is level with it and perfectly fine, because it
        // lives in the column gap. A run at the same y that reaches into
        // another node's column is the defect.
        const result = layout(SKIP, OPTIONS);
        const long = result.edges.find((edge) => edge.from === "a" && edge.to === "c")!;
        const boxes = result.nodes
            .filter((node) => node.id !== "a" && node.id !== "c")
            .map((node) => ({
                left: node.x,
                right: node.x + OPTIONS.nodeWidth,
                top: node.y,
                bottom: node.y + OPTIONS.nodeHeight,
            }));
        const path = points(long.path);
        for (let i = 1; i < path.length; i += 1) {
            const from = path[i - 1]!;
            const to = path[i]!;
            for (const box of boxes) {
                const overlapsX =
                    Math.min(from.x, to.x) < box.right && Math.max(from.x, to.x) > box.left;
                const overlapsY =
                    Math.min(from.y, to.y) < box.bottom && Math.max(from.y, to.y) > box.top;
                expect(overlapsX && overlapsY).toBe(false);
            }
        }
    });

    it("would cross one if it were drawn as a plain elbow", () => {
        // Guards the guard: without this, the test above passes on a graph
        // where nothing was ever in the way and proves nothing.
        const result = layout(SKIP, OPTIONS);
        const a = result.nodes.find((node) => node.id === "a")!;
        const c = result.nodes.find((node) => node.id === "c")!;
        const naiveY = a.y + OPTIONS.nodeHeight / 2;
        const struck = result.nodes.filter(
            (node) =>
                node.layer > a.layer &&
                node.layer < c.layer &&
                naiveY > node.y &&
                naiveY < node.y + OPTIONS.nodeHeight,
        );
        expect(struck.map((node) => node.id)).toEqual(["mid"]);
    });
});

describe("determinism holds for the general graph too", () => {
    const MESSY: LayoutInput[] = [
        { id: "table_workspaces", upstreams: [] },
        { id: "file_ticket", upstreams: [] },
        { id: "implement", upstreams: ["table_workspaces", "file_ticket", "implement"] },
        { id: "escalate", upstreams: ["implement"] },
        { id: "reopen", upstreams: ["escalate"] },
        { id: "file_ticket_again", upstreams: ["reopen", "file_ticket"] },
    ];

    it("is byte-identical however the input is ordered", () => {
        const shuffle = <T,>(items: readonly T[], seed: number): T[] => {
            const copy = [...items];
            let state = seed;
            for (let i = copy.length - 1; i > 0; i -= 1) {
                state = (state * 1103515245 + 12345) % 2147483648;
                const j = state % (i + 1);
                [copy[i], copy[j]] = [copy[j]!, copy[i]!];
            }
            return copy;
        };
        const reference = JSON.stringify(layout(MESSY, OPTIONS));
        for (const seed of [3, 11, 64, 2048, 70001]) {
            expect(JSON.stringify(layout(shuffle(MESSY, seed), OPTIONS))).toBe(reference);
        }
    });
});

describe("edge labels do not overprint", () => {
    // Found on screen, not by a test: `held` and `contended` leaving one node
    // landed at the same height 32px apart and smeared into each other, and so
    // did two fact names on the rule graph. Distinct turns are not enough —
    // a label is wider than the turn spacing.
    it("gives every edge out of one node its own label height", () => {
        const result = layout(GASTOWN, OPTIONS);
        const arms = result.edges.filter((edge) => edge.from === "log_entry");
        expect(arms).toHaveLength(3);
        expect(new Set(arms.map((edge) => edge.labelY)).size).toBe(3);
    });

    it("separates two edges into one node as well", () => {
        const result = layout(
            [
                { id: "a", upstreams: [] },
                { id: "b", upstreams: [] },
                { id: "hub", upstreams: ["a", "b"] },
            ],
            OPTIONS,
        );
        const into = result.edges.filter((edge) => edge.to === "hub");
        expect(into).toHaveLength(2);
        expect(into[0]!.labelY).not.toBe(into[1]!.labelY);
    });

    it("keeps every label inside the figure, however far they stagger", () => {
        // The stagger lifts labels, so the figure has to buy the headroom or
        // the top one is clipped by the viewBox and simply not there.
        for (const graph of [
            GASTOWN,
            [
                { id: "a", upstreams: [] },
                { id: "b", upstreams: [] },
                { id: "c", upstreams: [] },
                { id: "d", upstreams: [] },
                { id: "hub", upstreams: ["a", "b", "c", "d"] },
            ],
        ]) {
            const result = layout(graph, OPTIONS);
            for (const edge of result.edges) {
                // A label's ink reaches about 9px above its baseline.
                expect(edge.labelY - 9).toBeGreaterThanOrEqual(0);
            }
            for (const node of result.nodes) expect(node.y).toBeGreaterThanOrEqual(0);
        }
    });

    it("spends no headroom on a figure that needs none", () => {
        // The correction is measured, not reserved: a graph whose labels all
        // sit inside the band must place exactly where it always did.
        const plain = layout(
            [
                { id: "a", upstream: null },
                { id: "b", upstream: "a" },
            ],
            OPTIONS,
        );
        expect(plain.nodes.every((node) => node.y === OPTIONS.padding)).toBe(true);
    });
});

describe("downward flow", () => {
    const DOWN = { ...OPTIONS, direction: "down" as const };

    it("puts layers in rows and siblings side by side", () => {
        const result = layout(GASTOWN, DOWN);
        const at = new Map(result.nodes.map((node) => [node.id, node]));
        expect(at.get("slot")!.y).toBeGreaterThan(at.get("claimed")!.y);
        expect(at.get("turn")!.y).toBeGreaterThan(at.get("slot")!.y);
        // The three case arms are alternatives: one row, three columns.
        const arms = ["effect7", "effect8", "effect9"].map((id) => at.get(id)!);
        expect(new Set(arms.map((node) => node.y)).size).toBe(1);
        expect(new Set(arms.map((node) => node.x)).size).toBe(3);
    });

    it("never draws an effect above the one it waits on", () => {
        const result = layout(GASTOWN, DOWN);
        const yOf = new Map(result.nodes.map((node) => [node.id, node.y]));
        for (const node of GASTOWN) {
            if (!node.upstream) continue;
            expect(yOf.get(node.id)!).toBeGreaterThan(yOf.get(node.upstream)!);
        }
    });

    it("is the same algorithm: transposing the options transposes the nodes", () => {
        // Rightward with (w, h, colGap, rowGap) and downward with those swapped
        // must place every node at mirrored coordinates. If they differ, the
        // two directions have drifted into two engines. The one thing allowed
        // to differ is the headroom the labels ask for, which shifts the cross
        // axis uniformly — so cross positions compare relative to one node.
        const right = layout(GASTOWN, OPTIONS);
        const down = layout(GASTOWN, {
            ...OPTIONS,
            nodeWidth: OPTIONS.nodeHeight,
            nodeHeight: OPTIONS.nodeWidth,
            columnGap: OPTIONS.rowGap,
            rowGap: OPTIONS.columnGap,
            direction: "down",
        });
        const downAt = new Map(down.nodes.map((node) => [node.id, node]));
        const rightAt = new Map(right.nodes.map((node) => [node.id, node]));
        const rightOrigin = rightAt.get("claimed")!.y;
        const downOrigin = downAt.get("claimed")!.x;
        for (const node of right.nodes) {
            expect(downAt.get(node.id)!.y).toBe(node.x);
            expect(downAt.get(node.id)!.x - downOrigin).toBe(node.y - rightOrigin);
        }
        expect(down.height).toBe(right.width);
    });

    it("is byte-identical however the input is ordered", () => {
        const reference = JSON.stringify(layout(GASTOWN, DOWN));
        const shuffled = [...GASTOWN].reverse();
        expect(JSON.stringify(layout(shuffled, DOWN))).toBe(reference);
    });

    it("keeps the rightward output exactly as it was", () => {
        // The direction option must be invisible to a caller who never asked
        // for it: same options, same path, to the pixel.
        const result = layout(
            [
                { id: "a", upstream: null },
                { id: "b", upstream: "a" },
            ],
            { ...OPTIONS, direction: "right" },
        );
        expect(result.edges[0]!.path).toBe("M 108 28 L 158 28");
    });
});

describe("nodes of different sizes", () => {
    const sizes: Record<string, { width: number; height: number }> = {
        small: { width: 100, height: 40 },
        big: { width: 300, height: 200 },
        other: { width: 120, height: 40 },
    };
    const SIZED = {
        ...OPTIONS,
        direction: "down" as const,
        sizeOf: (id: string) => sizes[id]!,
    };
    const GRAPH: LayoutInput[] = [
        { id: "small", upstream: null },
        { id: "other", upstream: null },
        { id: "big", upstreams: ["small", "other"] },
    ];

    it("reports each node at its own extent", () => {
        const result = layout(GRAPH, SIZED);
        const big = result.nodes.find((node) => node.id === "big")!;
        expect([big.width, big.height]).toEqual([300, 200]);
    });

    it("makes a layer as deep as its deepest node, so the next layer clears it", () => {
        const result = layout(GRAPH, SIZED);
        const at = new Map(result.nodes.map((node) => [node.id, node]));
        // `big` is alone in layer 1; nothing below it, so the figure ends
        // exactly one padding past its bottom edge.
        expect(result.height).toBe(at.get("big")!.y + 200 + OPTIONS.padding);
    });

    it("packs each layer and centres it on the widest", () => {
        // Layer 0 is `other` (120) then `small` (100) with the column gap
        // between, 270 wide; layer 1 is `big` alone at 300. The narrow layer
        // is centred over the wide one: fifteen in from each side, not pushed
        // out beside it. That is the difference between a figure the width of
        // its widest box and one twice that.
        const result = layout(GRAPH, SIZED);
        const at = new Map(result.nodes.map((node) => [node.id, node]));
        expect(at.get("other")!.x).toBe(at.get("big")!.x + (300 - 270) / 2);
        expect(at.get("small")!.x).toBe(at.get("other")!.x + 120 + OPTIONS.columnGap);
        expect(result.width).toBe(300 + OPTIONS.padding * 2);
    });

    it("draws the edge from the source's bottom to the target's top", () => {
        const result = layout(GRAPH, SIZED);
        const at = new Map(result.nodes.map((node) => [node.id, node]));
        const edge = result.edges.find((e) => e.from === "small" && e.to === "big")!;
        const small = at.get("small")!;
        const big = at.get("big")!;
        // `small` has one child, so it leaves from its own centre. `big` has
        // two parents and `small` is the right-hand one, so it lands two
        // thirds of the way along `big`'s top edge — fanned, not stacked on
        // the centre where `other`'s edge already lands.
        expect(edge.path.startsWith(`M ${small.x + 50} ${small.y + 40}`)).toBe(true);
        expect(edge.path.endsWith(`L ${big.x + 200} ${big.y}`)).toBe(true);
    });
});
