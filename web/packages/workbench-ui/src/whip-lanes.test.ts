import { describe, expect, it } from "vitest";
import { groupFirings, laneColumns, laneLabel } from "./whip-lanes";
import type { WhipFiring } from "./whip-view";

const slot = (node: string, arm: string | null, extra: Record<string, unknown> = {}) => ({
    node,
    kind: `kind.${node}`,
    binding: node,
    arm,
    ...extra,
});

const firing = (
    rule: string,
    identity: string,
    programVersionId: string,
    effects: readonly ReturnType<typeof slot>[] = [slot("a", null)],
): WhipFiring =>
    ({
        rule,
        identity,
        commits: 1,
        programVersionId,
        structureAvailable: true,
        effects,
    }) as WhipFiring;

describe("groupFirings", () => {
    it("keeps firings of one rule and one program version together", () => {
        const groups = groupFirings([
            firing("implement", "a", "ver_1"),
            firing("implement", "b", "ver_1"),
            firing("implement", "c", "ver_1"),
        ]);
        expect(groups).toHaveLength(1);
        expect(groups[0]!.firings).toHaveLength(3);
    });

    it("splits on the rule, because two rules have different effects entirely", () => {
        const groups = groupFirings([
            firing("implement", "a", "ver_1"),
            firing("file_ticket", "b", "ver_1"),
        ]);
        expect(groups.map((group) => group.rule)).toEqual(["implement", "file_ticket"]);
    });

    it("splits on the program version, because a revision moves the columns", () => {
        // An instance revised while running has firings against two programs.
        // One grid would align a column of one against a column of the other
        // and the alignment would be a lie.
        const groups = groupFirings([
            firing("implement", "a", "ver_1"),
            firing("implement", "b", "ver_2"),
        ]);
        expect(groups).toHaveLength(2);
        expect(groups.map((group) => group.programVersionId)).toEqual(["ver_1", "ver_2"]);
    });

    it("never reorders firings within a group", () => {
        // The grid reads top to bottom as time; sorting it would destroy that
        // without saying so.
        const groups = groupFirings([
            firing("implement", "third", "ver_1"),
            firing("implement", "first", "ver_1"),
            firing("implement", "second", "ver_1"),
        ]);
        expect(groups[0]!.firings.map((one) => one.identity)).toEqual([
            "third",
            "first",
            "second",
        ]);
    });

    it("returns nothing for no firings", () => {
        expect(groupFirings([])).toEqual([]);
    });
});

describe("laneColumns", () => {
    const EFFECTS = [
        slot("claimed", null),
        slot("slot", "claimed:succeeds"),
        slot("turn", "slot:held"),
        slot("release_held", "slot:contended"),
        slot("review", "turn:succeeds"),
    ];

    it("orders columns the way the graph draws them, so the two views agree", () => {
        const columns = laneColumns([firing("implement", "a", "ver_1", EFFECTS)]);
        expect(columns.map((column) => column.node)).toEqual([
            "claimed",
            "slot",
            "release_held",
            "turn",
            "review",
        ]);
        expect(columns.map((column) => column.layer)).toEqual([0, 1, 2, 2, 3]);
    });

    it("takes the union, so a column never vanishes because one firing lacks it", () => {
        // A firing keyed against a program this build cannot fully resolve may
        // carry fewer slots. Dropping the column would take the evidence with
        // it, and the reader would never learn the effect exists.
        const columns = laneColumns([
            firing("implement", "a", "ver_1", [slot("claimed", null)]),
            firing("implement", "b", "ver_1", EFFECTS),
        ]);
        expect(columns.map((column) => column.node)).toContain("review");
        expect(columns).toHaveLength(5);
    });

    it("is independent of the order the firings arrive in", () => {
        const forward = laneColumns([
            firing("implement", "a", "ver_1", EFFECTS),
            firing("implement", "b", "ver_1", [slot("claimed", null)]),
        ]);
        const backward = laneColumns([
            firing("implement", "b", "ver_1", [slot("claimed", null)]),
            firing("implement", "a", "ver_1", EFFECTS),
        ]);
        expect(backward).toEqual(forward);
    });

    it("returns no columns when there are no effects to draw", () => {
        expect(laneColumns([])).toEqual([]);
        expect(laneColumns([firing("implement", "a", "ver_1", [])])).toEqual([]);
    });
});

describe("laneLabel", () => {
    it("takes the part of the identity that differs between rows", () => {
        expect(
            laneLabel(firing("implement", "issue:backlog:GT-204|ready:WorkspaceReady:c118", "v")),
        ).toBe("GT-204");
    });

    it("falls back to the identity rather than to nothing", () => {
        expect(laneLabel(firing("implement", "started", "v"))).toBe("started");
    });
});

describe("a batch of firings is what makes lanes worth drawing", () => {
    // Twelve firings of one rule against one program, eight of them held off a
    // one-slot lease. This was a fixture instance before the Instances tab read
    // real stores; the shape is kept here because it is the shape the grid
    // exists for, and a unit test can construct it where a browser cannot.
    const held = (issue: string): WhipFiring =>
        firing("implement", `issue:backlog:${issue}`, "ver_1", [
            slot("claimed", null, { status: "completed" }),
            slot("slot", "claimed:succeeds", {
                status: "blocked_by_capacity",
                blockReason: "workspace_slot/checkout is held by GT-201",
            }),
            slot("turn", "slot:held", { absent: true }),
            slot("log_entry", "turn:succeeds", { absent: true }),
        ]);
    const through = (issue: string): WhipFiring =>
        firing("implement", `issue:backlog:${issue}`, "ver_1", [
            slot("claimed", null, { status: "completed" }),
            slot("slot", "claimed:succeeds", { status: "completed" }),
            slot("turn", "slot:held", { status: "completed" }),
            slot("log_entry", "turn:succeeds", { status: "completed" }),
        ]);
    const batch = [
        through("GT-201"), through("GT-202"), through("GT-203"), through("GT-204"),
        held("GT-205"), held("GT-206"), held("GT-207"), held("GT-208"),
        held("GT-209"), held("GT-210"), held("GT-211"), held("GT-212"),
    ];

    it("is one instance with many firings of one rule, so it lanes", () => {
        const groups = groupFirings(batch);
        expect(groups).toHaveLength(1);
        expect(groups[0]!.firings.length).toBeGreaterThan(6);
    });

    it("has a column that is the finding: most of them stuck on the lease", () => {
        // The pattern a stack of graphs hides and a grid states.
        const blocked = batch.filter((one) =>
            one.effects.some(
                (effect) => effect.node === "slot" && effect.status === "blocked_by_capacity",
            ),
        );
        expect(blocked.length).toBeGreaterThanOrEqual(8);
        for (const one of blocked) {
            expect(
                one.effects.find((effect) => effect.node === "slot")!.blockReason,
            ).toContain("workspace_slot");
        }
    });

    it("still has firings that got through, or the column would prove nothing", () => {
        const settled = batch.filter((one) =>
            one.effects.some(
                (effect) => effect.node === "log_entry" && effect.status === "completed",
            ),
        );
        expect(settled.length).toBeGreaterThan(0);
    });

    it("shares one column set across every row, blocked or not", () => {
        const columns = laneColumns(batch);
        expect(columns.map((column) => column.node)).toEqual(["claimed", "slot", "turn", "log_entry"]);
    });
});

describe("a group whose structure is not recoverable", () => {
    // Same refusal `firingSummary` makes for one firing. Absence is computed
    // against the compiled program; without it there is nothing to count, and
    // a number here would be a claim the projection cannot support.
    it("is grouped like any other, because grouping does not need the structure", () => {
        const groups = groupFirings([
            { ...firing("implement", "a", "ver_1"), structureAvailable: false } as WhipFiring,
            { ...firing("implement", "b", "ver_1"), structureAvailable: false } as WhipFiring,
        ]);
        expect(groups).toHaveLength(1);
        expect(groups[0]!.firings).toHaveLength(2);
    });

    it("still yields columns, so the rows that DID run are not hidden", () => {
        const columns = laneColumns([
            { ...firing("implement", "a", "ver_1"), structureAvailable: false } as WhipFiring,
        ]);
        expect(columns.map((column) => column.node)).toEqual(["a"]);
    });
});
