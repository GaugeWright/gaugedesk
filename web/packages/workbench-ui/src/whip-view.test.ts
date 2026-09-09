import { describe, expect, it } from "vitest";
import {
    firingSummary,
    instanceViewFromV0,
    isWhipProgram,
    programForPath,
    programsFromV1,
    slotLabel,
    structureFromV0,
    tabsForPath,
    type WhipFiring,
} from "./whip-view";

describe("tabsForPath", () => {
    it("gives a whip program the two extra views, in reading order", () => {
        expect(tabsForPath("gates/inbound.whip")).toEqual([
            "view",
            "structure",
            "instances",
            "edit",
            "diff",
        ]);
    });

    it("leaves every other file with the three tabs it always had", () => {
        expect(tabsForPath("README.md")).toEqual(["view", "edit", "diff"]);
        expect(tabsForPath(null)).toEqual(["view", "edit", "diff"]);
        // A file merely mentioning the extension is not a program.
        expect(tabsForPath("notes/about-whip-files.md")).toEqual(["view", "edit", "diff"]);
    });
});

describe("isWhipProgram", () => {
    it("is extension-based, because a program is a program before any instance exists", () => {
        expect(isWhipProgram("gates/inbound.whip")).toBe(true);
        expect(isWhipProgram("GATES/INBOUND.WHIP")).toBe(true);
        expect(isWhipProgram("gates/inbound.envelope")).toBe(false);
        expect(isWhipProgram(undefined)).toBe(false);
    });
});

describe("slotLabel", () => {
    it("never spells absence as a status", () => {
        // The point of the view: an effect with no runtime row must not read as
        // one more state beside `queued`. There is no row — that IS the finding.
        expect(slotLabel({ node: "closed", kind: "tracker.finish", binding: null, arm: null, absent: true }))
            .toBe("not requested");
        expect(slotLabel({ node: "hold", kind: "tracker.claim", binding: "hold", arm: null, status: "running" }))
            .toBe("running");
    });
});

describe("firingSummary", () => {
    const base: WhipFiring = {
        rule: "settle",
        identity: "p:Pending:5c7e10aa",
        commits: 1,
        programVersionId: "ver_1",
        structureAvailable: true,
        effects: [
            { node: "hold", kind: "tracker.claim", binding: "hold", arm: null, status: "running" },
            { node: "closed", kind: "tracker.finish", binding: null, arm: "hold:succeeds", absent: true },
        ],
    };

    it("counts what ran and what was never asked for", () => {
        expect(firingSummary(base)).toBe("1 commit · 1 ran · 1 never requested");
    });

    it("drops the absent clause when everything ran", () => {
        const done = { ...base, commits: 3, effects: [base.effects[0]!] };
        expect(firingSummary(done)).toBe("3 commits · 1 ran");
    });

    it("says so instead of counting when the structure is not recoverable", () => {
        // Without the program version's `.ir`, absence is not computable, and a
        // count would be a claim the projection cannot support.
        expect(firingSummary({ ...base, structureAvailable: false })).toBe(
            "1 commit · structure unavailable",
        );
    });
});

describe("reading whipplescript.instance_view.v0", () => {
    // A v0 document as `whip view --json` prints it: snake_case, arms carried
    // as a dependency list, absence as the absence of a runtime row.
    const V0 = {
        schema: "whipplescript.instance_view.v0",
        instance: { instance_id: "ins_1", status: "running", program_version_id: "ver_1", revision_epoch: 0, ir_hash: "ir-1" },
        program_versions_seen: ["ver_1"],
        structure: {
            available: true, program_version_id: "ver_1", ir_hash: "ir-1", workflow: "Demo",
            rules: [{
                name: "work", whens: ["started"],
                effects: [{ node: "first", kind: "exec.command", binding: "first" }, { node: "second", kind: "exec.command", binding: "second" }],
                dependencies: [{ upstream: "first", predicate: "succeeds", downstream: "second" }],
            }],
            rule_edges: [{ producer: "work", fact: "tracker:backlog", consumer: "work" }],
        },
        firings: [{
            rule: "work", identity: "p:1", commits: [{ event_id: "e1" }, { event_id: "e2" }],
            program_version_id: "ver_1", structure_available: true,
            effects: [
                { node: "first", kind: "exec.command", binding: "first", arm: null, effect_id: "k1", status: "completed", block_reason: null, block_category: null,
                  runs: [{ run_id: "r1", provider: "builtin", worker_id: "w", status: "completed", started_at: "t0", completed_at: "t1" }] },
                { node: "second", kind: "exec.command", binding: "second", arm: "first:succeeds", absent: true, predicted_effect_id: "k2" },
            ],
        }],
        absent_total: 1,
        unattributed_effects: [],
    };

    it("turns the dependency list into the arm each effect hangs off", () => {
        const structure = structureFromV0(V0.structure);
        expect(structure.available).toBe(true);
        expect(structure.rules[0]!.effects.map((e) => e.arm)).toEqual([null, "first:succeeds"]);
        expect(structure.ruleEdges).toEqual([{ producer: "work", fact: "tracker:backlog", consumer: "work" }]);
    });

    it("keeps absence as absence, and a run as a run", () => {
        const view = instanceViewFromV0(V0);
        expect(view.instanceId).toBe("ins_1");
        const [first, second] = view.firings[0]!.effects;
        expect(first!.status).toBe("completed");
        expect(first!.runs?.[0]?.completedAt).toBe("t1");
        expect(second!.absent).toBe(true);
        expect(second!.predictedEffectId).toBe("k2");
        expect(view.firings[0]!.commits).toBe(2);
        expect(view.absentTotal).toBe(1);
    });

    it("says structure is unavailable rather than inventing an empty one", () => {
        const structure = structureFromV0({ available: false, reason: "no .ir snapshot is stored" });
        expect(structure.available).toBe(false);
        expect(structure.reason).toContain("no .ir snapshot");
        expect(structure.rules).toEqual([]);
    });

    it("finds a file's program by path, and knows an agent package is not a file", () => {
        const programs = programsFromV1({
            whips: [
                { path: "gates/inbound.whip", program: "gate", chat: null, structure: V0.structure, instances: [V0] },
                { path: null, program: "office-worker", chat: "chat_1", structure: null, instances: [] },
            ],
        });
        expect(programForPath(programs, "/gates/inbound.whip")?.program).toBe("gate");
        expect(programForPath(programs, "README.md")).toBeUndefined();
        expect(programs[1]!.structure).toBeNull();
        expect(programs[0]!.instances[0]!.structure.workflow).toBe("Demo");
    });
});
