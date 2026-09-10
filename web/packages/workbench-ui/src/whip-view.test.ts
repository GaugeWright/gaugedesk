import { describe, expect, it } from "vitest";
import {
    effectHandle,
    firingSummary,
    headerLines,
    isTableRule,
    kindFamily,
    nodeSubtitle,
    nodeTitle,
    instanceViewFromV0,
    isWhipProgram,
    programForPath,
    programsFromV1,
    slotLabel,
    structureFromV0,
    structureSummary,
    tableName,
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
        expect(slotLabel({ node: "closed", kind: "tracker.finish", verb: "finish", label: null, binding: null, arm: null, absent: true }))
            .toBe("not requested");
        expect(slotLabel({ node: "hold", kind: "tracker.claim", verb: "claim", label: "hold", binding: "hold", arm: null, status: "running" }))
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
            { node: "hold", kind: "tracker.claim", verb: "claim", label: "hold", binding: "hold", arm: null, status: "running" },
            { node: "closed", kind: "tracker.finish", verb: "finish", label: null, binding: null, arm: "hold:succeeds", absent: true },
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
                effects: [
                    { node: "first", kind: "exec.command", verb: "exec", label: "first", binding: "first" },
                    { node: "second", kind: "exec.command", verb: "exec", label: "second", binding: "second" },
                ],
                dependencies: [{ upstream: "first", predicate: "succeeds", downstream: "second" }],
                records: [],
            }],
            rule_edges: [{ producer: "work", fact: "tracker:backlog", consumer: "work" }],
        },
        firings: [{
            rule: "work", identity: "p:1", commits: [{ event_id: "e1" }, { event_id: "e2" }],
            program_version_id: "ver_1", structure_available: true,
            effects: [
                { node: "first", kind: "exec.command", verb: "exec", label: "first", binding: "first", arm: null, effect_id: "k1", status: "completed", block_reason: null, block_category: null,
                  runs: [{ run_id: "r1", provider: "builtin", worker_id: "w", status: "completed", started_at: "t0", completed_at: "t1" }] },
                { node: "second", kind: "exec.command", verb: "exec", label: "second", binding: "second", arm: "first:succeeds", absent: true, predicted_effect_id: "k2" },
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

describe("naming an effect", () => {
    const then = { node: "__then_plan", kind: "agent.tell", verb: "tell", label: "plan" };
    const unbound = { node: "effect8", kind: "tracker.release", verb: "release", label: null };

    it("never puts a compiler-made name in a figure", () => {
        // `__then_plan` is a reserved handle the author is refused if they spell
        // it, and `effect8` is a lowering position. A picture showing either is
        // showing the reader the compiler's bookkeeping.
        expect(nodeTitle(then)).toBe("tell");
        expect(nodeSubtitle(then)).toBe("plan");
        expect(nodeTitle(unbound)).toBe("release");
    });

    it("falls back to the kind's family when the author named nothing", () => {
        // `renew` alone is ambiguous — a tracker's and a lease's both — so the
        // family is what an unnamed node shows instead of a name.
        expect(nodeSubtitle(unbound)).toBe("tracker");
        expect(kindFamily("lease.renew")).toBe("lease");
        // A kind with no family is its own family rather than an empty line.
        expect(kindFamily("invented")).toBe("invented");
    });

    it("keeps the node id where text has no position to disambiguate by", () => {
        // Two `release` lines in a note list are worse than one `effect8`.
        expect(effectHandle(unbound)).toBe("effect8");
        expect(effectHandle(then)).toBe("plan");
    });
});

describe("headerLines", () => {
    it("gives a guard its own line, so the trigger is never what falls off", () => {
        const lines = headerLines(["Incident as incident where incident.severity >= 2"]);
        expect(lines).toEqual([
            { keyword: "when", text: "Incident as incident", full: null },
            { keyword: "where", text: "incident.severity >= 2", full: null },
        ]);
    });

    it("elides a long guard and keeps the whole clause for the tooltip", () => {
        const guard =
            '(((incident.severity >= 2) && ("route" in incident.metadata)) && (incident.metadata["route"] in ["code", "review", "ops"]))';
        const [pattern, where] = headerLines([`Incident as incident where ${guard}`]);
        // The pattern is short and survives whole; the guard is what would have
        // made this rule's box eleven hundred pixels wide.
        expect(pattern).toEqual({ keyword: "when", text: "Incident as incident", full: null });
        expect(where!.text.endsWith("…")).toBe(true);
        expect(where!.text.length).toBeLessThanOrEqual(44);
        expect(where!.full).toBe(guard);
    });

    it("leaves a guardless trigger as one line", () => {
        expect(headerLines(["started", "triager is available"])).toEqual([
            { keyword: "when", text: "started", full: null },
            { keyword: "when", text: "triager is available", full: null },
        ]);
    });
});

describe("telling a table from behaviour", () => {
    const table = {
        name: "table_tickets",
        whens: ["started"],
        effects: [],
        records: [{ schema: "Ticket", construct: "table_row" }],
    };

    it("reads a table declaration's lowered rule as the data it is", () => {
        expect(isTableRule(table)).toBe(true);
        // The prefix belongs to the lowering, not to whoever wrote `table tickets`.
        expect(tableName(table)).toBe("tickets");
    });

    it("does not claim a rule that acts, or one that records by hand", () => {
        expect(isTableRule({ ...table, effects: [{}] })).toBe(false);
        expect(isTableRule({ ...table, records: [] })).toBe(false);
        expect(
            isTableRule({ ...table, records: [{ schema: "Ticket", construct: "send" }] }),
        ).toBe(false);
    });
});

describe("structureSummary", () => {
    const table = {
        name: "table_tickets",
        whens: [],
        effects: [],
        binding: null,
        records: [{ schema: "Ticket", construct: "table_row" }],
    };
    const rule = { name: "triage", whens: [], effects: [], records: [] };

    it("counts tables apart from rules, because the figure draws them apart", () => {
        expect(
            structureSummary({ rules: [table, rule], ruleEdges: [{}] } as never),
        ).toBe("1 rule · 1 coupling · 1 table");
    });

    it("says nothing about tables in a program that has none", () => {
        expect(structureSummary({ rules: [rule, rule], ruleEdges: [{}, {}, {}] } as never)).toBe(
            "2 rules · 3 couplings",
        );
    });
});

describe("reading the author's words out of v0", () => {
    it("carries the verb, the label and the record sources through", () => {
        const structure = structureFromV0({
            available: true,
            workflow: "TriageChain",
            rules: [
                {
                    name: "triage_ticket",
                    whens: ["Ticket as ticket"],
                    effects: [
                        {
                            node: "__then_plan",
                            kind: "agent.tell",
                            verb: "tell",
                            label: "plan",
                            binding: "__then_plan",
                        },
                    ],
                    dependencies: [],
                    records: [],
                },
                {
                    name: "table_tickets",
                    whens: ["started"],
                    effects: [],
                    dependencies: [],
                    records: [{ schema: "Ticket", construct: "table_row" }],
                },
            ],
            rule_edges: [],
        });
        const [chained, table] = structure.rules;
        expect(chained!.effects[0]!.verb).toBe("tell");
        expect(chained!.effects[0]!.label).toBe("plan");
        // The binding is untouched: the arm names it and the graph's edges are
        // resolved through it.
        expect(chained!.effects[0]!.binding).toBe("__then_plan");
        expect(table!.records).toEqual([{ schema: "Ticket", construct: "table_row" }]);
    });

    it("shows the kind rather than inventing a verb when the runtime sends none", () => {
        // This desk pins the runtime that fills these in, so a node reading
        // `tracker.release` where a verb belongs says the pin is behind.
        const structure = structureFromV0({
            available: true,
            rules: [
                {
                    name: "old",
                    whens: [],
                    effects: [{ node: "effect1", kind: "tracker.release", binding: "-" }],
                    dependencies: [],
                },
            ],
            rule_edges: [],
        });
        const effect = structure.rules[0]!.effects[0]!;
        expect(effect.verb).toBe("tracker.release");
        expect(effect.label).toBeNull();
        expect(structure.rules[0]!.records).toEqual([]);
    });
});
