import { describe, expect, it } from "vitest";
import { ruleBox, tableSummary, type RuleNode } from "./WhipStructureGraph";

/** `incident-router`'s real guard, which is what made this worth bounding. */
const LONG_GUARD =
    '(((incident.severity >= 2) && ("route" in incident.metadata)) && (incident.metadata["route"] in ["code", "review", "ops"])) && ((incident.owner == null) || exists(incident.owner))';

const rule = (over: Partial<RuleNode> = {}): RuleNode => ({
    name: "route_incident",
    whens: ["Incident as incident"],
    effects: [{ node: "turn", kind: "agent.tell", verb: "tell", label: "turn" }],
    records: [],
    ...over,
});

describe("ruleBox", () => {
    it("does not let a guard set the width of the figure", () => {
        // A box is sized by its longest line, so before the guard got a line of
        // its own this rule alone was about eleven hundred pixels wide and pushed
        // every other rule sideways off the page.
        const guarded = ruleBox(rule({ whens: [`Incident as incident where ${LONG_GUARD}`] }));
        expect(LONG_GUARD.length).toBeGreaterThan(170);
        expect(guarded.width).toBeLessThan(400);

        // And the guard is still readable in full, on the line's tooltip.
        expect(guarded.lines.map((line) => line.keyword)).toEqual(["when", "where"]);
        expect(guarded.lines[1]!.full).toBe(LONG_GUARD);
        expect(guarded.lines[1]!.text.length).toBeLessThan(LONG_GUARD.length);
    });

    it("still grows for the things a reader cannot do without", () => {
        // The trigger is not elided at 44 characters' worth of guard: a wide box
        // for a genuinely wide pattern is correct, and the bound is on the half
        // that is unbounded.
        const wide = ruleBox(rule({ whens: ["backlog has ready issue as issue"] }));
        const narrow = ruleBox(rule({ whens: ["started"] }));
        expect(wide.width).toBeGreaterThanOrEqual(narrow.width);
    });

    it("draws a table smaller, in its own name, with no trigger", () => {
        const table = ruleBox(
            rule({
                name: "table_tickets",
                whens: ["started"],
                effects: [],
                records: [{ schema: "Ticket", construct: "table_row" }],
            }),
        );
        // Narrower than a rule, because it is the data the rules act on.
        expect(table.width).toBeLessThan(ruleBox(rule()).width);
        expect(table.name).toBe("tickets");
        // `when started` is every table's trigger and says nothing a reader needs.
        expect(table.lines).toEqual([]);
        expect(table.table).toBe("1 row of Ticket");
        expect(table.inner).toBeNull();
    });

    it("leaves a hand-written rule that only records saying so", () => {
        // Not a table: nothing in it came from a declared table's rows, and the
        // note is the honest thing to draw.
        const recorder = ruleBox(rule({ effects: [], records: [] }));
        expect(recorder.table).toBeNull();
        expect(recorder.lines).toHaveLength(1);
    });
});

describe("tableSummary", () => {
    it("counts the rows and names what they are", () => {
        expect(tableSummary([{ schema: "Ticket", construct: "table_row" }])).toBe("1 row of Ticket");
        expect(
            tableSummary([
                { schema: "Ticket", construct: "table_row" },
                { schema: "Ticket", construct: "table_row" },
            ]),
        ).toBe("2 rows of Ticket");
    });

    it("names each schema once, in a fixed order", () => {
        // Determinism is the same property the layout engine holds: one program
        // must draw identically every time it is opened.
        expect(
            tableSummary([
                { schema: "Workspace", construct: "table_row" },
                { schema: "Ticket", construct: "table_row" },
                { schema: "Workspace", construct: "table_row" },
            ]),
        ).toBe("3 rows of Ticket, Workspace");
    });
});
