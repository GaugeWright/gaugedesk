import { describe, expect, it } from "vitest";

import { costReadingFrom, formatMicros } from "./whip-cost";
import type { ProjectWhipCosts } from "@gaugewright/control-plane-client";

function costs(over: Partial<ProjectWhipCosts> = {}): ProjectWhipCosts {
    return {
        project: "proj-1",
        complete: true,
        unread: null,
        rateCard: { version: "card-v1", currency: "USD" },
        total: { currency: "USD", amountMicros: 0, recordedMicros: 0 },
        gaps: [],
        ...over,
    };
}

describe("formatMicros", () => {
    it("keeps a sub-cent amount rather than rounding it to nothing", () => {
        // 756 micros is what a real gate run cost. Rendered at two decimal
        // places it is "$0.00" — a run that cost something reported as free,
        // which is the defect this whole surface refuses, reached by
        // formatting instead of by arithmetic.
        expect(formatMicros(756, "USD")).toBe("USD 0.000756");
        expect(formatMicros(1, "USD")).toBe("USD 0.000001");
    });

    it("reads ordinarily for an ordinary amount", () => {
        expect(formatMicros(3_000_000, "USD")).toBe("USD 3.00");
        expect(formatMicros(1_500_000, "USD")).toBe("USD 1.50");
        expect(formatMicros(0, "USD")).toBe("USD 0.00");
    });
});

describe("costReadingFrom", () => {
    it("carries a complete figure as the total", () => {
        const reading = costReadingFrom(costs({
            total: { currency: "USD", amountMicros: 756, recordedMicros: 756 },
        }));
        expect(reading.total).toBe("USD 0.000756");
        expect(reading.complete).toBe(true);
        expect(reading.gaps).toEqual([]);
    });

    it("has NO total when anything is missing, and offers no zero in its place", () => {
        // The rule the producer enforces and this is the last place it can be
        // undone. `total` is null, so a component has to handle the absence:
        // there is nothing here it could render as a number by accident.
        const reading = costReadingFrom(costs({
            complete: false,
            total: { currency: "USD", amountMicros: null, recordedMicros: 756 },
            gaps: [{ reason: "no_rate", model: "gpt-5.4-mini" }],
        }));
        expect(reading.total).toBeNull();
        expect(reading.recorded).toBe("USD 0.000756");
    });

    it("turns every gap into the thing to fix", () => {
        const reading = costReadingFrom(costs({
            complete: false,
            total: { currency: "USD", amountMicros: null, recordedMicros: 0 },
            gaps: [
                { reason: "no_rate", model: "gpt-5.4-mini" },
                { reason: "unrecorded", model: "claude-sonnet-5", measure: "input_cache_write" },
                { reason: "model_unrecorded" },
            ],
        }));
        expect(reading.gaps.map((gap) => gap.label)).toEqual([
            "no rate for gpt-5.4-mini",
            "input_cache_write unrecorded for claude-sonnet-5",
            "tokens were spent and the run does not say which model spent them",
        ]);
    });

    it("reports a reason it does not recognise rather than dropping it", () => {
        // A dropped gap leaves a null total with nothing explaining it, which
        // reads as a bug in the surface rather than a hole in the data.
        const reading = costReadingFrom(costs({
            complete: false,
            total: { currency: "USD", amountMicros: null, recordedMicros: 0 },
            gaps: [{ reason: "something-this-build-has-not-met" }],
        }));
        expect(reading.gaps).toHaveLength(1);
        expect(reading.gaps[0].label).toBe("something-this-build-has-not-met");
    });

    it("tells an unreadable store apart from a nameable gap", () => {
        // A store that would not open has no gap to name: the desk does not
        // know what it could not see. Saying "no gaps" beside a missing total
        // would read as a surface fault rather than as a store that is silent.
        const reading = costReadingFrom(costs({
            complete: false,
            unread: "unreadable",
            total: { currency: "USD", amountMicros: null, recordedMicros: 0 },
        }));
        expect(reading.unread).toBe(true);
        expect(reading.gaps).toEqual([]);
        expect(reading.total).toBeNull();
    });
});
