/**
 * **What a project's whips have cost** (`COST-3`), derived for rendering.
 *
 * The producer withholds a total whenever anything is missing, and this module
 * exists so a component cannot accidentally put it back. Three rules travel
 * from `specs/primitives/runtime.md` — the runtime meters, the desk prices —
 * through the route's document and into what a reader sees.
 *
 * **A missing total is a word, not a number.** `amountMicros` is `null` when an
 * unrecorded token count, an unrated model, or an unreadable store stopped the
 * sum. The reading then carries `total: null`, so the only thing a component
 * *can* render in the total's place is the absence.
 *
 * **`recorded` is never the total.** It is what the counts the log does carry
 * came to, and it is not a bound in either direction: an unrecorded cache
 * bucket may be tokens never spent, or tokens spent at a rate this sum never
 * applied. So it is labelled as recorded, and shown beside the gaps rather than
 * in place of them.
 *
 * **A gap is a repair instruction.** "3 gaps" tells a reader nothing they can
 * act on; "no rate for claude-sonnet-5" is the next thing to do. Every gap
 * becomes a sentence naming what to fix.
 */

import type { ProjectWhipCosts } from "@gaugewright/control-plane-client";

/** One thing standing between the recorded figure and a total. */
export interface CostGap {
    /** What to fix, in words: "no rate for `gpt-5.4-mini`". */
    readonly label: string;
    /** For a stable list key and for tests, never for display. */
    readonly key: string;
}

export interface CostReading {
    /** The total, formatted — `null` when it is unavailable. There is no
     *  "0" fallback on purpose: a component that wants a number here has to
     *  handle the null, which is the whole point. */
    readonly total: string | null;
    /** What the recorded counts came to, formatted. Always present, never a
     *  total, and meaningless without {@link CostReading.gaps} beside it. */
    readonly recorded: string;
    /** True when a store could not be read at all, which is a different
     *  failure from a measure the log does not carry: the desk does not know
     *  what it missed, so it cannot even name the gap. */
    readonly unread: boolean;
    readonly gaps: readonly CostGap[];
    /** The card the figure was priced under, for "priced under …". */
    readonly card: string | null;
    /** True when nothing is missing at all. */
    readonly complete: boolean;
}

/** Micros of a currency, as money a person reads.
 *
 *  Six decimal places is the unit's own precision, and a model call can cost a
 *  few micros — rendering that as "$0.00" would report a run that cost
 *  something as having cost nothing, which is the arithmetic version of the
 *  defect this whole surface refuses. Trailing zeros are trimmed to the cent so
 *  ordinary amounts read ordinarily.
 */
export function formatMicros(micros: number, currency: string): string {
    const sign = micros < 0 ? "-" : "";
    const whole = Math.floor(Math.abs(micros) / 1_000_000);
    const fraction = String(Math.abs(micros) % 1_000_000).padStart(6, "0").replace(/(\d\d)(\d*?)0*$/u, "$1$2");
    return `${sign}${currency} ${whole}.${fraction}`;
}

function gapLabel(gap: ProjectWhipCosts["gaps"][number]): CostGap {
    const model = typeof gap.model === "string" && gap.model.length > 0 ? gap.model : null;
    switch (gap.reason) {
        case "no_rate":
            return {
                key: `no_rate:${model ?? ""}`,
                label: model ? `no rate for ${model}` : "no rate for a model this run used",
            };
        case "unrecorded":
            return {
                key: `unrecorded:${model ?? ""}:${gap.measure ?? ""}`,
                label: model
                    ? `${gap.measure ?? "a token count"} unrecorded for ${model}`
                    : `${gap.measure ?? "a token count"} unrecorded`,
            };
        case "model_unrecorded":
            return {
                key: "model_unrecorded",
                label: "tokens were spent and the run does not say which model spent them",
            };
        default:
            // A reason this build does not know is still a reason the total is
            // missing. Reported as itself rather than dropped, because dropping
            // it would leave a null total with nothing explaining it.
            return { key: `other:${gap.reason}`, label: gap.reason };
    }
}

export function costReadingFrom(costs: ProjectWhipCosts): CostReading {
    const currency = costs.total.currency;
    return {
        total: costs.total.amountMicros === null
            ? null
            : formatMicros(costs.total.amountMicros, currency),
        recorded: formatMicros(costs.total.recordedMicros, currency),
        unread: costs.unread !== null,
        gaps: costs.gaps.map(gapLabel),
        card: costs.rateCard?.version ?? null,
        complete: costs.complete,
    };
}
