import { describe, expect, it } from "vitest";
import { immediateDestinationPresentation, railFoldCount } from "./ChatComposer";

describe("folding the composer rail", () => {
    // A rail that fits once `need` items are folded, or once `need - 1` are
    // folded and the last item left may shorten, and records what it was asked.
    const rail = (need: number, tightNeed = need) => {
        const asked: string[] = [];
        const fits = (folded: number, tight: boolean) => {
            asked.push(`${folded}${tight ? "t" : ""}`);
            return folded >= (tight ? tightNeed : need);
        };
        return { asked, fits };
    };

    it("folds nothing while everything fits", () => {
        const { asked, fits } = rail(0);
        expect(railFoldCount(4, fits)).toBe(0);
        expect(asked).toEqual(["0"]);
    });

    it("folds one item at a time until the rail fits, never the last first", () => {
        const { asked, fits } = rail(2);
        expect(railFoldCount(4, fits)).toBe(2);
        expect(asked).toEqual(["0", "1", "2"]);
    });

    it("shortens the last item before folding it", () => {
        const { asked, fits } = rail(4, 3);
        expect(railFoldCount(4, fits)).toBe(3);
        expect(asked).toEqual(["0", "1", "2", "3", "3t"]);
    });

    it("folds the last item only when even its short form does not fit", () => {
        const { fits } = rail(4);
        expect(railFoldCount(4, fits)).toBe(4);
    });

    it("folds nothing when there is nothing to fold", () => {
        const { asked, fits } = rail(1);
        expect(railFoldCount(0, fits)).toBe(0);
        expect(asked).toEqual([]);
    });
});

describe("immediate composer language", () => {
    it("reserves steering language for a host that can interrupt", () => {
        expect(immediateDestinationPresentation(true, false, false)).toEqual({
            label: "Steer",
            detail: "Run it now",
        });
        expect(immediateDestinationPresentation(true, true, true)).toEqual({
            label: "Steer",
            detail: "Run it now, interrupting the turn in flight",
        });
    });

    it("presents a non-steering management message as Send", () => {
        expect(immediateDestinationPresentation(false, false, false)).toEqual({
            label: "Send",
            detail: "Send it now",
        });
        expect(immediateDestinationPresentation(false, true, false)).toEqual({
            label: "Send",
            detail: "Wait for the current turn to finish",
        });
        expect(immediateDestinationPresentation(false, true, true)).toEqual({
            label: "Send",
            detail: "Add it to the queue",
        });
    });
});
