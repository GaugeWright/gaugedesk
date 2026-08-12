import { describe, expect, it } from "vitest";
import { gemState } from "./StatusGem";

// The gem paints ONE state, resolved most-urgent first (WS-H b/c): a conflict the
// human must resolve outranks a live turn, which outranks an open ask.
//
// These cases used to also pass a `changes` projection flag. ADR 0136 retired the
// per-change review hold, so that flag could only ever be false and it is gone;
// the run tone is now the single source of "review".
describe("gemState precedence", () => {
    it("is idle when nothing is set", () => {
        expect(gemState({})).toBe("idle");
    });

    it("conflict outranks every other signal", () => {
        expect(gemState({ conflict: true, tone: "working" })).toBe("conflict");
        expect(gemState({ conflict: true, tone: "error" })).toBe("conflict");
        expect(gemState({ conflict: true, tone: "review" })).toBe("conflict");
    });

    it("a live working/error turn paints itself", () => {
        expect(gemState({ tone: "working" })).toBe("working");
        expect(gemState({ tone: "error" })).toBe("error");
    });

    it("an open ask lights the review state", () => {
        expect(gemState({ tone: "review" })).toBe("review");
    });

    it("an explicitly false conflict stays idle", () => {
        expect(gemState({ conflict: false })).toBe("idle");
    });
});
