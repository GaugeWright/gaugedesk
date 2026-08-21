import { describe, expect, it } from "vitest";
import { defaultContentMode, isSettledPhase, keptLabel, phaseLabel, shouldShowViewOnSelect } from "./content-view";

describe("isSettledPhase", () => {
    it("is true for the terminal/idle phases that may have rewritten the worktree", () => {
        expect(isSettledPhase("Rejected")).toBe(true);
        expect(isSettledPhase("Advanced")).toBe(true);
        expect(isSettledPhase("Integrated")).toBe(true);
        expect(isSettledPhase("Idle")).toBe(true);
    });
    it("is false while a change is mid-flight or up for review", () => {
        expect(isSettledPhase("Clean")).toBe(false);
        expect(isSettledPhase("Merging")).toBe(false);
        expect(isSettledPhase("Repairing")).toBe(false);
        expect(isSettledPhase(null)).toBe(false);
    });
});

describe("keptLabel (scope-specific vocabulary)", () => {
    it("a work chat keeps into the shared copy", () => {
        expect(keptLabel("work", undefined)).toBe("Kept into the shared copy");
        expect(keptLabel(undefined, "anything")).toBe("Kept into the shared copy");
    });
    it("an improve chat names the method and states the broader scope", () => {
        expect(keptLabel("edit", "Reviewer")).toBe(
            "Saved to the Reviewer Agent — this now applies everywhere it's used",
        );
    });
    it("an improve chat with no method name falls back to a generic method phrasing", () => {
        expect(keptLabel("edit", undefined)).toBe("Saved to the Agent — this now applies everywhere it's used");
        expect(keptLabel("edit", "   ")).toBe("Saved to the Agent — this now applies everywhere it's used");
    });
});

describe("phaseLabel", () => {
    it("renders each phase in plain words", () => {
        expect(phaseLabel("Idle", "work", undefined)).toBe("No changes to review yet");
        expect(phaseLabel("Merging", "work", undefined)).toBe("Checking the changes…");
        expect(phaseLabel("Repairing", "work", undefined)).toBe("Fixing up a conflict…");
        expect(phaseLabel("Rejected", "work", undefined)).toBe("You discarded these changes — nothing was kept");
    });
    it("Advanced/Integrated reuse the scope-specific kept label", () => {
        expect(phaseLabel("Advanced", "work", undefined)).toBe("Kept into the shared copy");
        expect(phaseLabel("Integrated", "edit", "Reviewer")).toBe(
            "Saved to the Reviewer Agent — this now applies everywhere it's used",
        );
    });
    it("falls back to the raw token for an unlabeled phase (Clean)", () => {
        expect(phaseLabel("Clean", "work", undefined)).toBe("Clean");
    });
});

describe("shouldShowViewOnSelect", () => {
    it("keeps the user on the review diff when a change is pending (Clean)", () => {
        expect(shouldShowViewOnSelect("Clean")).toBe(false);
    });
    it("drops into View for an ordinary file pick (no pending review)", () => {
        expect(shouldShowViewOnSelect("Idle")).toBe(true);
        expect(shouldShowViewOnSelect("Rejected")).toBe(true);
        expect(shouldShowViewOnSelect(null)).toBe(true);
    });
});

describe("defaultContentMode (open on View unless a review is open)", () => {
    it("leads with Changes when a review is open (Clean)", () => {
        expect(defaultContentMode("Clean")).toBe("diff");
    });
    it("opens on View for every non-review phase", () => {
        expect(defaultContentMode(null)).toBe("view");
        expect(defaultContentMode("Idle")).toBe("view");
        expect(defaultContentMode("Merging")).toBe("view");
        expect(defaultContentMode("Repairing")).toBe("view");
        expect(defaultContentMode("Advanced")).toBe("view");
        expect(defaultContentMode("Integrated")).toBe("view");
        expect(defaultContentMode("Rejected")).toBe("view");
    });
});
