/**
 * The review surface's rules, as functions rather than as a rendered tree
 * (ADR 0110 §7, GATE-6). What matters here is what a reviewer is told: the
 * status vocabulary, and that a flagged item never reads as deleted.
 */

import { describe, expect, it } from "vitest";
import { quarantineSize, quarantineStatusCopy } from "./QuarantineIndex";

describe("the review surface's status vocabulary", () => {
    it("says awaiting review for anything the gate has not ruled on", () => {
        expect(quarantineStatusCopy("Pending").label).toBe("awaiting review");
        // Fail toward "not yet decided": an unknown status must never read as a
        // decision, because a reviewer would skip it.
        expect(quarantineStatusCopy("something-new").label).toBe("awaiting review");
    });

    it("says flagged, never deleted or discarded (ADR 0110 §6)", () => {
        const flagged = quarantineStatusCopy("Rejected");
        expect(flagged.label).toBe("flagged");
        expect(flagged.label).not.toMatch(/delet|discard|remov/i);
    });

    it("says approved for what the gate let through", () => {
        expect(quarantineStatusCopy("Approved").label).toBe("approved");
    });
});

describe("item size", () => {
    it("reads in units a person can judge at a glance", () => {
        expect(quarantineSize(512)).toBe("512 B");
        expect(quarantineSize(2048)).toBe("2 KB");
        expect(quarantineSize(5 * 1024 * 1024)).toBe("5 MB");
    });

    it("never rounds a non-empty item to nothing", () => {
        expect(quarantineSize(1)).toBe("1 B");
    });
});
