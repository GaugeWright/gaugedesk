import { describe, expect, it } from "vitest";
import {
    deviceAddedLabel,
    expiresSoon,
    librarySyncPullLabel,
    managedInferenceWriteAvailable,
    signInMethodLabel,
} from "./SettingsPanel";

describe("trusted-device enrollment copy", () => {
    it("does not invent an enrollment date for legacy account records", () => {
        expect(deviceAddedLabel(0)).toBe("Added before enrollment dates were recorded");
        expect(deviceAddedLabel(Number.NaN)).toBe("Added before enrollment dates were recorded");
    });

    it("renders a real enrollment date", () => {
        expect(deviceAddedLabel(1_700_000_000)).toContain("2023");
    });

    it("labels the authenticated session without claiming durable method linkage", () => {
        expect(signInMethodLabel({ method: "google", label: "Google" })).toBe("Google");
        expect(signInMethodLabel(undefined)).toBe("Current session");
    });

    it("keeps hosted billing plans read-only while local plans remain editable", () => {
        expect(managedInferenceWriteAvailable(false)).toBe(false);
        expect(managedInferenceWriteAvailable(true)).toBe(true);
        expect(managedInferenceWriteAvailable(undefined)).toBe(true);
    });
});

describe("credential expiry warning", () => {
    const now = Date.UTC(2026, 0, 15);
    // Expiries are epoch milliseconds, the unit the account routes report.
    const inDays = (days: number) => now + days * 86_400_000;

    it("warns only inside the renewal window", () => {
        expect(expiresSoon(inDays(3), now)).toBe(true);
        expect(expiresSoon(inDays(30), now)).toBe(false);
    });

    it("says nothing about a credential that has already expired", () => {
        // Expiry is its own state with its own badge; "expires soon" alongside it would
        // describe an event that has already happened.
        expect(expiresSoon(inDays(-1), now)).toBe(false);
    });

    it("treats an absent or unusable expiry as no warning rather than an imminent one", () => {
        expect(expiresSoon(null, now)).toBe(false);
        expect(expiresSoon(undefined, now)).toBe(false);
        expect(expiresSoon(Number.NaN, now)).toBe(false);
    });
});

describe("library-sync pull copy", () => {
    it("ticks only when the whole pull happened", () => {
        expect(librarySyncPullLabel({ found: true, merged: 3, declined: null }))
            .toBe("merged 3 records ✓");
        expect(librarySyncPullLabel({ found: true, merged: 1 })).toBe("merged 1 record ✓");
        expect(librarySyncPullLabel({ found: false, merged: 0 }))
            .toBe("nothing published to pull yet");
    });

    // The whole reason this copy exists: the sealed half can merge while the
    // routing is refused, and a person told "merged 3 records ✓" has no way to
    // find out that their relay-only Homes stopped arriving.
    it("keeps the count but withholds the tick when routing was refused", () => {
        expect(
            librarySyncPullLabel({
                found: true,
                merged: 3,
                declined: "the directory served a record with no root signature",
            }),
        ).toBe(
            "merged 3 records — project routes were not merged: " +
                "the directory served a record with no root signature",
        );
    });

    it("reads an empty reason as no reason rather than as a dangling clause", () => {
        expect(librarySyncPullLabel({ found: true, merged: 2, declined: "  " }))
            .toBe("merged 2 records ✓");
    });

    // A snapshot retracts by omission (ADR 0154), so a pull removes as well as
    // adds. Folding a removal into the merge count would say the opposite of
    // what happened.
    it("counts a retraction as its own clause, never as a merge", () => {
        expect(librarySyncPullLabel({ found: true, merged: 4, retracted: 1 }))
            .toBe("merged 4 records, retracted 1 stale route ✓");
        expect(librarySyncPullLabel({ found: true, merged: 0, retracted: 2 }))
            .toBe("merged 0 records, retracted 2 stale routes ✓");
        expect(librarySyncPullLabel({ found: true, merged: 4, retracted: 0 }))
            .toBe("merged 4 records ✓");
    });
});
