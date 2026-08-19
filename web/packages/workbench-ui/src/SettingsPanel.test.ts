import { describe, expect, it } from "vitest";
import {
    deviceAddedLabel,
    expiresSoon,
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
