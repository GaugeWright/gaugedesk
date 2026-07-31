import { describe, expect, it } from "vitest";
import {
    deviceAddedLabel,
    managedInferenceWriteAvailable,
    signInMethodLabel,
} from "./AccountPanel";

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
