import { describe, expect, it } from "vitest";
import { desktopUpdateAllowed } from "./desktop-update";

describe("desktopUpdateAllowed", () => {
    it("preserves updates for unmanaged and unrestricted installations", () => {
        expect(desktopUpdateAllowed(null)).toBe(true);
        expect(desktopUpdateAllowed({ allowedChannels: [] })).toBe(true);
    });

    it("does not offer the stable updater outside an organization's allowed channels", () => {
        expect(desktopUpdateAllowed({ allowedChannels: ["beta", "dev"] })).toBe(false);
        expect(desktopUpdateAllowed({ allowedChannels: ["stable"] })).toBe(true);
    });
});
