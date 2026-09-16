import { describe, expect, it } from "vitest";
import {
    desktopUpdateAllowed,
    desktopUpdateShouldRecheck,
    DESKTOP_UPDATE_RECHECK_MS,
} from "./desktop-update";

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

describe("desktopUpdateShouldRecheck", () => {
    it("asks again from every state that could still learn something", () => {
        // A release published after this client launched is only ever found by
        // asking again, so the states that represent "no update known" — including
        // the one where the last attempt failed — must not stop the timer.
        expect(desktopUpdateShouldRecheck("current")).toBe(true);
        expect(desktopUpdateShouldRecheck("error")).toBe(true);
        expect(desktopUpdateShouldRecheck("restricted")).toBe(true);
        expect(desktopUpdateShouldRecheck("checking")).toBe(true);
        expect(desktopUpdateShouldRecheck(undefined)).toBe(true);
    });

    it("leaves an offered or installing update alone", () => {
        // Re-checking here replaces a held `Update` handle the install needs, or
        // overwrites the installing state with a discovery result.
        expect(desktopUpdateShouldRecheck("available")).toBe(false);
        expect(desktopUpdateShouldRecheck("installing")).toBe(false);
    });
});

describe("DESKTOP_UPDATE_RECHECK_MS", () => {
    it("narrows discovery to within a working day without polling the service", () => {
        // The bound that matters is not the exact interval but that one exists at
        // all: without it a client asks once at startup and never again.
        expect(DESKTOP_UPDATE_RECHECK_MS).toBeGreaterThan(60 * 60 * 1000);
        expect(DESKTOP_UPDATE_RECHECK_MS).toBeLessThanOrEqual(12 * 60 * 60 * 1000);
    });
});
