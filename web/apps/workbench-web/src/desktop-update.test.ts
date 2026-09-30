import { describe, expect, it, vi } from "vitest";
import {
    desktopUpdateAllowed,
    desktopUpdateOffer,
    withDesktopUpdateTimeout,
    desktopUpdateScopeReady,
    desktopUpdateShouldRecheck,
    selectedDesktopUpdatePolicy,
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

describe("desktopUpdateOffer", () => {
    it("holds an update while no account scope has resolved", () => {
        // The selected account refused by this computer's Home never resolves a
        // scope. Discovery still runs; installation waits for a known policy.
        expect(desktopUpdateOffer(undefined)).toBe("held");
    });

    it("offers or restricts once the policy is known", () => {
        expect(desktopUpdateOffer(null)).toBe("available");
        expect(desktopUpdateOffer({ allowedChannels: [] })).toBe("available");
        expect(desktopUpdateOffer({ allowedChannels: ["beta"] })).toBe("restricted");
    });
});

describe("withDesktopUpdateTimeout", () => {
    it("fails a request that never answers instead of leaving the check pending", async () => {
        vi.useFakeTimers();
        try {
            const pending = withDesktopUpdateTimeout(new Promise<never>(() => {}), 1_000);
            const outcome = expect(pending).rejects.toThrow("timed out");
            await vi.advanceTimersByTimeAsync(1_000);
            await outcome;
        } finally {
            vi.useRealTimers();
        }
    });

    it("passes an answer through", async () => {
        await expect(withDesktopUpdateTimeout(Promise.resolve(7), 1_000)).resolves.toBe(7);
    });
});

describe("selectedDesktopUpdatePolicy", () => {
    it("discovers updates for Personal while its Home is unreachable", async () => {
        const unreachableHome = () => Promise.reject(new TypeError("Load failed"));
        await expect(selectedDesktopUpdatePolicy({ personal: true }, false, unreachableHome)).resolves.toBeNull();
        await expect(selectedDesktopUpdatePolicy({ personal: false }, false, unreachableHome)).rejects.toThrow("Load failed");
    });

    it("checks from explicit local mode without asking an absent Home", async () => {
        const unreachableHome = () => Promise.reject(new TypeError("Load failed"));
        expect(desktopUpdateScopeReady(null, false)).toBe(false);
        expect(desktopUpdateScopeReady(null, true)).toBe(true);
        await expect(selectedDesktopUpdatePolicy(null, true, unreachableHome)).resolves.toBeNull();
    });

    it("keeps an organization's channel restriction", async () => {
        const policy = { allowedChannels: ["beta"] };
        await expect(selectedDesktopUpdatePolicy({ personal: false }, true, async () => policy)).resolves.toEqual(policy);
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
