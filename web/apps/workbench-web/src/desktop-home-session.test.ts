import { afterEach, describe, expect, it, vi } from "vitest";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import { desktopHomeSession } from "./desktop-home-session";

describe("desktop Home session", () => {
    afterEach(() => {
        invoke.mockReset();
        delete (globalThis as Record<string, unknown>).window;
    });
    it("is never asked for outside the desktop shell", async () => {
        (globalThis as Record<string, unknown>).window = {};
        expect(await desktopHomeSession()).toBeNull();
        expect(invoke).not.toHaveBeenCalled();
    });
    it("takes the shell's session over IPC, and nothing else", async () => {
        (globalThis as Record<string, unknown>).window = { __TAURI_INTERNALS__: {} };
        invoke.mockResolvedValueOnce("home-session-token");
        expect(await desktopHomeSession()).toBe("home-session-token");
        expect(invoke).toHaveBeenCalledWith("home_session");
    });
    it("keeps the local posture when the shell has none or refuses", async () => {
        (globalThis as Record<string, unknown>).window = { __TAURI_INTERNALS__: {} };
        for (const answer of [null, "", undefined]) {
            invoke.mockResolvedValueOnce(answer);
            expect(await desktopHomeSession()).toBeNull();
        }
        invoke.mockRejectedValueOnce(new Error("unknown command"));
        expect(await desktopHomeSession()).toBeNull();
    });
});
