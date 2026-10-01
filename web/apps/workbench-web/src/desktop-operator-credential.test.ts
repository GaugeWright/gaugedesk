import { afterEach, describe, expect, it, vi } from "vitest";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import { desktopOperatorSecret } from "./desktop-operator-credential";

describe("the desktop window's operator secret", () => {
    afterEach(() => {
        invoke.mockReset();
        delete (globalThis as Record<string, unknown>).window;
    });
    it("is never asked for outside the desktop shell", async () => {
        (globalThis as Record<string, unknown>).window = {};
        expect(await desktopOperatorSecret()).toBeNull();
        expect(invoke).not.toHaveBeenCalled();
    });
    it("comes from the shell over IPC", async () => {
        (globalThis as Record<string, unknown>).window = { __TAURI_INTERNALS__: {} };
        invoke.mockResolvedValueOnce("per-launch-secret");
        expect(await desktopOperatorSecret()).toBe("per-launch-secret");
        expect(invoke).toHaveBeenCalledWith("operator_secret");
    });
    it("is absent when the shell has none or predates the command", async () => {
        (globalThis as Record<string, unknown>).window = { __TAURI_INTERNALS__: {} };
        for (const answer of [null, "", undefined]) {
            invoke.mockResolvedValueOnce(answer);
            expect(await desktopOperatorSecret()).toBeNull();
        }
        invoke.mockRejectedValueOnce(new Error("unknown command"));
        expect(await desktopOperatorSecret()).toBeNull();
    });
});
