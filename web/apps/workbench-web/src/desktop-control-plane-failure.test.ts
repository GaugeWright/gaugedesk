import { afterEach, describe, expect, it, vi } from "vitest";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import { desktopControlPlaneFailure } from "./desktop-control-plane-failure";

describe("why the desktop's control plane is not answering", () => {
    afterEach(() => {
        invoke.mockReset();
        delete (globalThis as Record<string, unknown>).window;
    });
    it("is never asked for outside the desktop shell", async () => {
        (globalThis as Record<string, unknown>).window = {};
        expect(await desktopControlPlaneFailure()).toBeNull();
        expect(invoke).not.toHaveBeenCalled();
    });
    it("is the shell's message for the person", async () => {
        (globalThis as Record<string, unknown>).window = { __TAURI_INTERNALS__: {} };
        invoke.mockResolvedValueOnce({ kind: "store_too_new", message: "Update GaugeDesk to continue." });
        expect(await desktopControlPlaneFailure()).toBe("Update GaugeDesk to continue.");
        expect(invoke).toHaveBeenCalledWith("control_plane_failure");
    });
    it("is absent while it serves, or when the shell predates the command", async () => {
        (globalThis as Record<string, unknown>).window = { __TAURI_INTERNALS__: {} };
        for (const answer of [null, undefined, { kind: "failed", message: "" }]) {
            invoke.mockResolvedValueOnce(answer);
            expect(await desktopControlPlaneFailure()).toBeNull();
        }
        invoke.mockRejectedValueOnce(new Error("unknown command"));
        expect(await desktopControlPlaneFailure()).toBeNull();
    });
});
