import { afterEach, describe, expect, it, vi } from "vitest";
import { browserRouteJson } from "./browser-route-json";
import {
    LocalControlPlaneUnavailable,
    registerLocalControlPlaneFailure,
    resetLocalControlPlaneFailureForTest,
} from "./local-control-plane-failure";

afterEach(() => {
    resetLocalControlPlaneFailureForTest();
    vi.unstubAllGlobals();
});

/** What WebKit does when nothing listens: a TypeError that says only this. */
function nothingListens() {
    vi.stubGlobal("fetch", vi.fn(async () => {
        throw new TypeError("Load failed");
    }));
}

const UPDATE = "A newer version of GaugeDesk has already used the data on this computer. Update GaugeDesk to continue.";

describe("a request to the desktop's own control plane that cannot connect", () => {
    it("fails with the shell's reason instead of the webview's", async () => {
        nothingListens();
        registerLocalControlPlaneFailure("http://127.0.0.1:7878", async () => UPDATE);
        const json = browserRouteJson("http://127.0.0.1:7878");
        const failure = await json("POST", "/account/hub-session/start", { provider: "google" }).catch((e) => e);
        expect(failure).toBeInstanceOf(LocalControlPlaneUnavailable);
        expect((failure as Error).message).toBe(UPDATE);
        expect((failure as Error).cause).toBeInstanceOf(TypeError);
    });

    it("keeps the webview's error while the shell has no reason, or cannot say", async () => {
        nothingListens();
        const json = browserRouteJson("http://127.0.0.1:7878");
        registerLocalControlPlaneFailure("http://127.0.0.1:7878", async () => null);
        await expect(json("GET", "/workspace")).rejects.toThrow(new TypeError("Load failed"));
        registerLocalControlPlaneFailure("http://127.0.0.1:7878", async () => {
            throw new Error("unknown command");
        });
        await expect(json("GET", "/workspace")).rejects.toThrow(new TypeError("Load failed"));
    });

    it("never explains another origin, or an abort", async () => {
        nothingListens();
        const explain = vi.fn(async () => UPDATE);
        registerLocalControlPlaneFailure("http://127.0.0.1:7878", explain);
        await expect(browserRouteJson("https://home.example.com")("GET", "/workspace"))
            .rejects.toThrow(new TypeError("Load failed"));
        vi.stubGlobal("fetch", vi.fn(async () => {
            throw new DOMException("aborted", "AbortError");
        }));
        await expect(browserRouteJson("http://127.0.0.1:7878")("GET", "/workspace"))
            .rejects.toThrow("aborted");
        expect(explain).not.toHaveBeenCalled();
    });
});
