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
        registerLocalControlPlaneFailure("http://127.0.0.1:7878", async () => null, { waitMs: 0 });
        await expect(json("GET", "/workspace")).rejects.toThrow(new TypeError("Load failed"));
        registerLocalControlPlaneFailure("http://127.0.0.1:7878", async () => {
            throw new Error("unknown command");
        }, { waitMs: 0 });
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

/** A control plane that starts listening after `refusals` connection attempts. */
function startsAfter(refusals: number, body: unknown = { linked: true, person: "account-1" }) {
    let attempts = 0;
    const fetch = vi.fn(async () => {
        attempts += 1;
        if (attempts <= refusals) throw new TypeError("Load failed");
        return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
    });
    vi.stubGlobal("fetch", fetch);
    return fetch;
}

/** A clock the waits advance, so no test sleeps. */
function fakeClock() {
    let now = 0;
    return {
        now: () => now,
        sleep: vi.fn(async (ms: number) => {
            now += ms;
        }),
    };
}

describe("a read sent before the desktop's own control plane has started", () => {
    it("waits for it to start rather than answering as if signed out", async () => {
        // 2026-10-07: the first reads of a newly updated GaugeDesk reached
        // 127.0.0.1:7878 ~0.3 s before the control plane listened, and the
        // sign-in status read failing left the window signed out.
        const fetch = startsAfter(3);
        const clock = fakeClock();
        registerLocalControlPlaneFailure("http://127.0.0.1:7878", async () => null, clock);
        const json = browserRouteJson("http://127.0.0.1:7878");
        await expect(json("GET", "/account/hub-session")).resolves.toEqual({ linked: true, person: "account-1" });
        expect(fetch).toHaveBeenCalledTimes(4);
        expect(clock.sleep).toHaveBeenCalledTimes(3);
    });

    it("does not wait once the control plane has answered: then it has stopped", async () => {
        const fetch = startsAfter(0);
        const clock = fakeClock();
        registerLocalControlPlaneFailure("http://127.0.0.1:7878", async () => null, clock);
        const json = browserRouteJson("http://127.0.0.1:7878");
        await json("GET", "/account/hub-session");
        fetch.mockImplementation(async () => {
            throw new TypeError("Load failed");
        });
        await expect(json("GET", "/account/hub-session")).rejects.toThrow(new TypeError("Load failed"));
        expect(clock.sleep).not.toHaveBeenCalled();
    });

    it("stops waiting the moment the shell says why the control plane stopped", async () => {
        startsAfter(10);
        const clock = fakeClock();
        const explain = vi.fn(async () => (explain.mock.calls.length >= 2 ? UPDATE : null));
        registerLocalControlPlaneFailure("http://127.0.0.1:7878", explain, clock);
        const failure = await browserRouteJson("http://127.0.0.1:7878")("GET", "/workspace").catch((e) => e);
        expect(failure).toBeInstanceOf(LocalControlPlaneUnavailable);
        expect(clock.sleep).toHaveBeenCalledTimes(1);
    });

    it("gives up after the startup wait with the webview's own error", async () => {
        startsAfter(Number.POSITIVE_INFINITY);
        const clock = fakeClock();
        registerLocalControlPlaneFailure("http://127.0.0.1:7878", async () => null, { ...clock, waitMs: 5_000 });
        await expect(browserRouteJson("http://127.0.0.1:7878")("GET", "/workspace"))
            .rejects.toThrow(new TypeError("Load failed"));
        expect(clock.now()).toBeLessThanOrEqual(5_000);
        expect(clock.now()).toBeGreaterThan(2_000);
    });

    it("never sends a write twice", async () => {
        const fetch = startsAfter(1);
        const clock = fakeClock();
        registerLocalControlPlaneFailure("http://127.0.0.1:7878", async () => null, clock);
        await expect(browserRouteJson("http://127.0.0.1:7878")("POST", "/account/hub-session/start", {}))
            .rejects.toThrow(new TypeError("Load failed"));
        expect(fetch).toHaveBeenCalledTimes(1);
        expect(clock.sleep).not.toHaveBeenCalled();
    });
});
