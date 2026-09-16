/**
 * The navigator's read outcome → what it shows. These pin the regression that
 * left the whole nav on "loading…" with nothing that could clear it: the
 * co-resident control plane binds its port after the shell opens the webview, so
 * the first read can fail with a bare connection refusal, and a failed read used
 * to be indistinguishable from one still in flight.
 */

import { describe, expect, it } from "vitest";
import { navLoadState } from "./nav-load-state";

describe("navLoadState", () => {
    it("shows the tree once there is one", () => {
        expect(navLoadState({ errored: false, hasTree: true })).toBe("ready");
    });

    it("spins only while a read is genuinely outstanding", () => {
        expect(navLoadState({ errored: false, hasTree: false })).toBe("loading");
    });

    it("offers a retry instead of spinning forever when the first read failed", () => {
        // The bug: this returned "loading", so the nav promised work that was not
        // happening and no event could ever arrive to clear it.
        expect(navLoadState({ errored: true, hasTree: false })).toBe("error");
    });

    it("keeps a tree it already holds when a later refetch fails", () => {
        // Staleness is the freshness banner's job, not a reason to blank the nav.
        expect(navLoadState({ errored: true, hasTree: true })).toBe("ready");
    });
});
