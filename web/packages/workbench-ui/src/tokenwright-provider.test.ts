import { describe, expect, it } from "vitest";

import { tokenwrightProviderRow } from "./tokenwright-provider";
import type { StoredBox } from "@gaugewright/control-plane-client";

/** What the account hands back: no route, no key, and nowhere to put one. */
const BOX: StoredBox = {
    fingerprint: `sha256:${"ab".repeat(32)}`,
    relayEndpoint: "wss://relay.example:443/r",
    pairedAt: "2026-09-01T20:00:00Z",
    homeId: "home_a",
    keyId: "key_c30f",
    sealed: true,
};

const NOW = 1_800_000_000_000;
const MINUTE = 60_000;

describe("what the row can honestly claim", () => {
    it("is connected when the box answered moments ago", () => {
        const row = tokenwrightProviderRow(
            BOX, { lastSeen: NOW - 4_000, models: ["tinyllama"] }, NOW);
        expect(row.reachability).toBe("connected");
        expect(row.summary).toBe("tinyllama");
    });

    it("separates a box that is quiet from one that is gone", () => {
        // Four minutes and four hours are both "not answering this instant".
        // Collapsing them sends someone to check a machine that is fine, or
        // lets a dead one look merely quiet.
        const quiet = tokenwrightProviderRow(
            BOX, { lastSeen: NOW - 20 * MINUTE, models: ["tinyllama"] }, NOW);
        const gone = tokenwrightProviderRow(
            BOX, { lastSeen: NOW - 4 * 60 * MINUTE, models: ["tinyllama"] }, NOW);
        expect(quiet.reachability).toBe("stale");
        expect(gone.reachability).toBe("unreachable");
        expect(quiet.summary).not.toBe(gone.summary);
    });

    it("reports a box that is gone as evidence, not diagnosis", () => {
        // A box that is off, a relay that is down, and a network in between are
        // indistinguishable from here. "Offline" would pick one without grounds.
        const row = tokenwrightProviderRow(
            BOX, { lastSeen: NOW - 6 * 60 * MINUTE }, NOW);
        expect(row.summary).toMatch(/last seen/);
        expect(row.summary).not.toMatch(/offline|down|failed/i);
    });

    it("says nothing about freshness before the box has ever answered", () => {
        const row = tokenwrightProviderRow(BOX, {}, NOW);
        expect(row.reachability).toBe("never-reached");
        expect(row.freshness).toBeNull();
        expect(row.summary).toBe("Paired, not yet reached");
    });

    it("treats a backwards clock as just seen rather than a box from the future", () => {
        // A laptop waking, or a corrected NTP step.
        const row = tokenwrightProviderRow(
            BOX, { lastSeen: NOW + 30_000, models: ["tinyllama"] }, NOW);
        expect(row.reachability).toBe("connected");
        expect(row.freshness).toBe("just now");
    });

    it("calls a reachable box with no model exactly that", () => {
        // Installed, paired, nothing loaded. Ordinary, and not a fault.
        const row = tokenwrightProviderRow(BOX, { lastSeen: NOW, models: [] }, NOW);
        expect(row.summary).toBe("No model loaded");
        expect(row.reachability).toBe("connected");
    });

    it("keeps the row to one line however many models a box holds", () => {
        // A person may own several boxes and many models.
        const row = tokenwrightProviderRow(BOX, {
            lastSeen: NOW,
            models: ["tinyllama", "qwen2.5-7b", "llama-3.1-8b", "phi-4"],
        }, NOW);
        expect(row.summary).toBe("tinyllama, qwen2.5-7b +2");
        expect(row.summary).not.toContain("\n");
    });

    it("never puts the whole pin in the row", () => {
        const row = tokenwrightProviderRow(BOX, { lastSeen: NOW }, NOW);
        expect(JSON.stringify(row)).not.toContain(BOX.fingerprint);
    });

    it("says a box whose credential cannot be opened is not merely quiet", () => {
        // Listed and unreachable, but not because the box is off. "Not
        // answering" would send someone to check a machine that is fine; the
        // fix is to pair it again.
        const row = tokenwrightProviderRow(
            { ...BOX, sealed: false }, { lastSeen: NOW, models: ["tinyllama"] }, NOW);
        expect(row.reachability).toBe("unusable");
        expect(row.summary).toMatch(/pair this box again/);
        expect(row.summary).not.toMatch(/answering|last seen/);
        // And nothing observed about it is repeated as fact: nothing here can
        // dial it, so a model list from an earlier session is not current.
        expect(row.models).toEqual([]);
    });

    it("shortens the pin without pretending it is the whole thing", () => {
        const row = tokenwrightProviderRow(BOX, {}, NOW);
        expect(row.fingerprint.endsWith("…")).toBe(true);
        expect(BOX.fingerprint.startsWith(row.fingerprint.slice(0, -1))).toBe(true);
    });
});
