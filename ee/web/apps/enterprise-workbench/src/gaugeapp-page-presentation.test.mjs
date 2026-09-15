import assert from "node:assert/strict";
import test from "node:test";
import { pageFreshnessCaveat } from "./gaugeapp-page-presentation.ts";

test("healthy authority evidence does not become page-heading jargon", () => {
    for (const freshness of [
        "live",
        "authority-live",
        "home-admitted",
        "webhook-admitted",
        "processor-reconciled",
        "routing-live; inventory target-admitted",
    ]) assert.equal(pageFreshnessCaveat(freshness), null);
});

test("freshness failures become concise user-facing caveats", () => {
    assert.equal(pageFreshnessCaveat("not-connected"), "Not connected");
    assert.equal(pageFreshnessCaveat("home-unavailable"), "Temporarily unavailable");
    assert.equal(pageFreshnessCaveat("stale"), "May be out of date");
    assert.equal(pageFreshnessCaveat("unreconciled"), "May be out of date");
});
