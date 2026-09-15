import assert from "node:assert/strict";
import test from "node:test";
import { hostKind, hostStanding, nanoUsdInput, parseNanoUsd } from "./project-host-presentation.ts";

test("compute limits round-trip exact nanodollars", () => {
    for (const value of [0, 1, 1000000, 1500000000, Number.MAX_SAFE_INTEGER]) assert.equal(parseNanoUsd(nanoUsdInput(value)), value);
    assert.equal(nanoUsdInput(1), "0.000000001");
    assert.equal(parseNanoUsd("1.5"), 1500000000);
});
test("compute limits reject lossy, implicit and negative input", () => {
    for (const value of ["", " ", "-1", "1e2", "1.0000000001", "0x10", "NaN", "9007199.254740992"]) assert.equal(parseNanoUsd(value), null, value);
});
test("service standing never claims an unadmitted host is connected", () => {
    assert.equal(hostStanding({ lifecycle: "active", state: "indeterminate" }), "Active");
    assert.equal(hostStanding({ lifecycle: "suspended", state: "live" }), "Suspended");
    assert.equal(hostStanding({ lifecycle: "deleted", state: "unreachable" }), "Retired");
    assert.equal(hostKind({ kind: "cloud" }), "GaugeWright-managed");
    assert.equal(hostKind({ kind: "registered" }), "Self-managed");
});
