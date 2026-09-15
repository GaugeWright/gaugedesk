import assert from "node:assert/strict";
import test from "node:test";
import { availablePopoverHeight } from "./popover-fit.ts";

test("the full organization menu stays below the pane's clipping edge", () => {
    const height = availablePopoverHeight(628, 39);
    assert.equal(height, 579);
    assert.ok(628 - 5 - height > 39, "the first row remains visible and hit-testable");
});
test("popover height follows compact panes and respects its maximum", () => {
    assert.equal(availablePopoverHeight(300, 50), 240);
    assert.equal(availablePopoverHeight(1000, 39), 610);
    assert.equal(availablePopoverHeight(100, 120), 0);
    assert.equal(availablePopoverHeight(100, -50), 90);
    assert.equal(availablePopoverHeight(NaN, 0), 0);
});
