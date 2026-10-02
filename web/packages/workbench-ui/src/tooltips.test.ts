import { describe, expect, it } from "vitest";
import { placeTooltip } from "./tooltips";

describe("tooltip placement", () => {
    const viewport = { width: 1280, height: 800 };
    const size = { width: 120, height: 26 };

    it("centres the tooltip just below its control", () => {
        expect(placeTooltip({ left: 400, top: 100, width: 40, height: 20 }, size, viewport))
            .toEqual({ left: 360, top: 126 });
    });

    it("goes above a control near the bottom of the window", () => {
        expect(placeTooltip({ left: 400, top: 770, width: 40, height: 20 }, size, viewport))
            .toEqual({ left: 360, top: 738 });
    });

    it("stays inside the window beside either edge", () => {
        expect(placeTooltip({ left: 0, top: 100, width: 20, height: 20 }, size, viewport).left).toBe(6);
        expect(placeTooltip({ left: 1270, top: 100, width: 10, height: 20 }, size, viewport).left)
            .toBe(1280 - 120 - 6);
    });

    it("stays below when the window is too short for either side", () => {
        expect(placeTooltip({ left: 10, top: 2, width: 20, height: 20 }, size, { width: 300, height: 40 }).top)
            .toBe(28);
    });
});
