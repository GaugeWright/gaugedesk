import { describe, expect, it } from "vitest";
import { partitionedToolTarget } from "./tool-detail";

describe("target-partitioned diff labels", () => {
    it("separates the stable target root from its relative file path", () => {
        expect(partitionedToolTarget("targets/t-mfrgg/api/routes.ts")).toEqual({
            targetRoot: "t-mfrgg",
            relativePath: "api/routes.ts",
        });
    });

    it("keeps edit-chat and legacy paths intact", () => {
        expect(partitionedToolTarget("persona.md")).toEqual({
            targetRoot: null,
            relativePath: "persona.md",
        });
    });
});
