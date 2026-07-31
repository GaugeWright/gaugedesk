import { describe, expect, it } from "vitest";
import { workbenchPaneTitle } from "./WorkbenchShell";

describe("workbench pane titles", () => {
    it("preserves the GaugeDesk navigation title by default", () => {
        expect(workbenchPaneTitle("nav")).toBe("Navigate");
    });

    it("uses an Environment title in the visible navigation heading", () => {
        expect(workbenchPaneTitle("nav", { nav: "Hub" })).toBe("Hub");
        expect(workbenchPaneTitle("nav", { nav: "Administration" })).toBe("Administration");
    });
});
