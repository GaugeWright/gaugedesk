import { describe, expect, it } from "vitest";
import {
    DELIVERABLE_ROOT,
    deliverablesIn,
    isDeliverablePath,
    mediaTypeFor,
    newDeliverables,
} from "./deliverables";

describe("deliverable paths", () => {
    it("admits only files under the fixed root", () => {
        expect(DELIVERABLE_ROOT).toBe("deliverable/");
        expect(isDeliverablePath("deliverable/oai-readout.html")).toBe(true);
        expect(isDeliverablePath("deliverable/2026/readout.html")).toBe(true);
        // The record and the instrument are the owner's and the agent's, never the visitor's.
        expect(isDeliverablePath("record/oai-record.json")).toBe(false);
        expect(isDeliverablePath("oai/flow.md")).toBe(false);
        // A lookalike prefix is not the root.
        expect(isDeliverablePath("deliverables/readout.html")).toBe(false);
        expect(isDeliverablePath("deliverable")).toBe(false);
        expect(isDeliverablePath("deliverable/")).toBe(false);
        // Dotfiles stay internal, as they do in the Files panel.
        expect(isDeliverablePath("deliverable/.draft.html")).toBe(false);
        expect(isDeliverablePath("deliverable/.tmp/readout.html")).toBe(false);
        expect(isDeliverablePath("deliverable//readout.html")).toBe(false);
    });

    it("names the download after the last segment and types it by extension", () => {
        expect(deliverablesIn(["oai/flow.md", "deliverable/oai-readout.html"])).toEqual([
            {
                path: "deliverable/oai-readout.html",
                filename: "oai-readout.html",
                mediaType: "text/html",
            },
        ]);
        expect(mediaTypeFor("deliverable/readout.MD")).toBe("text/markdown");
        expect(mediaTypeFor("deliverable/readout.pdf")).toBe("application/pdf");
        // Unknown types are saved, never interpreted.
        expect(mediaTypeFor("deliverable/readout")).toBe("application/octet-stream");
        expect(mediaTypeFor("deliverable/readout.exe")).toBe("application/octet-stream");
    });

    it("announces only what the latest listing added", () => {
        const before = ["oai/flow.md", "deliverable/first.html"];
        const after = ["oai/flow.md", "deliverable/first.html", "deliverable/second.html", "record/r.json"];
        expect(newDeliverables(before, after).map((d) => d.path)).toEqual(["deliverable/second.html"]);
        expect(newDeliverables(after, after)).toEqual([]);
        // A first listing announces everything already there, so a reloaded
        // session still shows the report it produced before the reload.
        expect(newDeliverables([], after).map((d) => d.path)).toEqual([
            "deliverable/first.html",
            "deliverable/second.html",
        ]);
    });
});
