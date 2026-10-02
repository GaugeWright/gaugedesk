import { describe, expect, it } from "vitest";
import type { TranscriptLine } from "./transcript";
import { isOfferablePath, offeredDownload } from "./offered-download";

const tool = (name: string, args: unknown, ok?: boolean): TranscriptLine => ({
    seq: 1,
    tier: "operational",
    kind: "tool",
    text: "",
    tool: { name, args: typeof args === "string" ? args : JSON.stringify(args), ok },
}) as TranscriptLine;

describe("offered downloads", () => {
    it("offers only files under artifacts/", () => {
        expect(isOfferablePath("artifacts/readout.html")).toBe(true);
        expect(isOfferablePath("artifacts/2026/readout.html")).toBe(true);
        expect(isOfferablePath("artifacts/")).toBe(false);
        expect(isOfferablePath("artifacts")).toBe(false);
        expect(isOfferablePath("outbox/record.json")).toBe(false);
        expect(isOfferablePath("work/notes.md")).toBe(false);
        expect(isOfferablePath("artifacts/../outbox/record.json")).toBe(false);
        expect(isOfferablePath("artifacts/.draft.html")).toBe(false);
        expect(isOfferablePath("artifacts//readout.html")).toBe(false);
        expect(isOfferablePath("artifactsx/readout.html")).toBe(false);
    });

    it("reads the offer from the tool line, titled by the agent or the filename", () => {
        expect(offeredDownload(tool("offer_download", { path: "artifacts/oai-readout.html", title: "Your readout" })))
            .toEqual({ path: "artifacts/oai-readout.html", filename: "oai-readout.html", title: "Your readout" });
        expect(offeredDownload(tool("offer_download", { path: "artifacts/a/report.pdf" })))
            .toEqual({ path: "artifacts/a/report.pdf", filename: "report.pdf", title: "report.pdf" });
        // The live call has no result yet; it is still an offer.
        expect(offeredDownload(tool("offer_download", { path: "artifacts/r.md" }, undefined))?.path).toBe("artifacts/r.md");
    });

    it("leaves every other line an ordinary line", () => {
        expect(offeredDownload(tool("read", { path: "artifacts/r.md" }))).toBeNull();
        expect(offeredDownload(tool("offer_download", { path: "outbox/record.json" }))).toBeNull();
        expect(offeredDownload(tool("offer_download", "not json"))).toBeNull();
        expect(offeredDownload(tool("offer_download", { title: "no path" }))).toBeNull();
        // A refused offer shows its error as a tool line.
        expect(offeredDownload(tool("offer_download", { path: "artifacts/r.md" }, false))).toBeNull();
        expect(offeredDownload({ seq: 2, tier: "operational", kind: "assistant", text: "hi" } as TranscriptLine)).toBeNull();
    });
});
