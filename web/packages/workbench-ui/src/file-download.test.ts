import { describe, expect, it } from "vitest";
import type { EngagementId } from "@gaugewright/control-plane-client";
import { filenameOf, mediaTypeFor, readForDownload } from "./file-download";

const id = "sess" as EngagementId;

describe("file download", () => {
    it("names the file after its last segment and types it by extension", () => {
        expect(filenameOf("artifacts/2026/readout.html")).toBe("readout.html");
        expect(mediaTypeFor("artifacts/readout.HTML")).toBe("text/html");
        expect(mediaTypeFor("artifacts/readout.pdf")).toBe("application/pdf");
        // Unknown types are saved, never interpreted.
        expect(mediaTypeFor("artifacts/readout")).toBe("application/octet-stream");
        expect(mediaTypeFor("artifacts/readout.exe")).toBe("application/octet-stream");
        expect(mediaTypeFor("artifacts/v1.2/readout")).toBe("application/octet-stream");
        expect(mediaTypeFor("artifacts/.html")).toBe("application/octet-stream");
    });

    it("reads bytes when the session can, so binary files survive", async () => {
        const bytes = new Uint8Array([37, 80, 68, 70]);
        const read = await readForDownload({
            getFile: async () => "mangled",
            getFileBytes: async () => ({ bytes, cut: null }),
        }, id, "artifacts/readout.pdf");
        expect(read).toBe(bytes);
    });

    it("falls back to the text read when the session has no byte read", async () => {
        const read = await readForDownload({ getFile: async (_id, path) => `text:${path}` }, id, "artifacts/a.md");
        expect(read).toBe("text:artifacts/a.md");
    });
});
