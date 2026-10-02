import { describe, expect, it } from "vitest";
import type { EngagementId, FileEntry } from "@gaugewright/control-plane-client";
import type { EmbedSessionApi } from "./session-api";
import { isVisitorVisible, visitorApi, visitorEntries } from "./visitor-files";

const id = "sess" as EngagementId;

describe("visitor files", () => {
    it("shows the visitor artifacts/ and nothing else", () => {
        expect(isVisitorVisible("artifacts")).toBe(true);
        expect(isVisitorVisible("artifacts/readout.html")).toBe(true);
        expect(isVisitorVisible("artifacts/2026/readout.html")).toBe(true);
        // The agent's scratchpad and what goes to the owner's Inbox.
        expect(isVisitorVisible("work/notes.md")).toBe(false);
        expect(isVisitorVisible("outbox/record.json")).toBe(false);
        expect(isVisitorVisible("agent/AGENTS.md")).toBe(false);
        expect(isVisitorVisible("readme.md")).toBe(false);
        // A lookalike prefix is not the folder.
        expect(isVisitorVisible("artifactsx/readout.html")).toBe(false);
        expect(isVisitorVisible("artifact/readout.html")).toBe(false);
    });

    it("narrows a listing, keeping the folder so the tree still nests", () => {
        const entries: FileEntry[] = [
            { path: "artifacts", isDir: true },
            { path: "artifacts/readout.html", isDir: false },
            { path: "work", isDir: true },
            { path: "work/notes.md", isDir: false },
            { path: "outbox/record.json", isDir: false },
        ] as FileEntry[];
        expect(visitorEntries(entries).map((entry) => entry.path)).toEqual([
            "artifacts",
            "artifacts/readout.html",
        ]);
    });

    it("refuses a read outside artifacts/ without asking the host", async () => {
        const asked: string[] = [];
        class Client {
            readonly label = "edge";
            async getTree(): Promise<FileEntry[]> {
                return [
                    { path: "artifacts/readout.html", isDir: false },
                    { path: "outbox/record.json", isDir: false },
                ] as FileEntry[];
            }
            async getFile(_id: EngagementId, path: string): Promise<string> {
                asked.push(path);
                return `${this.label}:${path}`;
            }
            async embedGetConfig() {
                return { white_label: this.label === "edge" };
            }
        }
        const api = visitorApi(new Client() as unknown as EmbedSessionApi);

        expect((await api.getTree(id)).map((entry) => entry.path)).toEqual(["artifacts/readout.html"]);
        expect(await api.getFile(id, "artifacts/readout.html")).toBe("edge:artifacts/readout.html");
        await expect(api.getFile(id, "outbox/record.json")).rejects.toThrow("not shared with you");
        await expect(api.getFile(id, "work/notes.md")).rejects.toThrow("not shared with you");
        expect(asked).toEqual(["artifacts/readout.html"]);
        // Everything else passes through, still bound to the client.
        expect(await api.embedGetConfig()).toEqual({ white_label: true });
        // An optional read the client does not offer stays absent.
        expect(api.getFileBytes).toBeUndefined();
    });
});
