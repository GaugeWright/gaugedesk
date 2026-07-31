import { describe, expect, it, vi } from "vitest";
import { engagementId } from "./control-plane-domain";
import type { WorkbenchTransport } from "./control-plane-workbench";
import {
    exportResourceToDisk,
    getResourceExport,
    getResourceReview,
    resourceExportCommand,
    resourceReviewCommand,
} from "./control-plane-workbench";

describe("resource protection routes", () => {
    it("addresses review and export through the encoded resource, never a caller scope", async () => {
        const review = { phase: "Proposed", required: ["owner"], consented: [] };
        const exp = {
            phase: "Requested",
            source_required: ["owner"],
            source_consented: [],
            target_admitted: false,
        };
        const json = vi.fn()
            .mockResolvedValueOnce(review)
            .mockResolvedValueOnce(exp)
            .mockResolvedValueOnce({ ...review, phase: "Cleared", consented: ["owner"] })
            .mockResolvedValueOnce({ ...exp, source_consented: ["owner"] });
        const transport = { base: "", json } as WorkbenchTransport;
        const chat = engagementId("chat-1");

        await getResourceReview(transport, chat, "out/chat 1");
        await getResourceExport(transport, chat, "out/chat 1");
        await resourceReviewCommand(transport, chat, "out/chat 1", "consent", "review-key");
        await resourceExportCommand(transport, chat, "out/chat 1", "consent", "export-key");

        expect(json.mock.calls).toEqual([
            ["GET", "/chats/chat-1/resources/out%2Fchat%201/review"],
            ["GET", "/chats/chat-1/resources/out%2Fchat%201/export"],
            ["POST", "/chats/chat-1/resources/out%2Fchat%201/review/command", { action: "consent" }, { idempotencyKey: "review-key" }],
            ["POST", "/chats/chat-1/resources/out%2Fchat%201/export/command", { action: "consent" }, { idempotencyKey: "export-key" }],
        ]);
    });
});

describe("exportResourceToDisk", () => {
    it("posts the exact desktop egress route and decodes its result", async () => {
        const json = vi.fn().mockResolvedValue({
            exported: ["deliverable.txt"],
            dest: "/tmp/delivery",
        });
        const transport = { base: "", json } as WorkbenchTransport;

        await expect(
            exportResourceToDisk(
                transport,
                engagementId("chat-1"),
                "out/chat 1",
                "/tmp/delivery",
            ),
        ).resolves.toEqual({ exported: ["deliverable.txt"], dest: "/tmp/delivery" });
        expect(json).toHaveBeenCalledWith(
            "POST",
            "/chats/chat-1/resources/out%2Fchat%201/export-to-disk",
            { dest: "/tmp/delivery" },
        );
    });

    it("fails closed on a malformed response", async () => {
        const transport = {
            base: "",
            json: vi.fn().mockResolvedValue({ exported: [7], dest: "/tmp/delivery" }),
        } as WorkbenchTransport;
        await expect(
            exportResourceToDisk(transport, engagementId("chat-1"), "out-1", "/tmp/delivery"),
        ).rejects.toThrow("malformed exported files");
    });
});
