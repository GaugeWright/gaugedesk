import { describe, expect, it, vi } from "vitest";
import {
    cancelBackgroundCommand,
    listBackgroundCommands,
    queueBackgroundCommand,
} from "./background";
import type { WorkbenchTransport } from "./control-plane-workbench";
import { engagementId } from "./control-plane-domain";

const command = {
    id: "home-command:turn-1",
    chat_id: "chat-1",
    actor: "owner",
    run_at: 100,
    status: "queued",
    attempt: 0,
    error: null,
};

describe("durable background command client (HOME-6)", () => {
    it("admits before acknowledgement with a caller-stable key", async () => {
        const json = vi.fn(async () => ({ command, cursor: 4 }));
        const transport = { base: "", json } as unknown as WorkbenchTransport;
        const result = await queueBackgroundCommand(
            transport,
            engagementId("chat-1"),
            "continue",
            100,
            "turn-1",
        );
        expect(result).toMatchObject({ id: "home-command:turn-1", status: "queued" });
        expect(json).toHaveBeenCalledWith(
            "POST",
            "/chats/chat-1/background",
            { prompt: "continue", run_at: 100 },
            { idempotencyKey: "turn-1" },
        );
    });

    it("lists resumable state and cancels by encoded id", async () => {
        const json = vi
            .fn()
            .mockResolvedValueOnce({ commands: [command] })
            .mockResolvedValueOnce({ ...command, status: "canceled" });
        const transport = { base: "", json } as unknown as WorkbenchTransport;
        expect(await listBackgroundCommands(transport, engagementId("chat-1"))).toHaveLength(1);
        expect((await cancelBackgroundCommand(transport, "home-command:a/b")).status).toBe(
            "canceled",
        );
        expect(json.mock.calls[1]?.[1]).toBe("/background/home-command%3Aa%2Fb");
    });
});
