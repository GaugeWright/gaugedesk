import { describe, expect, it, vi } from "vitest";
import {
    listQuarantine,
    parseQuarantinedItem,
    screenQuarantinedItem,
    type WorkbenchTransport,
} from "./control-plane-workbench";

const base = {
    item_id: "session-a:1",
    source_id: "session-a",
    schema_ref: "survey/v1",
    byte_len: 12,
    arrived_at_unix_ms: 1_800_000_000_000,
};

describe("quarantine transport boundary", () => {
    it.each([
        [{ state: "pending" }, "Pending", null],
        [{ state: "approved", workspace_path: "collected/session-a-1.json" },
            "Approved", "collected/session-a-1.json"],
        [{ state: "rejected" }, "Rejected", null],
    ] as const)("normalizes Rust lifecycle state %o", (status, expected, workspacePath) => {
        expect(parseQuarantinedItem({ ...base, status })).toEqual({
            ...base,
            status: expected,
            workspace_path: workspacePath,
        });
    });

    it("fails closed on an unknown lifecycle state", () => {
        expect(() => parseQuarantinedItem({
            ...base,
            status: { state: "mystery" },
        })).toThrow("malformed");
    });

    it("normalizes every item returned by the production route", async () => {
        const json = vi.fn(async () => ({
            project_id: "project-a",
            pending: 1,
            items: [
                { ...base, status: { state: "pending" } },
                {
                    ...base,
                    item_id: "session-b:2",
                    source_id: "session-b",
                    status: {
                        state: "approved",
                        workspace_path: "collected/session-b-2.json",
                    },
                },
            ],
        }));
        const transport = { base: "", json } as unknown as WorkbenchTransport;

        await expect(listQuarantine(transport, "project-a")).resolves.toMatchObject({
            project_id: "project-a",
            pending: 1,
            items: [
                { status: "Pending", workspace_path: null },
                {
                    status: "Approved",
                    workspace_path: "collected/session-b-2.json",
                },
            ],
        });
        expect(json).toHaveBeenCalledWith("GET", "/projects/project-a/quarantine");
    });

    it("starts the gate through the exact production screen route", async () => {
        const json = vi.fn(async () => ({ workspace_path: null, parked: true }));
        const transport = { base: "", json } as unknown as WorkbenchTransport;

        await expect(screenQuarantinedItem(
            transport,
            "project/a",
            "session:1",
            "chat-review",
        )).resolves.toEqual({ workspacePath: null, parked: true });
        expect(json).toHaveBeenCalledWith(
            "POST",
            "/projects/project%2Fa/quarantine/session%3A1/screen",
            { chat_id: "chat-review" },
        );
    });
});
