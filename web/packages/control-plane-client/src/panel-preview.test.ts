import { describe, expect, it, vi } from "vitest";
import {
    publicPublisherKey,
    startPanelPreview,
    stopPanelPreview,
    type WorkbenchTransport,
} from "./control-plane-workbench";

describe("Panel Preview client", () => {
    it("starts and revokes the disposable public-session handle", async () => {
        const outcome = {
            preview_id: "panel-preview-abc",
            deployment_id: "panel-preview-abc",
            release_id: `sha256:${"a".repeat(64)}`,
            edge_origin: "https://panels.example",
            deployment_url: "https://panels.example/d/panel-preview-abc",
            panels: ["gw-chat"],
            expires_at_unix_ms: 1_800_000_000_000,
        };
        const json = vi.fn(async (method: string) =>
            method === "POST" ? { preview: outcome } : undefined);
        const transport = { base: "", json } as unknown as WorkbenchTransport;
        const input = {
            agent_id: "agent-panel" as never,
            edge_origin: "https://panels.example",
            allowed_origin: "https://desk.example",
            funding: { kind: "managed" as const, tenant_id: "tenant-canary" },
        };

        await expect(startPanelPreview(transport, input)).resolves.toEqual(outcome);
        await expect(stopPanelPreview(transport, outcome.preview_id)).resolves.toBeUndefined();
        expect(json.mock.calls).toEqual([
            ["POST", "/panel-previews", input],
            ["DELETE", "/panel-previews/panel-preview-abc"],
        ]);
    });

    it("validates the publisher authority before asking Hub to bind funding", async () => {
        const key = `04${"a".repeat(128)}`;
        const json = vi.fn(async () => ({ public_key: key }));
        const transport = { base: "", json } as unknown as WorkbenchTransport;
        await expect(publicPublisherKey(transport)).resolves.toBe(key);
        await expect(publicPublisherKey({
            base: "",
            json: vi.fn(async () => ({ public_key: "not-a-key" })),
        } as unknown as WorkbenchTransport)).rejects.toThrow("malformed");
    });
});
