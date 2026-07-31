import { describe, expect, it, vi } from "vitest";
import { restoreMaterial } from "./backups";
import type { RouteJson } from "./control-plane-transport";

function fakeJson(response: unknown): { json: RouteJson; calls: [string, string, unknown?][] } {
    const calls: [string, string, unknown?][] = [];
    const json = vi.fn(async (method: string, path: string, body?: unknown) => {
        calls.push([method, path, body]);
        return response;
    }) as unknown as RouteJson;
    return { json, calls };
}

describe("backup recovery-holder client", () => {
    it("reads only sealed restore material", async () => {
        const material = fakeJson({
            ciphertext: { bytes: [1, 2, 3] },
            wrap: { recipient_id: "browser-a", ephemeral_pubkey: "04aa", ciphertext: "001122" },
        });
        await expect(restoreMaterial(material.json, "tenant", "point:1", "browser-a")).resolves.toEqual({
            ciphertext: { bytes: [1, 2, 3] },
            wrap: { recipient_id: "browser-a", ephemeral_pubkey: "04aa", ciphertext: "001122" },
        });
        expect(material.calls).toEqual([[
            "GET",
            "/account/tenants/tenant/backups/points/point%3A1/restore-material/browser-a",
            undefined,
        ]]);
    });
});
