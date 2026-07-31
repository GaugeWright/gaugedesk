import { describe, expect, it, vi } from "vitest";
import { accountDevices, parseAccountDevice } from "./control-plane-account";
import type { RouteJson } from "./control-plane-transport";

describe("account device projection", () => {
    it("reads the durable enrollment timestamp without inventing one for legacy records", async () => {
        const json = vi.fn(async () => ({
            devices: [
                { id: "desktop", label: "Desktop", status: "active", enrolled_at: 1_700_000_000 },
                { id: "legacy", label: "Old laptop", status: "active" },
            ],
        })) as unknown as RouteJson;
        await expect(accountDevices(json)).resolves.toEqual([
            { id: "desktop", label: "Desktop", status: "active", enrolledAt: 1_700_000_000 },
            { id: "legacy", label: "Old laptop", status: "active", enrolledAt: 0 },
        ]);
    });

    it("fails closed for malformed device fields", () => {
        expect(parseAccountDevice({ id: 7, enrolled_at: -3 })).toEqual({
            id: "", label: "", status: "", enrolledAt: 0,
        });
    });
});
