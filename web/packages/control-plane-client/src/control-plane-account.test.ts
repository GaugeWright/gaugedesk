import { describe, expect, it, vi } from "vitest";
import { accountDevices, accountDirectory, parseAccountDevice } from "./control-plane-account";
import type { RouteJson } from "./control-plane-transport";

describe("the account directory projection (DESK-5f)", () => {
    it("reads which root signs the record and where it lives", async () => {
        const json = vi.fn(async () => ({
            root_pubkey: "ed25519:abc",
            origin: "https://directory.example/",
        })) as unknown as RouteJson;
        await expect(accountDirectory(json)).resolves.toEqual({
            rootPubkey: "ed25519:abc",
            origin: "https://directory.example",
        });
    });

    it("reports nothing rather than throwing when the account published none", async () => {
        // A hub that 404s, and a hub too old to serve the route at all, mean the
        // same thing to a caller: no signed record to read. Neither is a reason
        // to fail an account that works without one.
        const missing = vi.fn(async () => {
            throw new Error("GET /account/directory: 404");
        }) as unknown as RouteJson;
        await expect(accountDirectory(missing)).resolves.toBeNull();
    });

    it("treats an empty or malformed key as absent, never as a key", async () => {
        // An empty string is what an unset value looks like, and pinning it
        // would make every later real key read as a conflict.
        for (const value of [{ root_pubkey: "  " }, { root_pubkey: 7 }, null]) {
            const json = vi.fn(async () => value) as unknown as RouteJson;
            await expect(accountDirectory(json)).resolves.toBeNull();
        }
    });

    it("falls back to no origin rather than inventing one", async () => {
        // The caller owns the canonical default; a client-side guess here would
        // silently disagree with the desktop's.
        const json = vi.fn(async () => ({ root_pubkey: "k" })) as unknown as RouteJson;
        await expect(accountDirectory(json)).resolves.toEqual({ rootPubkey: "k", origin: "" });
    });
});

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
