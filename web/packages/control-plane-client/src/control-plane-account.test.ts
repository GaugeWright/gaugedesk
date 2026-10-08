import { describe, expect, it, vi } from "vitest";
import { accountDevices, accountDirectory, hubSessionSelectLocal, keepSharedProjectPin, parseAccountDevice } from "./control-plane-account";
import type { RouteJson } from "./control-plane-transport";

describe("explicit local desktop posture", () => {
    it("requires the server to confirm local mode before returning to the owner Home", async () => {
        const selected = vi.fn(async () => ({ available: true, linked: false, local: true })) as unknown as RouteJson;
        await expect(hubSessionSelectLocal(selected)).resolves.toMatchObject({
            linked: false, local: true, localChoiceRequired: false,
        });
        expect(selected).toHaveBeenCalledWith("POST", "/account/hub-session/select-local", {});
        const refused = vi.fn(async () => ({ available: true, linked: false })) as unknown as RouteJson;
        await expect(hubSessionSelectLocal(refused)).rejects.toThrow("not selected");
    });
});

describe("a shared project's pin on this computer (DR-0458)", () => {
    it("hands the computer exactly the pin the invitation carried", async () => {
        const json = vi.fn(async () => ({ project: "p-shared" })) as unknown as RouteJson;
        await keepSharedProjectPin(json, {
            project: "p-shared",
            homeId: "home:owner",
            projectKey: "project-key",
            ownerRoot: "owner-root",
        });
        expect(json).toHaveBeenCalledWith("POST", "/account/shared-projects", {
            project: "p-shared",
            home_id: "home:owner",
            project_key: "project-key",
            owner_root: "owner-root",
        });
    });
});

describe("the account directory projection (DESK-5f)", () => {
    it("reads which root signs the record and where it lives", async () => {
        const json = vi.fn(async () => ({
            root_pubkey: "ed25519:abc",
            origin: "https://directory.example/",
            subject: "person-1",
        })) as unknown as RouteJson;
        await expect(accountDirectory(json)).resolves.toEqual({
            rootPubkey: "ed25519:abc",
            origin: "https://directory.example",
            subject: "person-1",
            transitions: [],
        });
    });

    it("carries no subject when the hub is too old to name one", async () => {
        // A browser holds no bearer to read claims from, so the hub naming the
        // session's person is the only way this page can namespace its pin. An
        // older hub omits it, and the caller must be left exactly where it was
        // rather than pinning everyone under "".
        const json = vi.fn(async () => ({
            root_pubkey: "ed25519:abc",
            origin: "https://directory.example",
        })) as unknown as RouteJson;
        await expect(accountDirectory(json)).resolves.toEqual({
            rootPubkey: "ed25519:abc",
            origin: "https://directory.example",
            subject: "",
            transitions: [],
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

    it("carries the hub's root hand-overs for the verifier to follow (DR-0361)", async () => {
        const handOver = { from: "a", to: "k", issued_at_ms: 1, signature: "s" };
        const json = vi.fn(async () => ({
            root_pubkey: "k",
            transitions: [handOver],
        })) as unknown as RouteJson;
        await expect(accountDirectory(json)).resolves.toMatchObject({ transitions: [handOver] });
        const malformed = vi.fn(async () => ({ root_pubkey: "k", transitions: "x" })) as unknown as RouteJson;
        await expect(accountDirectory(malformed)).resolves.toMatchObject({ transitions: [] });
    });

    it("falls back to no origin rather than inventing one", async () => {
        // The caller owns the canonical default; a client-side guess here would
        // silently disagree with the desktop's.
        const json = vi.fn(async () => ({ root_pubkey: "k" })) as unknown as RouteJson;
        await expect(accountDirectory(json)).resolves.toEqual({
            rootPubkey: "k",
            origin: "",
            subject: "",
            transitions: [],
        });
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
