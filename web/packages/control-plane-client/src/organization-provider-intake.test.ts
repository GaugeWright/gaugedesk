import { describe, expect, it, vi } from "vitest";
import fixture from "../../../../crates/app/src/model_provider_management/projection/page.fixture.json";
import { submitOrganizationProviderSecret, verifyOrganizationProviderCandidate } from "./organization-provider-intake";
const candidate = { binding: fixture.binding, connection: "connection-a", version: "version-a" };
const ticket = () => ({ v: 1, upload_url: "https://credentials.example.invalid/v1/model-providers/credential", ticket: `abcd.${"a".repeat(64)}`, expires_at: 1999999999 });
const reply = () => ({ v: 1, binding: fixture.binding, page: structuredClone(fixture) });
describe("organization credential intake", () => {
    it("sends only references through Hub and raw bytes directly without account credentials", async () => {
        const json = vi.fn(async () => ticket()); let sent: Uint8Array | undefined;
        const fetcher = vi.fn<typeof fetch>(async (_url, options) => {
            sent = options!.body as Uint8Array;
            expect(new TextDecoder().decode(sent)).toBe("synthetic-key");
            expect(options).toMatchObject({ method: "POST", credentials: "omit", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer", headers: { "Content-Type": "application/octet-stream", Authorization: `Bearer ${ticket().ticket}` } });
            return Response.json(reply());
        });
        await submitOrganizationProviderSecret(json, candidate, "synthetic-key", { signal: new AbortController().signal, fetcher });
        expect(json).toHaveBeenCalledWith("POST", "/gaugeapps/administration/model-providers/intake", { organization: candidate.binding.organization, connection: candidate.connection, version: candidate.version });
        expect(fetcher.mock.calls[0]![0]).toBe(ticket().upload_url);
        expect(sent!.every((value) => value === 0)).toBe(true);
        expect(JSON.stringify(json.mock.calls)).not.toContain("synthetic-key");
    });
    it("does not upload if the form closes while the ticket is pending", async () => {
        const controller = new AbortController(); const fetcher = vi.fn<typeof fetch>();
        const json = async () => { controller.abort(); return ticket(); };
        await expect(submitOrganizationProviderSecret(json, candidate, "synthetic-key", { signal: controller.signal, fetcher })).rejects.toThrow();
        expect(fetcher).not.toHaveBeenCalled();
    });
    it("rejects unsafe destinations, unknown ticket fields, and scope-switched replies", async () => {
        for (const upload_url of ["http://credentials.example.invalid/v1/model-providers/credential", "https://user:password@example.invalid/v1/model-providers/credential", "https://example.invalid/wrong", "https://example.invalid/v1/model-providers/credential?key=leak"]) {
            const fetcher = vi.fn<typeof fetch>();
            await expect(submitOrganizationProviderSecret(async () => ({ ...ticket(), upload_url }), candidate, "synthetic-key", { signal: new AbortController().signal, fetcher })).rejects.toThrow();
            expect(fetcher).not.toHaveBeenCalled();
        }
        await expect(submitOrganizationProviderSecret(async () => ({ ...ticket(), unexpected: true }), candidate, "synthetic-key", { signal: new AbortController().signal })).rejects.toThrow(/incompatible/);
        for (const key of ["authority", "organization", "environment"] as const) {
            const response = reply(); response.binding = { ...response.binding, [key]: "another-scope" };
            await expect(submitOrganizationProviderSecret(async () => ticket(), candidate, "synthetic-key", { signal: new AbortController().signal, fetcher: vi.fn(async () => Response.json(response)) })).rejects.toThrow(/different organization binding/);
        }
    });
    it("never echoes a credential-bearing response body, even malformed successful JSON", async () => {
        for (const status of [200, 400, 401, 403, 409, 500]) {
            let buffer: Uint8Array | undefined;
            const fetcher = vi.fn<typeof fetch>(async (_url, options) => { buffer = options!.body as Uint8Array; return new Response("synthetic-secret-in-provider-response", { status }); });
            try { await submitOrganizationProviderSecret(async () => ticket(), candidate, "synthetic-key", { signal: new AbortController().signal, fetcher }); throw Error("Expected refusal"); }
            catch (error) { expect(String(error)).not.toMatch(/synthetic/); expect(String(error)).toMatch(/upload|permission|candidate|response/i); }
            expect(buffer!.every((value) => value === 0)).toBe(true);
        }
    });
});
describe("organization credential verification", () => {
    it("sends only the exact candidate reference and accepts a bound refreshed page", async () => {
        const json = vi.fn(async () => reply());
        await verifyOrganizationProviderCandidate(json, candidate);
        expect(json).toHaveBeenCalledWith("POST", "/gaugeapps/administration/model-providers/verify", { organization: candidate.binding.organization, connection: candidate.connection, version: candidate.version });
    });
    it("rejects extra fields and every switched binding axis", async () => {
        await expect(verifyOrganizationProviderCandidate(async () => ({ ...reply(), extra: true }), candidate)).rejects.toThrow(/incompatible/);
        for (const key of ["authority", "organization", "environment"] as const) {
            const response = reply(); response.binding = { ...response.binding, [key]: "another-scope" };
            await expect(verifyOrganizationProviderCandidate(async () => response, candidate)).rejects.toThrow(/different organization binding/);
        }
    });
});
