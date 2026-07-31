import { afterEach, describe, expect, it, vi } from "vitest";
import { acceptHomeInvitation, createHomeInvitation, parseHomeInvitation } from "./home-invitation";

function invitation(overrides: Record<string, unknown> = {}): string {
    const value = JSON.stringify({
        version: 1,
        invitation: "hinv-1",
        invited_authority: "account:invitee",
        project: "proj-1",
        home_id: "home:owner",
        endpoint: "https://home.example/",
        secret: "never-render-this",
        ...overrides,
    });
    return Array.from(new TextEncoder().encode(value), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

afterEach(() => vi.unstubAllGlobals());

describe("ordinary Home invitations", () => {
    it("returns only safe preview fields and rejects malformed or insecure capabilities", () => {
        expect(parseHomeInvitation(invitation())).toEqual({
            authority: "account:invitee",
            project: "proj-1",
            homeId: "home:owner",
            endpoint: "https://home.example",
        });
        expect(JSON.stringify(parseHomeInvitation(invitation()))).not.toContain("never-render-this");
        expect(() => parseHomeInvitation("garbage")).toThrow(/malformed/);
        expect(() => parseHomeInvitation(invitation({ endpoint: "http://remote.example" }))).toThrow(
            /insecure endpoint/,
        );
    });

    it("accepts on the target Home with account auth and refuses a mismatched response", async () => {
        const encoded = invitation();
        const fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
            expect(new Headers(init?.headers).get("authorization")).toBe("Bearer account-token");
            expect(String(init?.body)).toContain(encoded);
            return new Response(JSON.stringify({
                home_id: "home:owner",
                project: "proj-1",
                endpoint: "https://home.example",
                admission: "memory-only-admission",
            }));
        });
        vi.stubGlobal("fetch", fetch);
        await expect(acceptHomeInvitation(encoded, { bearer: () => "account-token" })).resolves.toMatchObject({
            homeId: "home:owner",
            project: "proj-1",
            admission: "memory-only-admission",
        });
        expect(fetch).toHaveBeenCalledWith(
            "https://home.example/home/invitations/accept",
            expect.objectContaining({ credentials: "include" }),
        );

        fetch.mockResolvedValueOnce(new Response(JSON.stringify({
            home_id: "home:liar",
            project: "proj-1",
            endpoint: "https://home.example",
            admission: "token",
        })));
        await expect(acceptHomeInvitation(encoded)).rejects.toThrow(/did not match/);
    });

    it("validates an owner-created invitation against the command", async () => {
        const encoded = invitation();
        const route = vi.fn(async () => ({
            invite: encoded,
            url: `https://desk.gaugewright.com/invite?d=${encoded}`,
            expires_at: 123,
        }));
        await expect(createHomeInvitation(route, {
            authority: "account:invitee",
            project: "proj-1" as never,
            endpoint: "https://home.example",
        })).resolves.toMatchObject({ homeId: "home:owner", expiresAt: 123 });
        expect(route).toHaveBeenCalledWith("POST", "/home/invitations", expect.objectContaining({
            authority: "account:invitee",
            project: "proj-1",
        }));
    });
});
