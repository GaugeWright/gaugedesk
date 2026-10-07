import { afterEach, describe, expect, it, vi } from "vitest";
import {
    acceptHomeInvitation,
    cancelHomeInvitation,
    createHomeInvitation,
    emailHomeInvitation,
    listPendingHomeInvitations,
    parseHomeInvitation,
    RELAY_ONLY_INVITATION,
    RelayOnlyHomeInvitationError,
    resendHomeInvitation,
} from "./home-invitation";

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

    it("refuses before asking when the Home is reached only through the relay", async () => {
        const route = vi.fn();
        for (const recipient of [{ authority: "account:invitee" }, { email: "alex@example.test" }]) {
            await expect(createHomeInvitation(route, {
                ...recipient,
                project: "proj-1" as never,
                endpoint: "",
            })).rejects.toBeInstanceOf(RelayOnlyHomeInvitationError);
        }
        await expect(createHomeInvitation(route, {
            authority: "account:invitee",
            project: "proj-1" as never,
            endpoint: "   ",
        })).rejects.toThrow(RELAY_ONLY_INVITATION);
        expect(route).not.toHaveBeenCalled();
    });

    it("carries an email invitation's address and no account until it is accepted", async () => {
        const encoded = invitation({ invited_authority: "", invited_email: "alex@example.test" });
        expect(parseHomeInvitation(encoded)).toEqual({
            authority: "",
            email: "alex@example.test",
            project: "proj-1",
            homeId: "home:owner",
            endpoint: "https://home.example",
        });
        expect(() => parseHomeInvitation(invitation({ invited_authority: "" }))).toThrow(/invited authority/);
        const route = vi.fn(async () => ({
            invite: encoded,
            url: `https://desk.gaugewright.com/invite?d=${encoded}`,
            expires_at: 123,
        }));
        await expect(createHomeInvitation(route, {
            email: " Alex@Example.test ",
            project: "proj-1" as never,
            endpoint: "https://home.example",
        })).resolves.toMatchObject({ homeId: "home:owner" });
        expect(route).toHaveBeenCalledWith("POST", "/home/invitations", expect.not.objectContaining({
            authority: expect.anything(),
        }));
        await expect(createHomeInvitation(route, {
            email: "someone-else@example.test",
            project: "proj-1" as never,
            endpoint: "https://home.example",
        })).rejects.toThrow(/malformed/);
    });

    it("asks the account service to email an invitation and reports where it went", async () => {
        const route = vi.fn(async () => ({ sent_to: "alex@example.test" }));
        await expect(emailHomeInvitation(route, "abcd")).resolves.toBe("alex@example.test");
        expect(route).toHaveBeenCalledWith("POST", "/account/project-invitations/email", { invite: "abcd" });
        await expect(emailHomeInvitation(vi.fn(async () => ({})), "abcd")).rejects.toThrow();
    });

    it("lists, cancels and resends pending invitations without ever reading a link", async () => {
        const route = vi.fn(async (method: string, path: string) => {
            if (method === "GET") {
                return {
                    invitations: [
                        { id: "hinv-1", authority: "", email: "alex@example.test", role: "viewer", expires_at: 9 },
                        { id: "hinv-2", authority: "account:sam", email: null, role: "member", expires_at: 10 },
                        { id: "", authority: "x", expires_at: 1 },
                        { id: "hinv-3", authority: "", email: null, expires_at: 1 },
                    ],
                };
            }
            if (path.endsWith("/resend")) {
                return { invite: invitation(), url: "https://desk.gaugewright.com/invite?d=x", expires_at: 11 };
            }
            return null;
        });
        await expect(listPendingHomeInvitations(route, "proj/1" as never)).resolves.toEqual([
            { id: "hinv-1", authority: "", email: "alex@example.test", role: "viewer", expiresAt: 9 },
            { id: "hinv-2", authority: "account:sam", email: null, role: "member", expiresAt: 10 },
        ]);
        expect(route).toHaveBeenCalledWith("GET", "/home/projects/proj%2F1/invitations");
        await cancelHomeInvitation(route, "hinv-1");
        expect(route).toHaveBeenCalledWith("POST", "/home/invitations/hinv-1/cancel", {});
        await expect(resendHomeInvitation(route, "hinv-2")).resolves.toMatchObject({ expiresAt: 11, homeId: "home:owner" });
    });
});
