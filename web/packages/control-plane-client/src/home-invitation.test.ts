import { afterEach, describe, expect, it, vi } from "vitest";
import {
    acceptedHomeRecords,
    acceptHomeInvitation,
    cancelHomeInvitation,
    createHomeInvitation,
    emailHomeInvitation,
    listPendingHomeInvitations,
    parseHomeInvitation,
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

const LOCATOR = {
    endpoint: "wss://relay.example.test",
    handle: "a".repeat(43),
    proof: "b".repeat(43),
    route_epoch: 3,
    home_fingerprint: "c".repeat(64),
};
const PLACEMENT = {
    project_key: "project-key",
    host_key: "host-key",
    placement_signature: "placed",
    locator_signature: "located",
};

/** An invitation from a Home reached only through its relay (DR-0370). */
function relayOnly(overrides: Record<string, unknown> = {}): string {
    return invitation({
        invited_authority: "",
        invited_email: "alex@example.test",
        endpoint: "",
        relay: LOCATOR,
        placement: PLACEMENT,
        owner_root: "owner-root",
        ...overrides,
    });
}

/** Holds only for the placement the invitation's project key signed. */
const placementVerified = vi.fn(async (route: unknown, key: string) =>
    key === "project-key"
    && (route as { placement?: { placement_signature?: unknown } }).placement?.placement_signature === "placed");

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

    it("asks a Home reached only through the relay, which answers with its route", async () => {
        const encoded = relayOnly();
        const route = vi.fn(async () => ({
            invite: encoded,
            url: `https://desk.gaugewright.com/invite?d=${encoded}`,
            expires_at: 123,
        }));
        await expect(createHomeInvitation(route, {
            email: "alex@example.test",
            project: "proj-1" as never,
            endpoint: "   ",
        })).resolves.toMatchObject({ homeId: "home:owner", endpoint: "" });
        expect(route).toHaveBeenCalledWith("POST", "/home/invitations", expect.objectContaining({
            endpoint: "",
        }));
        // A Home nobody can reach says so itself, and that is what is shown.
        const refused = vi.fn(async () => {
            throw new Error("invitations to projects on this computer aren't available until it can be reached from elsewhere");
        });
        await expect(createHomeInvitation(refused, {
            email: "alex@example.test",
            project: "proj-1" as never,
            endpoint: "",
        })).rejects.toThrow(/aren't available until it can be reached from elsewhere/);
    });

    it("reads a relay-only invitation's route and refuses one that carries none", () => {
        expect(parseHomeInvitation(relayOnly())).toEqual({
            authority: "",
            email: "alex@example.test",
            project: "proj-1",
            homeId: "home:owner",
            endpoint: "",
        });
        expect(() => parseHomeInvitation(relayOnly({ relay: undefined }))).toThrow(/requires endpoint/);
        expect(() => parseHomeInvitation(relayOnly({ placement: undefined }))).toThrow(/requires endpoint/);
        expect(() => parseHomeInvitation(relayOnly({ relay: { ...LOCATOR, home_fingerprint: "zz" } })))
            .toThrow(/invalid relay locator/);
    });

    it("accepts through the relay once the route holds against the project key", async () => {
        const encoded = relayOnly();
        const close = vi.fn();
        const asked: unknown[] = [];
        const relayJson = vi.fn((route, bearer: () => string | null) => {
            asked.push(route);
            const json = vi.fn(async (method: string, path: string, body?: unknown) => {
                expect([method, path, body, bearer()]).toEqual([
                    "POST", "/home/invitations/accept", { invite: encoded }, "account-token",
                ]);
                return {
                    home_id: "home:owner",
                    project: "proj-1",
                    endpoint: "",
                    admission: "memory-only-admission",
                    relay: { ...LOCATOR, route_epoch: 4 },
                    placement: PLACEMENT,
                    owner_root: "owner-root",
                };
            });
            return Object.assign(json, { close });
        });
        const accepted = await acceptHomeInvitation(encoded, {
            bearer: () => "account-token",
            relayJson,
            placementVerified,
        });
        expect(asked).toEqual([expect.objectContaining({
            project: "proj-1",
            homeId: "home:owner",
            endpoint: "",
            relay: expect.objectContaining({ routeEpoch: 3 }),
        })]);
        expect(close).toHaveBeenCalled();
        expect(accepted).toMatchObject({
            homeId: "home:owner",
            endpoint: "",
            admission: "memory-only-admission",
            shared: {
                project: "proj-1",
                homeId: "home:owner",
                projectKey: "project-key",
                ownerRoot: "owner-root",
                route: { relay: expect.objectContaining({ route_epoch: 4 }) },
            },
        });
    });

    // A shared project is reached through its pin (DR-0451) and sharing it is
    // not a choice of Home (DR-0455). Registering the owner's Home was refused
    // with a 422 when it had no endpoint (WS-1022), and with a relay locator it
    // replaced the member's own desktop, which carries the same id (WS-1024).
    it("records nothing in the member's account for a project shared from someone's desktop", () => {
        const shared = {
            project: "proj-1" as never,
            homeId: "home:local-user" as never,
            projectKey: "project-key",
            route: { project: "proj-1", home_id: "home:local-user", endpoint: "", relay: LOCATOR, placement: PLACEMENT },
        };
        expect(acceptedHomeRecords({
            authority: "",
            project: "proj-1" as never,
            homeId: "home:local-user" as never,
            endpoint: "",
            admission: "memory-only-admission",
            shared,
        })).toBeNull();
        // Nor for a shared Home that also has an address.
        expect(acceptedHomeRecords({
            authority: "",
            project: "proj-1" as never,
            homeId: "home:owner" as never,
            endpoint: "https://home.example",
            admission: "memory-only-admission",
            shared: { ...shared, homeId: "home:owner" as never },
        })).toBeNull();
    });

    it("registers a Home answered directly, and its project's route, as before", () => {
        const records = acceptedHomeRecords({
            authority: "account:invitee",
            project: "proj-1" as never,
            homeId: "home:owner" as never,
            endpoint: "https://home.example",
            admission: "memory-only-admission",
        });
        expect(records).toEqual({
            home: { id: "home:owner", kind: "registered", endpoint: "https://home.example" },
            route: { project: "proj-1", homeId: "home:owner", endpoint: "https://home.example" },
        });
        expect(JSON.stringify(records)).not.toContain("memory-only-admission");
    });

    it("dials nothing for a relay-only invitation its project key did not sign", async () => {
        const relayJson = vi.fn();
        await expect(acceptHomeInvitation(
            relayOnly({ placement: { ...PLACEMENT, placement_signature: "forged" } }),
            { relayJson, placementVerified },
        )).rejects.toThrow(/not signed by its project's key/);
        expect(relayJson).not.toHaveBeenCalled();
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
