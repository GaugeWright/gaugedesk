import { describe, expect, it, vi } from "vitest";
import {
    accountAttachFacility,
    accountDetachFacility,
    accountFacilities,
    accountInvitations,
    accountPublishLibrarySync,
    accountPullLibrarySync,
    accountSignInMethod,
    accountTenants,
    acceptAccountInvitation,
    createOrganization,
    materializeOrganizationSharedProject,
    organizationSharedProject,
    hubSessionTenants,
    parseFacility,
    parseInvitation,
    parseAccountSignInMethod,
    parseProjectShareCandidate,
    parseTenant,
    tenantFacilities,
    tenantProjectShareCandidates,
    tenantProjectShareDirectory,
} from "./control-plane-tenant";
import type { RouteJson } from "./control-plane-transport";

/** A RouteJson double that records calls and returns a canned response. */
function fakeJson(response: unknown): { json: RouteJson; calls: [string, string, unknown?][] } {
    const calls: [string, string, unknown?][] = [];
    const json = vi.fn(async (method: string, path: string, body?: unknown) => {
        calls.push([method, path, body]);
        return response;
    }) as unknown as RouteJson;
    return { json, calls };
}

describe("control-plane-tenant (ADR 0077 §7/§9)", () => {
    it("lists facilities, mapping snake_case + defaulting missing fields", async () => {
        const { json, calls } = fakeJson({
            facilities: [
                { id: "lib", kind: "library_sync", owner: "person", status: "active", display_name: "Library sync" },
                { id: "bare" }, // degrades field-by-field
            ],
        });
        const out = await accountFacilities(json);
        expect(calls[0]).toEqual(["GET", "/account/facilities", undefined]);
        expect(out[0]).toEqual({
            id: "lib",
            kind: "library_sync",
            owner: "person",
            status: "active",
            displayName: "Library sync",
        });
        // a bare record defaults kind/owner/status, empty display name.
        expect(out[1]).toEqual({ id: "bare", kind: "library_sync", owner: "person", status: "active", displayName: "" });
    });

    it("lists only the selected tenant's facility-section metadata", async () => {
        const { json, calls } = fakeJson({
            facilities: [{ id: "backup", kind: "cloud_backup", owner: "tenant", status: "active", display_name: "Backups" }],
        });
        await expect(tenantFacilities(json, "organization/acme")).resolves.toEqual([{
            id: "backup", kind: "cloud_backup", owner: "tenant", status: "active", displayName: "Backups",
        }]);
        expect(calls).toEqual([[
            "GET", "/account/tenants/organization%2Facme/facilities", undefined,
        ]]);
    });

    it("attaches a facility, sending display_name (snake_case) and returning the parsed record", async () => {
        const { json, calls } = fakeJson({ facility: { id: "lib", kind: "library_sync", display_name: "Library sync" } });
        const f = await accountAttachFacility(json, { id: "lib", kind: "library_sync", displayName: "Library sync" });
        expect(calls[0]).toEqual(["POST", "/account/facilities", { id: "lib", kind: "library_sync", display_name: "Library sync" }]);
        expect(f.id).toBe("lib");
        expect(f.displayName).toBe("Library sync");
    });

    it("detaches a facility, url-encoding the id", async () => {
        const { json, calls } = fakeJson({});
        await accountDetachFacility(json, "lib/one");
        expect(calls[0]).toEqual(["DELETE", "/account/facilities/lib%2Fone", undefined]);
    });

    it("publishes and pulls library sync only through the declared account routes", async () => {
        const publish = fakeJson({ published: true });
        await accountPublishLibrarySync(publish.json);
        expect(publish.calls).toEqual([["POST", "/account/library-sync", undefined]]);

        const pull = fakeJson({ found: true, merged: 3.8, routes_verified: true });
        await expect(accountPullLibrarySync(pull.json)).resolves.toEqual({
            found: true,
            merged: 3,
            retracted: 0,
            routesVerified: true,
            declined: null,
        });
        expect(pull.calls).toEqual([["POST", "/account/library-sync/pull", undefined]]);
        await expect(accountPullLibrarySync(fakeJson({ merged: "many" }).json))
            .resolves.toEqual({
                found: false,
                merged: 0,
                retracted: 0,
                routesVerified: false,
                declined: null,
            });

        // A pull that merged the sealed half but refused the routing reports
        // both facts. Absent `routes_verified` reads as unverified, never as
        // verified-by-omission: a desktop older than this field is one that
        // merged routes without checking them.
        await expect(
            accountPullLibrarySync(
                fakeJson({
                    found: true,
                    merged: 2,
                    routes_verified: false,
                    declined: "the directory served a record with no root signature",
                }).json,
            ),
        ).resolves.toEqual({
            found: true,
            merged: 2,
            retracted: 0,
            routesVerified: false,
            declined: "the directory served a record with no root signature",
        });

        // A snapshot retracts by omission (ADR 0154), so a pull can remove a
        // stale locator. That is a removal and is counted as one.
        await expect(
            accountPullLibrarySync(
                fakeJson({ found: true, merged: 1, retracted: 2, routes_verified: true }).json,
            ),
        ).resolves.toEqual({
            found: true,
            merged: 1,
            retracted: 2,
            routesVerified: true,
            declined: null,
        });
    });

    it("lists tenants and flags the personal one", async () => {
        const { json } = fakeJson({
            tenants: [{ id: "personal:root", display_name: "Personal", role: "owner", personal: true }],
        });
        const out = await accountTenants(json);
        expect(out).toEqual([{ id: "personal:root", displayName: "Personal", role: "owner", personal: true, providerCommercial: false }]);
    });

    it("lists the same safe tenant projection through Desktop's sealed Hub session", async () => {
        const { json, calls } = fakeJson({
            tenants: [{ id: "tenant:canary", display_name: "Canary", role: "admin", personal: false }],
        });
        await expect(hubSessionTenants(json)).resolves.toEqual([{
            id: "tenant:canary",
            displayName: "Canary",
            role: "admin",
            personal: false,
            providerCommercial: false,
        }]);
        expect(calls).toEqual([["GET", "/account/hub-session/tenants", undefined]]);
    });

    it("creates a named organization through the account command", async () => {
        const { json, calls } = fakeJson({
            tenant: { id: "organization:abc", display_name: "Acme Studio", role: "owner", personal: false },
        });
        await expect(createOrganization(json, "Acme Studio")).resolves.toEqual({
            id: "organization:abc",
            displayName: "Acme Studio",
            role: "owner",
            personal: false,
            providerCommercial: false,
        });
        expect(calls).toEqual([["POST", "/account/tenants", { display_name: "Acme Studio" }]]);
    });

    it("reads the pending shared project and sends its exact Home materialization request", async () => {
        expect(parseTenant({
            id: "organization:ab", display_name: "Acme", role: "owner", personal: false,
            shared_project: { id: "shared", project_id: "proj-org-ab", founding_owner: "alice",
                display_name: "Acme", home_id: null },
        }).sharedProject).toMatchObject({ projectId: "proj-org-ab", homeId: null });
        const pending = fakeJson({ project: {
            id: "shared", project_id: "proj-org-ab", founding_owner: "alice",
            display_name: "Acme", home_id: null,
        } });
        await expect(organizationSharedProject(pending.json, "organization:ab")).resolves.toEqual({
            id: "shared", projectId: "proj-org-ab", foundingOwner: "alice",
            displayName: "Acme", homeId: null,
        });
        expect(pending.calls).toEqual([
            ["GET", "/account/tenants/organization%3Aab/shared-project", undefined],
        ]);
        const home = fakeJson({ project: { id: "proj-org-ab" } });
        await expect(materializeOrganizationSharedProject(
            home.json, "organization:ab", true,
        )).resolves.toBe("proj-org-ab");
        expect(home.calls).toEqual([[
            "POST", "/organizations/organization%3Aab/shared-project/materialize",
            { personal_default: true },
        ]]);
    });

    it("lists and accepts metadata-only tenant invitations", async () => {
        const { json, calls } = fakeJson({
            invitations: [{ tenant_id: "organization:acme", display_name: "Acme Studio", role: "member" }],
        });
        await expect(accountInvitations(json)).resolves.toEqual([{
            tenantId: "organization:acme", displayName: "Acme Studio", role: "member",
        }]);
        expect(calls).toEqual([["GET", "/account/invitations", undefined]]);

        const accepted = fakeJson({
            tenant: { id: "organization:acme", display_name: "Acme Studio", role: "member", personal: false },
        });
        await expect(acceptAccountInvitation(accepted.json, "organization:acme")).resolves.toEqual({
            id: "organization:acme", displayName: "Acme Studio", role: "member", personal: false, providerCommercial: false,
        });
        expect(accepted.calls).toEqual([[
            "POST", "/account/invitations/organization%3Aacme/accept", undefined,
        ]]);
    });

    it("reads the current session's safe sign-in-method label", async () => {
        const { json, calls } = fakeJson({ method: "google", label: "Google" });
        await expect(accountSignInMethod(json)).resolves.toEqual({ method: "google", label: "Google" });
        expect(calls).toEqual([["GET", "/auth/session", undefined]]);
    });

    it("reads project-share candidates from the exact encoded tenant", async () => {
        const { json, calls } = fakeJson({
            candidates: [
                { authority: "authority:alex", label: "alex@example.test" },
                { authority: "", label: "malformed" },
            ],
        });
        await expect(tenantProjectShareCandidates(json, "organization/acme")).resolves.toEqual([{
            authority: "authority:alex",
            label: "alex@example.test",
        }]);
        expect(calls).toEqual([[
            "GET", "/account/tenants/organization%2Facme/project-share-candidates", undefined,
        ]]);
    });

    it("reads an organization's sharing policy, members only unless it says anyone", async () => {
        await expect(tenantProjectShareDirectory(fakeJson({ candidates: [], sharing: "anyone" }).json, "organization:a"))
            .resolves.toEqual({ candidates: [], sharing: "anyone" });
        for (const sharing of [undefined, "members", "ANYONE", 1]) {
            await expect(tenantProjectShareDirectory(fakeJson({ candidates: [], sharing }).json, "organization:a"))
                .resolves.toMatchObject({ sharing: "members" });
        }
    });

    it("is total: garbage / empty envelopes degrade to empty lists, never throw", async () => {
        expect(await accountFacilities(fakeJson(null).json)).toEqual([]);
        expect(await accountFacilities(fakeJson({ facilities: "nope" }).json)).toEqual([]);
        expect(await accountTenants(fakeJson({}).json)).toEqual([]);
        expect(parseFacility(null).id).toBe("");
        expect(parseTenant(undefined).personal).toBe(false);
        expect(parseInvitation(undefined).tenantId).toBe("");
        expect(parseAccountSignInMethod(undefined)).toEqual({ method: "", label: "" });
        expect(parseProjectShareCandidate(undefined)).toEqual({ authority: "", label: "" });
    });
});
