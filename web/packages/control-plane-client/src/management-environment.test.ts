import { describe, expect, it, vi } from "vitest";
import type { RouteJson, RouteOptions } from "./control-plane-transport";
import { managementAgentEnvironments, managementEnvironmentKinds, managementRouteNames, managementRoutes, listManagementChanges, openManagementEnvironment, proposeManagementDocumentChange, readManagementDocument, reviewManagementChange, sendManagementAgentMessage, submitManagementCommand, type ManagementCommandEnvelope, type ManagementEnvironmentSession } from "./management-environment";

function fakeJson(response: unknown): { json: RouteJson; calls: [string, string, unknown?, RouteOptions?][] } {
    const calls: [string, string, unknown?, RouteOptions?][] = [];
    const json = vi.fn(async (method: string, path: string, body?: unknown, options?: RouteOptions) => {
        calls.push([method, path, body, options]);
        return response;
    }) as unknown as RouteJson;
    return { json, calls };
}

const session: ManagementEnvironmentSession = {
    id: "environment-session:one", environment: "administration", scope: { kind: "tenant", id: "tenant-a" }, actor: "alice",
    capabilities: ["manage-members"],
    documents: [{ id: "access", path: "access.json", schema: "access/v1", revision: "7", freshness: "live", readable: true, editable: true, commands: ["member.invite"] }],
    commands: [{ id: "member.invite", capability: "manage-members", review: "human" }],
};

describe("management Environment client", () => {
    it("opens and reads only through the session-shaped API", async () => {
        const route = fakeJson({ session, document: { id: "access", revision: "7" } });
        await openManagementEnvironment(route.json, "administration", session.scope);
        await readManagementDocument(route.json, session, "access");
        expect(route.calls).toEqual([
            ["POST", "/environments/administration/sessions", { scope: session.scope }, undefined],
            ["GET", "/environments/administration/documents/access?session=environment-session%3Aone&scope=tenant-a", undefined, undefined],
        ]);
    });
    it("carries one caller key and differs across clients only by evidence label", async () => {
        for (const client of ["browser", "edit", "agent", "cli"] as const) {
            const route = fakeJson({ receipt: { id: "stable" } });
            const envelope: ManagementCommandEnvelope = { session_id: session.id, environment: session.environment, scope: session.scope, document_id: "access", command_id: "member.invite", base_revision: "7", payload: { authority: "bob" }, client };
            await submitManagementCommand(route.json, envelope, "intent-1");
            expect(route.calls[0]).toEqual(["POST", "/environments/administration/commands", envelope, { idempotencyKey: "intent-1" }]);
        }
    });
    it("submits literal edits to the shared changes path", async () => {
        const route = fakeJson({ receipt: { id: "stable" } });
        await proposeManagementDocumentChange(route.json, { session, documentId: "access", baseRevision: "7", content: { members: [] }, client: "edit" }, "edit-1");
        expect(route.calls[0]?.[1]).toBe("/environments/administration/changes");
        expect(route.calls[0]?.[3]).toEqual({ idempotencyKey: "edit-1" });
    });
    it("resolves Hub and Vend through exact served operation tables", async () => {
        const route = fakeJson({ session });
        await openManagementEnvironment(route.json, "hub");
        await openManagementEnvironment(route.json, "vend", {
            kind: "provider-tenant",
            id: "provider:one",
        });
        expect(route.calls).toEqual([
            ["POST", "/environments/hub/sessions", {}, undefined],
            [
                "POST",
                "/environments/vend/sessions",
                { scope: { kind: "provider-tenant", id: "provider:one" } },
                undefined,
            ],
        ]);
    });
    it("refuses a literal change to a document the session did not mark editable", async () => {
        const route = fakeJson({ receipt: { id: "never" } });
        await expect(proposeManagementDocumentChange(
            route.json,
            {
                session,
                documentId: "machines",
                baseRevision: "7",
                content: {},
                client: "edit",
            },
            "edit-ungranted",
        )).rejects.toThrow("not editable in this session");
        expect(route.calls).toEqual([]);
    });
    it("declares every common route for every Environment it can address", () => {
        // The route table is written out per Environment so that the textual
        // client-calls check can see the paths. This is what stops a block
        // added for a new Environment from being quietly incomplete.
        for (const environment of managementEnvironmentKinds) {
            const routes = managementRoutes[environment] as Record<string, { path: string }>;
            for (const name of managementRouteNames) {
                expect(routes[name]?.path).toMatch(
                    new RegExp(`^/environments/${environment}/`),
                );
            }
        }
    });
    it("declares the agent pair for exactly the Environments that run an agent", () => {
        // A TokenWright box runs no agent -- it is a model server, and the only
        // things it answers are its two surfaces. Declaring routes it does not
        // serve would put a control on the page that fails when pressed, which
        // is the bug this route table exists to make impossible.
        for (const environment of managementEnvironmentKinds) {
            const routes = managementRoutes[environment] as Record<string, { path: string } | undefined>;
            const expected = managementAgentEnvironments.includes(environment);
            expect(Boolean(routes.agentRead), `${environment} agentRead`).toBe(expected);
            expect(Boolean(routes.agentSend), `${environment} agentSend`).toBe(expected);
        }
    });
    it("refuses to send an agent message to an Environment that runs no agent", async () => {
        const route = fakeJson({ turn: { message: "never", proposals: [] } });
        const boxSession: ManagementEnvironmentSession = { ...session, environment: "tokenwright" };
        await expect(sendManagementAgentMessage(route.json, boxSession, "hello"))
            .rejects.toThrow(/runs no agent/u);
        expect(route.calls).toHaveLength(0);
    });
    it("serves TokenWright the two routes its box needs beyond the common set", () => {
        // `propose` because selecting a model is a literal edit to a `desired`
        // block -- TokenWright's commands take no parameters at all, so an edit
        // is the only way to say which model to load. `audit` because the box
        // reports a signed head to this Home, and the entries behind an anchor
        // have to be readable for the anchor to be worth anything.
        expect(managementRoutes.tokenwright.propose.path)
            .toBe("/environments/tokenwright/changes");
        expect(managementRoutes.tokenwright.audit.path)
            .toBe("/environments/tokenwright/audit");
    });
    it("lets a TokenWright document be proposed when the grant marks it editable", async () => {
        const route = fakeJson({ receipt: { id: "receipt:tokenwright" } });
        const boxSession: ManagementEnvironmentSession = {
            ...session,
            environment: "tokenwright",
            documents: [{
                id: "tokenwright.inference", path: "inference.json",
                schema: "gw://schemas/tokenwright/inference/v1",
                revision: "rev-1", freshness: "live", readable: true, editable: true,
                commands: [],
            }],
        };
        await proposeManagementDocumentChange(route.json, {
            session: boxSession, documentId: "tokenwright.inference",
            baseRevision: "rev-1", content: { desired: { model: "qwen3-coder-30b" } },
            client: "edit",
        }, "idem-1");
        expect(route.calls[0]?.[1]).toBe("/environments/tokenwright/changes");
    });
    it("refuses a document the grant marks read-only, which the Environment name could not see", async () => {
        const route = fakeJson({ receipt: { id: "never" } });
        const readOnly: ManagementEnvironmentSession = {
            ...session,
            documents: [{ ...session.documents[0]!, editable: false }],
        };
        await expect(proposeManagementDocumentChange(
            route.json,
            { session: readOnly, documentId: "access", baseRevision: "7", content: {}, client: "edit" },
            "edit-readonly",
        )).rejects.toThrow("not editable in this session");
        expect(route.calls).toEqual([]);
    });
    it("refuses a literal change where the control plane serves no such route", async () => {
        const route = fakeJson({ receipt: { id: "never" } });
        const hub: ManagementEnvironmentSession = { ...session, environment: "hub" };
        await expect(proposeManagementDocumentChange(
            route.json,
            { session: hub, documentId: "access", baseRevision: "7", content: {}, client: "edit" },
            "edit-unserved",
        )).rejects.toThrow("serves no literal-change route");
        expect(route.calls).toEqual([]);
    });
    it("lists and reviews changes through the same scoped session", async () => {
        const route = fakeJson({ changes: [], receipt: { id: "stable" }, change: { id: "change-1" } });
        await listManagementChanges(route.json, session);
        await reviewManagementChange(route.json, session, "change-1", "accept", "review-1", "cli");
        expect(route.calls).toEqual([
            ["GET", "/environments/administration/changes?session=environment-session%3Aone&scope=tenant-a", undefined, undefined],
            ["POST", "/environments/administration/changes/change-1/review", { session_id: session.id, environment: session.environment, scope: session.scope, decision: "accept", client: "cli" }, { idempotencyKey: "review-1" }],
        ]);
    });
});
