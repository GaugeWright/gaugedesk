import { describe, expect, it, vi } from "vitest";
import type { RouteJson, RouteOptions } from "./control-plane-transport";
import { listManagementChanges, openManagementEnvironment, proposeManagementDocumentChange, readManagementDocument, reviewManagementChange, submitManagementCommand, type ManagementCommandEnvelope, type ManagementEnvironmentSession } from "./management-environment";

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
