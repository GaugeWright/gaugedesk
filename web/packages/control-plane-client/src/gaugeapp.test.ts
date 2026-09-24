import { describe, expect, it, vi } from "vitest";
import {
    claimAccountDeviceLink,
    completeAccountDeviceLink,
    eraseGaugeAppAgentTranscript,
    finishAccountAuthorization,
    gaugeAppKinds,
    gaugeAppRoutes,
    listGaugeAppAgentMessages,
    listGaugeAppProposals,
    openGaugeApp,
    parseGaugeAppAgentLiveFrame,
    parseGaugeAppUpdateSnapshot,
    prepareGaugeAppProposal,
    readGaugeAppPage,
    readAccountDeviceLink,
    readGaugeAppUpdates,
    reviewGaugeAppProposal,
    sendGaugeAppAgentMessage,
    stopGaugeAppAgentTurn,
    startAccountAuthorization,
    startConsumerOidcLink,
    startConsumerOidcAvatar,
    subscribeGaugeAppAgentEvents,
    submitGaugeAppCommand,
    submitAccountProviderSecret,
    submitOrganizationSsoCredential,
    type GaugeAppCommandEnvelope,
    type GaugeAppSession,
} from "./gaugeapp";
import { administrationEmptyModels } from "./gaugeapp-administration-models.fixture";

function fakeJson(response: unknown = {}) {
    const calls: [string, string, unknown?, unknown?][] = [];
    const json = vi.fn(async (method: string, path: string, body?: unknown, options?: unknown) => {
        calls.push([method, path, body, options]);
        return response;
    });
    return { json: json as never, calls };
}

const session: GaugeAppSession = {
    id: "gaugeapp-session:one",
    generation: "generation-7",
    app: "administration",
    scope: { kind: "tenant", id: "tenant-a" },
    actor: "person:alice",
    capabilities: ["manage-members"],
    pages: [{
        id: "people",
        read_model: "PeoplePageV1",
        version: 1,
        resource_basis: "basis-9",
        freshness: "live",
        availability: "available",
        commands: ["people.invitation.create"],
    }],
    commands: [{ id: "people.invitation.create", capability: "manage-members", review: "human" }],
    update_cursor: "cursor-9",
};

const envelope = (client: "desktop" | "web" | "agent" = "web"): GaugeAppCommandEnvelope => ({
    session_id: session.id,
    generation: session.generation,
    app: session.app,
    scope: session.scope,
    page_id: "people",
    command_id: "people.invitation.create",
    expected_basis: "basis-9",
    idempotency_key: `invite-${client}`,
    payload: { authority: "person:bob" },
    client,
});

describe("typed GaugeApp client", () => {
    it("names exactly the three accepted Apps with complete literal routes", () => {
        expect(gaugeAppKinds).toEqual(["account-settings", "administration", "commercial-operations"]);
        expect(Object.keys(gaugeAppRoutes)).toEqual(gaugeAppKinds);
        for (const app of gaugeAppKinds) {
            const routes = Object.keys(gaugeAppRoutes[app]).sort();
            expect(routes).toEqual(app === "account-settings" ? [
                "agentErase", "agentEvents", "agentRead", "agentSend", "agentStop", "command", "consumerOidcAvatar", "consumerOidcLink", "deviceLinkClaim", "deviceLinkComplete", "deviceLinkRead", "page", "proposals", "providerSecret", "review", "session", "updates",
            ] : app === "administration" ? [
                "agentErase", "agentEvents", "agentRead", "agentSend", "agentStop", "command", "page", "proposals", "providerCredential", "providerIntake", "providerVerify", "review", "session", "ssoCredential", "updates",
            ] : [
                "agentErase", "agentEvents", "agentRead", "agentSend", "agentStop", "command", "page", "proposals", "review", "session", "updates",
            ]);
        }
    });

    it("submits organization OIDC credentials only through the write-only route", async () => {
        const route = fakeJson({ receipt: { status: "applied" } });
        const credentialEnvelope: GaugeAppCommandEnvelope = {
            ...envelope("web"),
            app: "administration",
            scope: { kind: "tenant", id: "organization:acme" },
            page_id: "enterprise-identity",
            command_id: "enterprise-identity.connection.credential.set",
            idempotency_key: "sso-secret-1",
            payload: { connection_revision: "revision-1" },
        };
        await submitOrganizationSsoCredential(route.json, credentialEnvelope, "oidc-secret");
        expect(route.calls[0]).toEqual([
            "POST",
            "/gaugeapps/administration/enterprise-identity/credential",
            { envelope: credentialEnvelope, secret: "oidc-secret" },
            { idempotencyKey: "sso-secret-1" },
        ]);
        await expect(submitOrganizationSsoCredential(route.json, envelope("web"), "secret"))
            .rejects.toThrow(/enterprise identity/);
    });

    it("submits provider credentials only through the sealed account route", async () => {
        const route = fakeJson({ receipt: { status: "applied" }, result: { connection_id: "openai" } });
        const providerEnvelope: GaugeAppCommandEnvelope = {
            ...envelope("web"),
            app: "account-settings",
            scope: { kind: "person", id: "person:alice" },
            page_id: "provider-connections",
            command_id: "provider-connection.api-key.add",
            idempotency_key: "provider-openai-1",
            payload: { provider: "openai", label: "OpenAI API" },
        };
        await submitAccountProviderSecret(route.json, providerEnvelope, "sk-example");
        expect(route.calls[0]).toEqual([
            "POST",
            "/gaugeapps/account-settings/provider-connections/secrets",
            { envelope: providerEnvelope, secret: "sk-example" },
            { idempotencyKey: "provider-openai-1" },
        ]);
        await expect(submitAccountProviderSecret(route.json, envelope("web"), "secret"))
            .rejects.toThrow(/Account Settings/);
    });

    it("starts consumer linking through the authenticated account route", async () => {
        const route = fakeJson({ authorization_url: "https://accounts.example.test/authorize" });
        await expect(startConsumerOidcLink(route.json)).resolves.toBe("https://accounts.example.test/authorize");
        expect(route.calls).toEqual([
            ["POST", "/auth/account/consumer-oidc/link/start", undefined, undefined],
        ]);
        await expect(startConsumerOidcLink(fakeJson({ authorization_url: "javascript:alert(1)" }).json))
            .rejects.toThrow(/valid provider authorization URL/);
    });

    it("starts the photo re-fetch through its own authenticated account route", async () => {
        const route = fakeJson({ authorization_url: "https://accounts.example.test/authorize" });
        await expect(startConsumerOidcAvatar(route.json)).resolves.toBe("https://accounts.example.test/authorize");
        expect(route.calls).toEqual([
            ["POST", "/auth/account/consumer-oidc/avatar/start", undefined, undefined],
        ]);
        await expect(startConsumerOidcAvatar(fakeJson({ authorization_url: "http://accounts.example.test" }).json))
            .rejects.toThrow(/valid provider authorization URL/);
    });

    it("uses purpose-built account routes for the two-sided device ceremony", async () => {
        const route = fakeJson({ link: { id: "link-1" } });
        const claim = {
            human_code: "ABCD-1234",
            label: "Phone",
            kind: "phone" as const,
            subkey_pubkey: "04device",
        };
        await claimAccountDeviceLink(route.json, claim, "claim-1");
        await readAccountDeviceLink(route.json, "link-1");
        await completeAccountDeviceLink(route.json, "link-1", {
            account_key_proof: "proof",
            signature: "signature",
        }, "complete-1");
        expect(route.calls).toEqual([
            ["POST", "/gaugeapps/account-settings/device-links/claim", claim, { idempotencyKey: "claim-1" }],
            ["GET", "/gaugeapps/account-settings/device-links/link-1", undefined, undefined],
            ["POST", "/gaugeapps/account-settings/device-links/link-1/complete", {
                account_key_proof: "proof",
                signature: "signature",
            }, { idempotencyKey: "complete-1" }],
        ]);
    });

    it("carries generation and exact scope on every read", async () => {
        const route = fakeJson({ page: {
            app: session.app, scope: session.scope,
            id: "people", read_model: "PeoplePageV1", version: 1,
            resource_basis: "basis-9", freshness: "live", model: administrationEmptyModels.people,
        } });
        await readGaugeAppPage(route.json, session, "people");
        expect(route.calls[0]?.[1]).toBe(
            "/gaugeapps/administration/pages/people?session=gaugeapp-session%3Aone&generation=generation-7&scope=tenant-a",
        );
    });

    it("binds command idempotency in both envelope and request metadata", async () => {
        const route = fakeJson({ receipt: { status: "applied" }, result: { recovery_codes: ["shown-once"] } });
        const command = envelope("desktop");
        const response = await submitGaugeAppCommand(route.json, command);
        expect(route.calls[0]).toEqual([
            "POST", "/gaugeapps/administration/commands", command, { idempotencyKey: "invite-desktop" },
        ]);
        expect(response.result).toEqual({ recovery_codes: ["shown-once"] });
    });

    it("reserves proposal preparation for the agent", async () => {
        const route = fakeJson({ receipt: { status: "proposed" } });
        await expect(prepareGaugeAppProposal(route.json, envelope("web"))).rejects.toThrow(/agent/);
        const proposal = envelope("agent");
        await prepareGaugeAppProposal(route.json, proposal);
        expect(route.calls[0]?.[1]).toBe("/gaugeapps/administration/proposals");
    });

    it("carries message idempotency and stable-session coordinates", async () => {
        const route = fakeJson({ turn: { message: "ok", proposals: [] } });
        await sendGaugeAppAgentMessage(route.json, session, "Explain access.", "message-1");
        expect(route.calls[0]).toEqual([
            "POST",
            "/gaugeapps/administration/agent/messages",
            {
                session_id: session.id,
                generation: session.generation,
                scope: session.scope,
                idempotency_key: "message-1",
                message: "Explain access.",
            },
            { idempotencyKey: "message-1" },
        ]);
    });

    it("stops only the exact admitted management session", async () => {
        const route = fakeJson({ stopped: true });
        await expect(stopGaugeAppAgentTurn(route.json, session)).resolves.toBe(true);
        expect(route.calls[0]).toEqual([
            "POST",
            "/gaugeapps/administration/agent/stop",
            {
                session_id: session.id,
                generation: session.generation,
                scope: session.scope,
            },
            undefined,
        ]);
    });

    it("erases only the exact admitted management thread with an idempotent request", async () => {
        const route = fakeJson({ erasure: { thread_id: "thread-1", generation: 2 } });
        await expect(
            eraseGaugeAppAgentTranscript(route.json, session, "erase-1"),
        ).resolves.toEqual({ thread_id: "thread-1", generation: 2 });
        expect(route.calls[0]).toEqual([
            "POST",
            "/gaugeapps/administration/agent/erase",
            {
                session_id: session.id,
                generation: session.generation,
                scope: session.scope,
                idempotency_key: "erase-1",
            },
            { idempotencyKey: "erase-1" },
        ]);
    });

    it("subscribes to the exact admitted management session and resumes by opaque cursor", () => {
        const onFrame = vi.fn();
        const close = vi.fn();
        const events = vi.fn((_path: string, onMessage: (data: string) => void) => {
            onMessage(JSON.stringify({
                cursor: "turn-1:3",
                thread_id: "thread-1",
                turn_id: "turn-1",
                sequence: 3,
                event: { type: "tool-result", call_id: "call-1", ok: true },
            }));
            return close;
        });

        const dispose = subscribeGaugeAppAgentEvents(
            events as never,
            session,
            onFrame,
            "turn-1:2",
        );

        expect(events.mock.calls[0]?.[0]).toBe(
            "/gaugeapps/administration/agent/events?session=gaugeapp-session%3Aone&generation=generation-7&scope=tenant-a&after=turn-1%3A2",
        );
        expect(onFrame).toHaveBeenCalledWith({
            cursor: "turn-1:3",
            thread_id: "thread-1",
            turn_id: "turn-1",
            sequence: 3,
            event: { type: "tool-result", call_id: "call-1", ok: true },
        });
        dispose();
        expect(close).toHaveBeenCalledOnce();
    });

    it("rejects malformed live management frames instead of inventing defaults", () => {
        expect(() => parseGaugeAppAgentLiveFrame({
            cursor: "turn-1:0",
            thread_id: "thread-1",
            turn_id: "turn-1",
            sequence: 0,
            event: { type: "tool-result", call_id: "call-1", ok: "yes" },
        })).toThrow(/agent-event\.event\.ok/);
    });

    it("uses the resumable cursor for proposals, transcript, review, and invalidations", async () => {
        const route = fakeJson({
            proposals: [],
            thread: { id: "thread-1", cursor: "message-8", messages: [] },
            invalidations: [],
            cursor: "cursor-9",
        });
        await listGaugeAppProposals(route.json, session);
        await listGaugeAppAgentMessages(route.json, session, "message-7");
        await reviewGaugeAppProposal(route.json, session, "proposal-1", "accept", "review-1", "desktop", "proof-1");
        await readGaugeAppUpdates(route.json, session, "cursor-8");
        expect(route.calls.map((call) => call[1])).toEqual([
            "/gaugeapps/administration/proposals?session=gaugeapp-session%3Aone&generation=generation-7&scope=tenant-a",
            "/gaugeapps/administration/agent/messages?session=gaugeapp-session%3Aone&generation=generation-7&scope=tenant-a&after=message-7",
            "/gaugeapps/administration/proposals/proposal-1/review",
            "/gaugeapps/administration/updates?session=gaugeapp-session%3Aone&generation=generation-7&scope=tenant-a&after=cursor-8",
        ]);
        expect(route.calls[2]?.[2]).toMatchObject({ authorization_proof: "proof-1" });
    });

    it("keeps fresh authorization in its response-only passkey ceremony", async () => {
        const start = fakeJson({ ceremony_id: "ceremony-1", public_key: { challenge: "abc" } });
        await expect(startAccountAuthorization(start.json, "organization.delete")).resolves.toEqual({
            ceremony_id: "ceremony-1",
            public_key: { challenge: "abc" },
        });
        expect(start.calls[0]).toEqual([
            "POST",
            "/auth/account/authorization/start",
            { operation: "organization.delete" },
            undefined,
        ]);

        const finish = fakeJson({ authorization_proof: "proof-1", expires_in: 300 });
        await expect(finishAccountAuthorization(
            finish.json,
            "ceremony-1",
            { id: "credential-1" },
        )).resolves.toBe("proof-1");
        expect(finish.calls[0]).toEqual([
            "POST",
            "/auth/account/authorization/finish",
            { ceremony_id: "ceremony-1", credential: { id: "credential-1" } },
            undefined,
        ]);
    });

    it("validates update snapshots before they can invalidate a page", async () => {
        expect(parseGaugeAppUpdateSnapshot({
            cursor: "cursor-10",
            invalidations: [{ page_id: "people", resource_basis: "basis-10", ignored: "drop me" }],
            ignored: "drop me",
        })).toEqual({
            cursor: "cursor-10",
            invalidations: [{ page_id: "people", resource_basis: "basis-10" }],
        });
        expect(() => parseGaugeAppUpdateSnapshot({ cursor: "", invalidations: [] })).toThrow(/updates.cursor/);
        expect(() => parseGaugeAppUpdateSnapshot({ cursor: "cursor-10", invalidations: [{ page_id: "people" }] }))
            .toThrow(/resource_basis/);

        const foreign = fakeJson({
            cursor: "cursor-10",
            invalidations: [{ page_id: "billing", resource_basis: "basis-10" }],
        });
        await expect(readGaugeAppUpdates(foreign.json, session)).rejects.toThrow(/page_id/);
    });

    it("opens each App without projecting local state as authority", async () => {
        for (const app of gaugeAppKinds) {
            const route = fakeJson({ session });
            await openGaugeApp(route.json, app, session.scope);
            expect(route.calls[0]?.[1]).toBe(`/gaugeapps/${app}/sessions`);
        }
    });
});
