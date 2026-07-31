import { describe, expect, it, vi } from "vitest";
import {
    controlDeployment,
    erasePublicSession,
    inspectDeployment,
    listPublicCredentials,
    provisionPublicCredential,
    revokePublicCredential,
    type WorkbenchTransport,
} from "./control-plane-workbench";

const inspection = {
    deployment: {
        lifecycle: "active" as const,
        config: {
            deployment_id: "theory-a",
            allowed_origins: ["https://example.com"],
            panel_ceiling: ["gw-chat"],
            max_spend_cents: 100,
            per_visitor_turn_limit: 20,
            max_concurrent_sessions: 10,
        },
        active_release_id: `sha256:${"a".repeat(64)}`,
        activation_revision: 4,
        spent_cents: 1.25,
        reserved_cents: 0,
        sessions: 1,
        settled_turns: 2,
    },
    audience: [],
};

describe("public deployment owner client", () => {
    it("uses only local signed-command bridge routes", async () => {
        const json = vi.fn(async (_method: string, path: string) => {
            if (path.endsWith("/inspect")) return inspection;
            if (path.endsWith("/control")) return { deployment: inspection.deployment };
            return { erased: true };
        });
        const transport = { base: "", json } as unknown as WorkbenchTransport;

        await expect(inspectDeployment(transport, "https://edge.example", "theory-a"))
            .resolves.toEqual(inspection);
        await expect(controlDeployment(
            transport,
            "https://edge.example",
            "theory-a",
            "pause",
            4,
        )).resolves.toEqual(inspection.deployment);
        await expect(erasePublicSession(
            transport,
            "https://edge.example",
            "theory-a",
            `sess_${"a".repeat(32)}`,
        )).resolves.toBeUndefined();

        expect(json.mock.calls).toEqual([
            ["POST", "/public-deployments/inspect", {
                edge_origin: "https://edge.example",
                deployment_id: "theory-a",
            }],
            ["POST", "/public-deployments/control", {
                edge_origin: "https://edge.example",
                deployment_id: "theory-a",
                command: "pause",
                expected_revision: 4,
            }],
            ["POST", "/public-deployments/erase-session", {
                edge_origin: "https://edge.example",
                deployment_id: "theory-a",
                session_id: `sess_${"a".repeat(32)}`,
            }],
        ]);
    });

    it("rejects malformed inspection before UI use", async () => {
        const transport = {
            base: "",
            json: vi.fn(async () => ({ deployment: { lifecycle: "mystery" } })),
        } as unknown as WorkbenchTransport;
        await expect(inspectDeployment(transport, "https://edge.example", "theory-a"))
            .rejects.toThrow("malformed");
    });

    it("moves provider keys only through the signed local credential bridge", async () => {
        const credential = {
            credential_ref: `credential:public:${"a".repeat(64)}:openai:${"b".repeat(32)}`,
            provider: "openai" as const,
            credential_class: "managed-openai",
            label: "Production",
            created_at_unix_ms: 1_800_000_000_000,
        };
        const json = vi.fn(async (_method: string, path: string) => {
            if (path.endsWith("/list")) return { credentials: [credential] };
            if (path.endsWith("/provision")) return { credential };
            return { revoked: true };
        });
        const transport = { base: "", json } as unknown as WorkbenchTransport;

        await expect(listPublicCredentials(transport, "https://edge.example"))
            .resolves.toEqual([credential]);
        await expect(provisionPublicCredential(transport, {
            edge_origin: "https://edge.example",
            provider: "openai",
            credential_class: "managed-openai",
            api_key: "sk-owner-secret",
            label: "Production",
        })).resolves.toEqual(credential);
        await expect(revokePublicCredential(
            transport,
            "https://edge.example",
            credential.credential_ref,
        )).resolves.toBeUndefined();

        expect(json.mock.calls).toEqual([
            ["POST", "/public-deployments/credentials/list", {
                edge_origin: "https://edge.example",
            }],
            ["POST", "/public-deployments/credentials/provision", {
                edge_origin: "https://edge.example",
                provider: "openai",
                credential_class: "managed-openai",
                api_key: "sk-owner-secret",
                label: "Production",
            }],
            ["POST", "/public-deployments/credentials/revoke", {
                edge_origin: "https://edge.example",
                credential_ref: credential.credential_ref,
            }],
        ]);
    });
});
