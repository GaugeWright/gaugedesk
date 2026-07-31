import {
    bearer,
    browserRouteJson,
    browserRouteRequest,
    controlPlaneBase,
    listManagementChanges,
    listManagementAgentMessages,
    openManagementEnvironment,
    proposeManagementDocumentChange,
    readManagementDocument,
    reviewManagementChange,
    sendManagementAgentMessage,
    submitManagementCommand,
    type ManagementCommandEnvelope,
    type ManagementEnvironmentSession,
    type RouteJson,
    type RouteRequest,
} from "@gaugewright/control-plane-client";
import * as enterprise from "./control-plane-enterprise";
import type {
    AuditExportFormat,
    EnterpriseAdminApi,
    SsoConnection,
} from "./control-plane-enterprise";

export { controlPlaneBase };

export class EnterpriseControlPlane implements EnterpriseAdminApi {
    private readonly json: RouteJson;
    private readonly request: RouteRequest;

    constructor(
        base = controlPlaneBase(),
        options: { readonly tenant?: () => string | null } = {},
    ) {
        const normalizedBase = base.replace(/\/+$/, "");
        const requestOptions = {
            bearer,
            tenant: options.tenant,
        };
        this.json = browserRouteJson(normalizedBase, requestOptions);
        this.request = browserRouteRequest(normalizedBase, requestOptions);
    }

    adminCapabilities() {
        return enterprise.adminCapabilities(this.json);
    }

    placementPolicy() {
        return enterprise.placementPolicy(this.json);
    }

    openAdministration(scope?: { readonly kind: "tenant"; readonly id: string }) {
        return openManagementEnvironment(this.json, "administration", scope);
    }

    readAdministrationDocument(session: ManagementEnvironmentSession, documentId: string) {
        return readManagementDocument(this.json, session, documentId);
    }

    administrationDomainChallenge(session: ManagementEnvironmentSession, domain: string) {
        const query = new URLSearchParams({ session: session.id, scope: session.scope.id, domain });
        return this.json("GET", `/environments/administration/domain-verification?${query}`) as Promise<{
            readonly domain: string;
            readonly record_name: string;
            readonly record_type: "TXT";
            readonly value: string;
        }>;
    }

    submitAdministrationCommand(envelope: ManagementCommandEnvelope, idempotencyKey: string) {
        return submitManagementCommand(this.json, envelope, idempotencyKey);
    }

    proposeAdministrationDocumentChange(
        input: { readonly session: ManagementEnvironmentSession; readonly documentId: string; readonly baseRevision: string; readonly content: unknown; readonly client: "browser" | "edit" | "agent" | "cli" },
        idempotencyKey: string,
    ) {
        return proposeManagementDocumentChange(this.json, input, idempotencyKey);
    }

    administrationChanges(session: ManagementEnvironmentSession) {
        return listManagementChanges(this.json, session);
    }

    reviewAdministrationChange(session: ManagementEnvironmentSession, changeId: string, decision: "accept" | "reject", idempotencyKey: string) {
        return reviewManagementChange(this.json, session, changeId, decision, idempotencyKey);
    }

    sendAdministrationAgentMessage(session: ManagementEnvironmentSession, message: string) {
        return sendManagementAgentMessage(this.json, session, message);
    }

    administrationAgentMessages(session: ManagementEnvironmentSession) {
        return listManagementAgentMessages(this.json, session);
    }

    adminIntegration() {
        return enterprise.adminIntegration(this.json);
    }

    adminTestSso(connection: SsoConnection) {
        return enterprise.adminTestSso(this.json, connection);
    }

    async exportAdministrationAudit(
        format: AuditExportFormat,
        filters: { readonly actor?: string; readonly action?: string } = {},
    ) {
        const query = new URLSearchParams({ format });
        if (filters.actor?.trim()) query.set("actor", filters.actor.trim());
        if (filters.action?.trim()) query.set("action", filters.action.trim());
        const response = await this.request(`/admin/audit?${query}`, {
            headers: { accept: format === "csv" ? "text/csv" : "application/json" },
        });
        if (!response.ok) {
            throw new Error(`GET /admin/audit: ${response.status}`);
        }
        return {
            format,
            body: await response.text(),
            contentType: response.headers.get("content-type") ??
                (format === "csv" ? "text/csv" : "application/json"),
            filename: `gaugewright-audit.${format}`,
        } as const;
    }

}
