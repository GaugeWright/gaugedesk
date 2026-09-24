import {
    bearer,
    accountSetSetting,
    accountSettings,
    browserRouteEventStream,
    browserRouteJson,
    browserRouteRequest,
    createOrganization,
    claimAccountDeviceLink,
    completeAccountDeviceLink,
    controlPlaneBase,
    eraseGaugeAppAgentTranscript,
    listGaugeAppProposals,
    listGaugeAppAgentMessages,
    openGaugeApp,
    readGaugeAppPage,
    readGaugeAppUpdates,
    readPlacementGovernance,
    restoreMaterial,
    reviewGaugeAppProposal,
    startAccountAuthorization,
    finishAccountAuthorization,
    sendGaugeAppAgentMessage,
    subscribeGaugeAppAgentEvents,
    stopGaugeAppAgentTurn,
    startConsumerOidcLink,
    startConsumerOidcAvatar,
    submitGaugeAppCommand,
    submitAccountProviderSecret,
    submitOrganizationSsoCredential,
    submitOrganizationProviderSecret,
    verifyOrganizationProviderCandidate,
    type OrganizationProviderCandidate,
    readAccountDeviceLink,
    type AccountDeviceLinkStatus,
    type GaugeAppCommandEnvelope,
    type GaugeAppAgentLiveFrame,
    type GaugeAppKind,
    type GaugeAppScope,
    type GaugeAppSession,
    type GaugeAppPageModel,
    type AdministrationGaugeAppPage,
    type AdministrationGaugeAppPageId,
    type RouteJson,
    type RouteRequest,
    type RouteEventStream,
    tenantProjectShareCandidates,
} from "@gaugewright/control-plane-client";
import * as enterprise from "./control-plane-enterprise";
import type {
    AuditExportFormat,
    EnterpriseAdminApi,
    SsoConnection,
} from "./control-plane-enterprise";

export { controlPlaneBase };

export interface CommercialProposalAccess {
    readonly tenant_id: string;
    readonly engagement_id: string;
    readonly delivery_id: string;
    readonly proof: string;
}

export interface OrganizationInvitationAccess {
    readonly tenant_id: string;
    readonly invitation_id: string;
    readonly proof: string;
}

export interface OrganizationInvitationPreview {
    readonly tenant_id: string;
    readonly display_name: string;
    readonly email: string;
    readonly role: string;
    readonly expires_at_ms: number;
    readonly account_matches: boolean;
    readonly can_respond: boolean;
}

export interface CommercialProposalPreview {
    readonly tenant_id: string;
    readonly provider_name: string;
    readonly engagement_id: string;
    readonly proposal_revision: number;
    readonly stage: string;
    readonly client_name: string;
    readonly product: unknown;
    readonly terms: unknown;
    readonly recipient: unknown;
    readonly issued_at_ms: number;
    readonly expired: boolean;
    readonly accepted: boolean;
    readonly requires_account_sign_in: boolean;
    readonly can_accept: boolean;
}

export class EnterpriseControlPlane implements EnterpriseAdminApi {
    private readonly json: RouteJson;
    private readonly request: RouteRequest;
    private readonly events: RouteEventStream;

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
        this.events = browserRouteEventStream(normalizedBase, requestOptions);
    }

    adminCapabilities() {
        return enterprise.adminCapabilities(this.json);
    }

    placementPolicy() {
        return enterprise.placementPolicy(this.json);
    }

    projectShareCandidates(tenant: string) {
        return tenantProjectShareCandidates(this.json, tenant);
    }

    createOrganization(displayName: string) {
        return createOrganization(this.json, displayName);
    }

    /** Never-throwing governance read (solo control planes have no org routes). */
    placementGovernance() {
        return readPlacementGovernance(this.request);
    }

    /** Preferences evaluated by the currently connected Project Host. These
     * remain on that server; the hosted account plane and browser storage are
     * deliberately not another authority for them. */
    projectHostAccountSettings() {
        return accountSettings(this.json);
    }

    setProjectHostAccountSetting(key: string, value: string) {
        return accountSetSetting(this.json, key, value);
    }

    openAdministration(scope?: { readonly kind: "tenant"; readonly id: string }) {
        return openGaugeApp(this.json, "administration", scope);
    }

    openGaugeApp(app: GaugeAppKind, scope?: GaugeAppScope) {
        return openGaugeApp(this.json, app, scope);
    }

    readGaugeAppPage<P extends AdministrationGaugeAppPageId>(session: GaugeAppSession, pageId: P): Promise<AdministrationGaugeAppPage<P>>;
    readGaugeAppPage(session: GaugeAppSession, pageId: string): Promise<GaugeAppPageModel>;
    readGaugeAppPage(session: GaugeAppSession, pageId: string): Promise<GaugeAppPageModel> {
        return readGaugeAppPage(this.json, session, pageId);
    }

    readGaugeAppUpdates(session: GaugeAppSession, after?: string) {
        return readGaugeAppUpdates(this.json, session, after);
    }

    submitGaugeAppCommand(envelope: GaugeAppCommandEnvelope) {
        return submitGaugeAppCommand(this.json, envelope);
    }

    submitAccountProviderSecret(envelope: GaugeAppCommandEnvelope, secret: string) {
        return submitAccountProviderSecret(this.json, envelope, secret);
    }
    submitOrganizationSsoCredential(envelope: GaugeAppCommandEnvelope, secret?: string) {
        return submitOrganizationSsoCredential(this.json, envelope, secret);
    }
    startConsumerOidcLink() {
        return startConsumerOidcLink(this.json);
    }
    startConsumerOidcAvatar() {
        return startConsumerOidcAvatar(this.json);
    }
    submitOrganizationProviderSecret(candidate: OrganizationProviderCandidate, secret: string, signal: AbortSignal) {
        return submitOrganizationProviderSecret(this.json, candidate, secret, { signal });
    }
    verifyOrganizationProviderCandidate(candidate: OrganizationProviderCandidate) {
        return verifyOrganizationProviderCandidate(this.json, candidate);
    }

    claimAccountDeviceLink(
        claim: {
            readonly id?: string;
            readonly human_code?: string;
            readonly label: string;
            readonly kind: "computer" | "phone" | "tablet";
            readonly subkey_pubkey: string;
        },
        idempotencyKey: string,
    ): Promise<AccountDeviceLinkStatus> {
        return claimAccountDeviceLink(this.json, claim, idempotencyKey);
    }

    readAccountDeviceLink(id: string): Promise<AccountDeviceLinkStatus> {
        return readAccountDeviceLink(this.json, id);
    }

    completeAccountDeviceLink(
        id: string,
        completion: { readonly account_key_proof: string; readonly signature: string },
        idempotencyKey: string,
    ): Promise<AccountDeviceLinkStatus> {
        return completeAccountDeviceLink(this.json, id, completion, idempotencyKey);
    }

    gaugeAppProposals(session: GaugeAppSession) {
        return listGaugeAppProposals(this.json, session);
    }

    reviewGaugeAppProposal(session: GaugeAppSession, proposalId: string, decision: "accept" | "reject", idempotencyKey: string, authorizationProof?: string) {
        return reviewGaugeAppProposal(this.json, session, proposalId, decision, idempotencyKey, "web", authorizationProof);
    }

    startAccountAuthorization(operation: string) {
        return startAccountAuthorization(this.json, operation);
    }

    finishAccountAuthorization(ceremonyId: string, credential: Readonly<Record<string, unknown>>) {
        return finishAccountAuthorization(this.json, ceremonyId, credential);
    }

    backupRestoreMaterial(tenant: string, pointHandle: string, recipientId: string) {
        return restoreMaterial(this.json, tenant, pointHandle, recipientId);
    }

    sendGaugeAppAgentMessage(session: GaugeAppSession, message: string, idempotencyKey: string) {
        return sendGaugeAppAgentMessage(this.json, session, message, idempotencyKey);
    }

    stopGaugeAppAgentTurn(session: GaugeAppSession) {
        return stopGaugeAppAgentTurn(this.json, session);
    }

    eraseGaugeAppAgentTranscript(session: GaugeAppSession, idempotencyKey: string) {
        return eraseGaugeAppAgentTranscript(this.json, session, idempotencyKey);
    }

    gaugeAppAgentMessages(session: GaugeAppSession) {
        return listGaugeAppAgentMessages(this.json, session);
    }

    gaugeAppAgentEvents(
        session: GaugeAppSession,
        onFrame: (frame: GaugeAppAgentLiveFrame) => void,
        after?: string,
        onOpen?: () => void,
        onClose?: () => void,
    ) {
        return subscribeGaugeAppAgentEvents(
            this.events,
            session,
            onFrame,
            after,
            onOpen,
            onClose,
        );
    }

    previewCommercialProposal(access: CommercialProposalAccess) {
        return this.json("POST", "/commercial/proposals/preview", access) as Promise<{
            readonly proposal: CommercialProposalPreview;
        }>;
    }

    acceptCommercialProposal(access: CommercialProposalAccess) {
        return this.json("POST", "/commercial/proposals/accept", access) as Promise<{
            readonly accepted: true;
            readonly engagement_id: string;
            readonly proposal_revision: number;
            readonly accepted_at_ms: number;
            readonly replayed: boolean;
        }>;
    }

    previewOrganizationInvitation(access: OrganizationInvitationAccess) {
        return this.json("POST", "/organization-invitations/preview", access) as Promise<{
            readonly invitation: OrganizationInvitationPreview;
        }>;
    }

    respondOrganizationInvitation(
        access: OrganizationInvitationAccess,
        decision: "accept" | "decline",
        idempotencyKey: string,
    ) {
        return this.json("POST", "/organization-invitations/respond", {
            ...access,
            decision,
        }, { idempotencyKey }) as Promise<{
            readonly decision: "accepted" | "declined";
            readonly tenant_id: string;
            readonly replayed: boolean;
        }>;
    }

    readAdministrationPage<P extends AdministrationGaugeAppPageId>(session: GaugeAppSession, pageId: P): Promise<AdministrationGaugeAppPage<P>>;
    readAdministrationPage(session: GaugeAppSession, pageId: string): Promise<GaugeAppPageModel>;
    readAdministrationPage(session: GaugeAppSession, pageId: string): Promise<GaugeAppPageModel> {
        return readGaugeAppPage(this.json, session, pageId);
    }

    administrationDomainChallenge(session: GaugeAppSession, domain: string) {
        const query = new URLSearchParams({
            session: session.id,
            generation: session.generation,
            scope: session.scope.id,
            domain,
        });
        return this.json("GET", `/gaugeapps/administration/organization/domain-verification?${query}`) as Promise<{
            readonly domain: string;
            readonly record_name: string;
            readonly record_type: "TXT";
            readonly value: string;
        }>;
    }

    submitAdministrationCommand(envelope: GaugeAppCommandEnvelope) {
        return submitGaugeAppCommand(this.json, envelope);
    }

    administrationProposals(session: GaugeAppSession) {
        return listGaugeAppProposals(this.json, session);
    }

    reviewAdministrationProposal(session: GaugeAppSession, proposalId: string, decision: "accept" | "reject", idempotencyKey: string, authorizationProof?: string) {
        return reviewGaugeAppProposal(this.json, session, proposalId, decision, idempotencyKey, "web", authorizationProof);
    }

    sendAdministrationAgentMessage(session: GaugeAppSession, message: string, idempotencyKey: string) {
        return sendGaugeAppAgentMessage(this.json, session, message, idempotencyKey);
    }

    stopAdministrationAgentTurn(session: GaugeAppSession) {
        return stopGaugeAppAgentTurn(this.json, session);
    }

    administrationAgentMessages(session: GaugeAppSession) {
        return listGaugeAppAgentMessages(this.json, session);
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
