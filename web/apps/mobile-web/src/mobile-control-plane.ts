import * as workbenchClient from "@gaugewright/control-plane-client";
import type {
    ArchetypeId,
    Engagement,
    EngagementId,
    FileEntry,
    HumanTask,
    PlacementId,
    ProjectId,
    SearchHit,
    StreamEvent,
    WorkTargetId,
    WorkstreamId,
    WorkstreamNode,
    Workspace,
    WorkspaceChange,
    WorkspaceDelta,
    ProjectionCarriage,
    CreatedHomeInvitation,
    PendingHomeInvitation,
    FederationPeer,
    HandoffStatus,
    LinkedProvider,
    OrganizationModelAuthorityBinding,
    Participant,
    ProjectOrganizationModelOptions,
    ProjectOrganizationModelSelection,
} from "@gaugewright/control-plane-client";
import {
    browserRouteEventStream,
    browserRouteJson,
    browserRouteRequest,
    reconnectingRouteEventStream,
    controlPlaneBase,
    type BrowserRouteJsonOptions,
    type RouteJson,
} from "@gaugewright/control-plane-client";
import type { FacetBrowserApi } from "@gaugewright/workbench-ui";

export { controlPlaneBase };

export const MOBILE_CONTROL_PLANE_INVENTORY = {
    getWorkspaceCarriage: "projection",
    getWorkspaceDeltaCarriage: "projection",
    getTasks: "projection",
    search: "projection",
    getPlacementConfig: "projection",
    setPlacementConfig: "command",
    createArchetype: "command",
    copyAgentAsPanel: "command",
    renameArchetype: "command",
    deleteArchetype: "command",
    forkArchetype: "command",
    pullFromSource: "command",
    publishArchetype: "command",
    upgradePlacement: "command",
    acceptPlacement: "command",
    createProject: "command",
    renameProject: "command",
    deleteProject: "command",
    placeArchetype: "command",
    removePlacement: "command",
    ensureCollectionRecipient: "command",
    handoffStatus: "projection",
    handoffParticipants: "projection",
    getProjectKeyDelegations: "projection",
    listPeers: "projection",
    handoffRelocate: "command",
    handoffRevoke: "command",
    createHomeInvitation: "command",
    pendingHomeInvitations: "projection",
    cancelHomeInvitation: "command",
    resendHomeInvitation: "command",
    setProjectNetworkIsolated: "command",
    projectCredentials: "projection",
    linkProjectCredential: "command",
    unlinkProjectCredential: "command",
    projectOrganizationModelOptions: "projection",
    projectOrganizationModelSelection: "projection",
    selectProjectOrganizationModel: "command",
    clearProjectOrganizationModelSelection: "command",
    createChatUnderArchetype: "command",
    createChatUnderPlacement: "command",
    reviseChatTargets: "command",
    previewAgent: "command",
    createEngagement: "command",
    forkChat: "command",
    renameChat: "command",
    deleteChat: "command",
    organizeChat: "command",
    createWorkstream: "command",
    joinWorkstream: "command",
    leaveWorkstream: "command",
    promoteWorkstream: "command",
    settleWorkstreamTarget: "command",
    settleChatTargets: "command",
    getTargetSettlement: "projection",
    queryTargetSettlementMember: "command",
    retryTargetSettlementMember: "command",
    supersedeTargetSettlementMember: "command",
    compensateTargetSettlement: "command",
    abandonTargetSettlement: "command",
    cancelTargetSettlement: "command",
    archiveWorkstream: "command",
    taskIdentity: "projection",
    runTask: "command",
    stopTurn: "command",
    getTranscript: "projection",
    getTree: "projection",
    getFile: "projection",
    subscribe: "reference-stream",
    subscribeWorkspace: "reference-stream",
    openPairing: "direct-admission",
    acceptBoundary: "direct-admission",
    pairingStatus: "direct-admission",
    claimMachineInvitation: "direct-admission",
    proveMachineDevice: "direct-admission",
    machineEnrollmentStatus: "direct-admission",
    machineSessionChallenge: "direct-admission",
    openMachineSession: "direct-admission",
    revokeMachineController: "direct-admission",
} as const;

/** App-owned control-plane edge for the mobile web harness. */
export class MobileControlPlane implements FacetBrowserApi {
    private readonly route: RouteJson;
    /** Raw fetches and event streams, carrying the same credentials as `route`.
     * Without them the workbench falls back to a bare `fetch` and `EventSource`,
     * which carry none, so every stream a Home checks was refused — over the
     * relay above all, where a desktop Home admits only its owner (DR-0232). */
    private readonly request: workbenchClient.RouteRequest;
    private readonly events: workbenchClient.RouteEventStream;

    constructor(
        private readonly base = controlPlaneBase(),
        config: {
            readonly routeJson?: RouteJson;
            readonly machineSession?: BrowserRouteJsonOptions["machineSession"];
            readonly bearer?: BrowserRouteJsonOptions["bearer"];
            readonly homeAdmission?: BrowserRouteJsonOptions["homeAdmission"];
            readonly onSessionRejected?: () => void;
            readonly onAuthorizationRejected?: (
                status: 401 | 403 | 421,
                detail: string,
            ) => void;
            readonly onTransportUnavailable?: (detail: string) => void;
        } = {},
    ) {
        const configuredSession = config.machineSession;
        const session: () => string | null =
            typeof configuredSession === "function"
                ? configuredSession
                : () => configuredSession ?? null;
        const credentials = {
            machineSession: session,
            bearer: config.bearer,
            homeAdmission: config.homeAdmission,
        };
        const route = config.routeJson ?? browserRouteJson(this.base, credentials);
        this.request = browserRouteRequest(this.base, credentials);
        // Reconnecting, as `EventSource` did by itself: a stream over the relay
        // ends whenever its tunnel does. A refusal is reported the way a
        // refused call is, so the owner can admit again or say why.
        const eventSource = browserRouteEventStream(this.base, credentials);
        this.events = reconnectingRouteEventStream(() => eventSource, {
            beforeReconnect: (reason) => {
                const status = reason?.status;
                if (status === 401 || status === 403 || status === 421) {
                    config.onAuthorizationRejected?.(status, reason?.detail ?? "");
                }
            },
        });
        this.route = async (method, path, body, requestOptions) => {
            try {
                return await route(method, path, body, requestOptions);
            } catch (error) {
                if (session() && /\b401\b/.test(String(error))) {
                    config.onSessionRejected?.();
                } else if (/\b401\b/.test(String(error))) {
                    config.onAuthorizationRejected?.(401, String(error));
                } else if (/\b403\b/.test(String(error))) {
                    config.onAuthorizationRejected?.(403, String(error));
                } else if (/\b421\b/.test(String(error))) {
                    config.onAuthorizationRejected?.(421, String(error));
                } else {
                    config.onTransportUnavailable?.(String(error));
                }
                throw error;
            }
        };
    }

    private routeJson(): RouteJson {
        return this.route;
    }

    private workbenchTransport(): workbenchClient.WorkbenchTransport {
        return {
            base: this.base,
            json: this.routeJson(),
            request: this.request,
            events: this.events,
        };
    }

    getWorkspaceCarriage(): Promise<ProjectionCarriage<Workspace>> {
        return workbenchClient.getWorkspaceCarriage(this.workbenchTransport());
    }

    getWorkspaceDeltaCarriage(change: WorkspaceChange): Promise<ProjectionCarriage<WorkspaceDelta>> {
        return workbenchClient.getWorkspaceDeltaCarriage(this.workbenchTransport(), change);
    }

    getTasks(): Promise<HumanTask[]> {
        return workbenchClient.getTasks(this.workbenchTransport());
    }

    search(query: string): Promise<SearchHit[]> {
        return workbenchClient.search(this.workbenchTransport(), query);
    }

    getPlacementConfig(placementId: PlacementId): Promise<{ config: string; notes: string }> {
        return workbenchClient.getPlacementConfig(this.workbenchTransport(), placementId);
    }

    setPlacementConfig(placementId: PlacementId, config: string, notes: string): Promise<void> {
        return workbenchClient.setPlacementConfig(this.workbenchTransport(), placementId, config, notes);
    }

    createArchetype(name: string, kind?: import("@gaugewright/control-plane-client").AgentKind): Promise<ArchetypeId> {
        return workbenchClient.createArchetype(this.workbenchTransport(), name, kind);
    }

    copyAgentAsPanel(id: ArchetypeId, name?: string): Promise<ArchetypeId> {
        return workbenchClient.copyAgentAsPanel(this.workbenchTransport(), id, name);
    }

    renameArchetype(id: ArchetypeId, name: string): Promise<void> {
        return workbenchClient.renameArchetype(this.workbenchTransport(), id, name);
    }

    deleteArchetype(id: ArchetypeId): Promise<void> {
        return workbenchClient.deleteArchetype(this.workbenchTransport(), id);
    }

    forkArchetype(id: ArchetypeId, name?: string): Promise<ArchetypeId> {
        return workbenchClient.forkArchetype(this.workbenchTransport(), id, name);
    }

    pullFromSource(id: ArchetypeId): Promise<void> {
        return workbenchClient.pullFromSource(this.workbenchTransport(), id);
    }

    publishArchetype(
        id: ArchetypeId,
        autoUpgrade?: boolean,
    ): Promise<{ version: number; autoUpgraded: number }> {
        return workbenchClient.publishArchetype(this.workbenchTransport(), id, autoUpgrade);
    }

    upgradePlacement(placementId: PlacementId): Promise<number> {
        return workbenchClient.upgradePlacement(this.workbenchTransport(), placementId);
    }

    acceptPlacement(placementId: PlacementId): Promise<void> {
        return workbenchClient.acceptPlacement(this.workbenchTransport(), placementId);
    }

    createProject(name: string): Promise<ProjectId> {
        return workbenchClient.createProject(this.workbenchTransport(), name);
    }

    renameProject(id: ProjectId, name: string): Promise<void> {
        return workbenchClient.renameProject(this.workbenchTransport(), id, name);
    }

    deleteProject(id: ProjectId): Promise<void> {
        return workbenchClient.deleteProject(this.workbenchTransport(), id);
    }

    placeArchetype(pid: ProjectId, archetypeId: ArchetypeId, recipient?: import("@gaugewright/control-plane-client").CollectionRecipient): Promise<PlacementId> {
        return workbenchClient.placeArchetype(this.workbenchTransport(), pid, archetypeId, recipient);
    }

    removePlacement(pid: ProjectId, placementId: PlacementId): Promise<void> {
        return workbenchClient.removePlacement(this.workbenchTransport(), pid, placementId);
    }

    ensureCollectionRecipient(recipientId: string): Promise<workbenchClient.CollectionRecipient> {
        return workbenchClient.ensureCollectionRecipient(this.workbenchTransport(), recipientId);
    }

    handoffStatus(project: ProjectId): Promise<HandoffStatus> {
        return workbenchClient.handoffStatus(this.routeJson(), project);
    }

    handoffParticipants(project: ProjectId): Promise<Participant[]> {
        return workbenchClient.handoffParticipants(this.routeJson(), project);
    }

    /** What background work holds which of a project's keys (DR-0312). */
    getProjectKeyDelegations(project: ProjectId): Promise<workbenchClient.ProjectKeyDelegations> {
        return workbenchClient.getProjectKeyDelegations(this.workbenchTransport(), project);
    }

    listPeers(): Promise<FederationPeer[]> {
        return workbenchClient.listPeers(this.routeJson());
    }

    handoffRelocate(project: ProjectId, peer: string): Promise<HandoffStatus> {
        return workbenchClient.handoffRelocate(this.routeJson(), project, peer);
    }

    handoffRevoke(project: ProjectId, authority: string, owns: string): Promise<void> {
        return workbenchClient.handoffRevoke(this.routeJson(), project, authority, owns);
    }

    createHomeInvitation(
        recipient: string | { readonly email: string },
        project: ProjectId,
        role: "member" | "viewer" = "member",
    ): Promise<CreatedHomeInvitation> {
        return workbenchClient.createHomeInvitation(this.routeJson(), {
            ...(typeof recipient === "string"
                ? { authority: recipient.trim() }
                : { email: recipient.email.trim() }),
            project,
            endpoint: this.base,
            role,
        });
    }

    pendingHomeInvitations(project: ProjectId): Promise<PendingHomeInvitation[]> {
        return workbenchClient.listPendingHomeInvitations(this.routeJson(), project);
    }

    cancelHomeInvitation(id: string): Promise<void> {
        return workbenchClient.cancelHomeInvitation(this.routeJson(), id);
    }

    resendHomeInvitation(id: string): Promise<CreatedHomeInvitation> {
        return workbenchClient.resendHomeInvitation(this.routeJson(), id);
    }

    setProjectNetworkIsolated(project: ProjectId, isolated: boolean): Promise<void> {
        return workbenchClient.setProjectNetworkIsolated(
            this.workbenchTransport(),
            project,
            isolated,
        );
    }

    projectCredentials(project: string): Promise<LinkedProvider[]> {
        return workbenchClient.projectCredentials(this.routeJson(), project);
    }

    linkProjectCredential(
        project: string,
        provider: string,
        token: string,
        baseUrl?: string,
    ): Promise<void> {
        return workbenchClient.linkProjectCredential(
            this.routeJson(),
            project,
            provider,
            token,
            baseUrl,
        );
    }

    unlinkProjectCredential(project: string, provider: string): Promise<void> {
        return workbenchClient.unlinkProjectCredential(this.routeJson(), project, provider);
    }

    projectOrganizationModelOptions(project: string): Promise<ProjectOrganizationModelOptions> {
        return workbenchClient.projectOrganizationModelOptions(this.routeJson(), project);
    }

    projectOrganizationModelSelection(
        project: string,
    ): Promise<ProjectOrganizationModelSelection | null> {
        return workbenchClient.projectOrganizationModelSelection(this.routeJson(), project);
    }

    selectProjectOrganizationModel(
        project: string,
        input: {
            readonly binding: OrganizationModelAuthorityBinding;
            readonly connection: string;
            readonly model: string;
            readonly privateBroker: string;
            readonly admitPrivatePlaintext: true;
        },
    ): Promise<ProjectOrganizationModelSelection> {
        return workbenchClient.selectProjectOrganizationModel(this.routeJson(), project, input);
    }

    clearProjectOrganizationModelSelection(project: string): Promise<void> {
        return workbenchClient.clearProjectOrganizationModelSelection(this.routeJson(), project);
    }

    createChatUnderArchetype(archetypeId: ArchetypeId, title: string): Promise<EngagementId> {
        return workbenchClient.createChatUnderArchetype(this.workbenchTransport(), archetypeId, title);
    }

    createChatUnderPlacement(
        pid: ProjectId,
        placementId: PlacementId,
        title: string,
        targetIds: readonly WorkTargetId[],
    ): Promise<EngagementId> {
        return workbenchClient.createChatUnderPlacement(this.workbenchTransport(), pid, placementId, title, targetIds);
    }

    async reviseChatTargets(id: EngagementId, targets: readonly { targetId: WorkTargetId; participation: "read-only" | "writable" }[]): Promise<void> {
        await workbenchClient.reviseChatTargets(this.workbenchTransport(), id, targets);
    }

    previewAgent(archetypeId: ArchetypeId, placementId?: PlacementId): Promise<EngagementId> {
        return workbenchClient.previewAgent(this.workbenchTransport(), archetypeId, placementId);
    }

    createEngagement(): Promise<Engagement> {
        return workbenchClient.createEngagement(this.workbenchTransport());
    }

    forkChat(id: EngagementId): Promise<EngagementId> {
        return workbenchClient.forkChat(this.workbenchTransport(), id);
    }

    renameChat(id: EngagementId, title: string): Promise<void> {
        return workbenchClient.renameChat(this.workbenchTransport(), id, title);
    }

    deleteChat(id: EngagementId): Promise<void> {
        return workbenchClient.deleteChat(this.workbenchTransport(), id);
    }

    organizeChat(id: EngagementId, change: { archived?: boolean; pinned?: boolean }): Promise<void> {
        return workbenchClient.organizeChat(this.workbenchTransport(), id, change);
    }

    createWorkstream(placementId: PlacementId, name: string): Promise<WorkstreamNode> {
        return workbenchClient.createWorkstream(this.workbenchTransport(), placementId, name);
    }

    joinWorkstream(ws: WorkstreamId, chat: EngagementId): Promise<void> {
        return workbenchClient.joinWorkstream(this.workbenchTransport(), ws, chat);
    }

    leaveWorkstream(ws: WorkstreamId, chat: EngagementId): Promise<void> {
        return workbenchClient.leaveWorkstream(this.workbenchTransport(), ws, chat);
    }

    async promoteWorkstream(ws: WorkstreamId): Promise<void> {
        await workbenchClient.promoteWorkstream(this.workbenchTransport(), ws);
    }

    async settleWorkstreamTarget(
        ws: WorkstreamId,
        target: WorkTargetId,
        act: "apply" | "publish" | "release",
        promotionManifestRef?: string,
    ): Promise<void> {
        await workbenchClient.settleWorkstreamTarget(this.workbenchTransport(), ws, target, act, promotionManifestRef);
    }

    async settleChatTargets(chat: EngagementId, members: readonly { target_id: WorkTargetId; act: "apply" | "publish" | "release" }[]): Promise<void> {
        await workbenchClient.settleChatTargets(this.workbenchTransport(), chat, members);
    }

    async getTargetSettlement(declarationId: string): Promise<void> {
        await workbenchClient.getTargetSettlement(this.workbenchTransport(), declarationId);
    }

    async queryTargetSettlementMember(declarationId: string, memberId: string): Promise<void> {
        await workbenchClient.queryTargetSettlementMember(this.workbenchTransport(), declarationId, memberId);
    }

    async retryTargetSettlementMember(declarationId: string, memberId: string): Promise<void> {
        await workbenchClient.retryTargetSettlementMember(this.workbenchTransport(), declarationId, memberId);
    }

    async supersedeTargetSettlementMember(declarationId: string, memberId: string, laterDeclarationId: string, laterMemberId: string): Promise<void> {
        await workbenchClient.supersedeTargetSettlementMember(this.workbenchTransport(), declarationId, memberId, laterDeclarationId, laterMemberId);
    }

    async compensateTargetSettlement(declarationId: string, receiptLinks: readonly workbenchClient.CompensationReceiptLink[]): Promise<void> {
        await workbenchClient.compensateTargetSettlement(this.workbenchTransport(), declarationId, receiptLinks);
    }

    async abandonTargetSettlement(declarationId: string, reason: string): Promise<void> {
        await workbenchClient.abandonTargetSettlement(this.workbenchTransport(), declarationId, reason);
    }

    async cancelTargetSettlement(declarationId: string, reason: string): Promise<void> {
        await workbenchClient.cancelTargetSettlement(this.workbenchTransport(), declarationId, reason);
    }

    archiveWorkstream(ws: WorkstreamId): Promise<void> {
        return workbenchClient.archiveWorkstream(this.workbenchTransport(), ws);
    }

    async taskIdentity(): Promise<{ home_id: string; actor_id: string }> {
        const identity = await this.route("GET", "/file-actions/actor") as { home?: unknown; actor?: unknown };
        if (typeof identity.home !== "string" || !identity.home || typeof identity.actor !== "string" || !identity.actor) {
            throw new Error("Task Home actor proof is unavailable");
        }
        return { home_id: identity.home, actor_id: identity.actor };
    }

    runTask(
        id: EngagementId,
        prompt: string,
        images: { data: string; mimeType: string }[] = [],
        composedId?: string,
    ): Promise<unknown> {
        return workbenchClient.runTask(this.workbenchTransport(), id, prompt, images, composedId);
    }

    stopTurn(id: EngagementId): Promise<{ stopped: boolean }> {
        return workbenchClient.stopTurn(this.workbenchTransport(), id);
    }

    getTranscript(id: EngagementId): Promise<StreamEvent[]> {
        return workbenchClient.getTranscript(this.workbenchTransport(), id);
    }

    getTree(id: EngagementId): Promise<FileEntry[]> {
        return workbenchClient.getTree(this.workbenchTransport(), id);
    }

    getFile(id: EngagementId, path: string): Promise<string> {
        return workbenchClient.getFile(this.workbenchTransport(), id, path);
    }

    subscribe(id: EngagementId, onEvent: (ev: StreamEvent) => void, onOpen?: () => void): () => void {
        return workbenchClient.subscribe(this.workbenchTransport(), id, onEvent, onOpen);
    }

    subscribeWorkspace(onChange: (change: WorkspaceChange) => void, onOpen?: () => void): () => void {
        return workbenchClient.subscribeWorkspace(this.workbenchTransport(), onChange, onOpen);
    }

    openPairing(device: string, bridgeGrant: string | null): Promise<{ pairingId: string; bridgeGrant: string }> {
        return workbenchClient.openPairing(this.workbenchTransport(), device, bridgeGrant);
    }

    acceptBoundary(boundaryId: string, participant: string): Promise<void> {
        return workbenchClient.acceptBoundary(this.workbenchTransport(), boundaryId, participant);
    }

    pairingStatus(boundaryId: string): Promise<unknown> {
        return workbenchClient.pairingStatus(this.workbenchTransport(), boundaryId);
    }

    claimMachineInvitation(invitation: {
        invitationId: string;
        secret: string;
        machine: string;
        endpoint: string;
    }, device: string, publicKey: string, label: string): Promise<{
        requestId: string;
        challenge: string;
        expiresAt: number;
    }> {
        return this.route("POST", "/mobile/enrollment/claim", {
            ...invitation,
            device,
            publicKey,
            label,
        }) as Promise<{ requestId: string; challenge: string; expiresAt: number }>;
    }

    proveMachineDevice(requestId: string, signature: string): Promise<void> {
        return this.route("POST", "/mobile/enrollment/prove", {
            requestId,
            signature,
        }) as Promise<void>;
    }

    machineEnrollmentStatus(requestId: string, secret: string): Promise<{
        status: string;
        grantId: string | null;
        credential: string | null;
    }> {
        return this.route("POST", "/mobile/enrollment/status", {
            requestId,
            secret,
        }) as Promise<{ status: string; grantId: string | null; credential: string | null }>;
    }

    machineSessionChallenge(grantId: string, device: string): Promise<{
        challengeId: string;
        challenge: string;
        expiresAt: number;
    }> {
        return this.route("POST", "/mobile/sessions/challenge", {
            grantId,
            device,
        }) as Promise<{ challengeId: string; challenge: string; expiresAt: number }>;
    }

    openMachineSession(input: {
        challengeId: string;
        grantId: string;
        device: string;
        credential: string;
        signature: string;
    }): Promise<{ session: string; expiresAt: number; machine: string }> {
        return this.route("POST", "/mobile/sessions", input) as Promise<{
            session: string;
            expiresAt: number;
            machine: string;
        }>;
    }

    revokeMachineController(grantId: string): Promise<void> {
        return this.route(
            "POST",
            `/mobile/controllers/${encodeURIComponent(grantId)}/revoke`,
        ) as Promise<void>;
    }
}
