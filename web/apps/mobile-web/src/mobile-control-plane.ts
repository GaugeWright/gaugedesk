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
} from "@gaugewright/control-plane-client";
import {
    browserRouteJson,
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
    createChatUnderArchetype: "command",
    createChatUnderPlacement: "command",
    useArchetype: "command",
    createEngagement: "command",
    forkChat: "command",
    renameChat: "command",
    deleteChat: "command",
    createWorkstream: "command",
    joinWorkstream: "command",
    leaveWorkstream: "command",
    promoteWorkstream: "command",
    archiveWorkstream: "command",
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
        const route =
            config.routeJson
            ?? browserRouteJson(this.base, {
                machineSession: session,
                bearer: config.bearer,
                homeAdmission: config.homeAdmission,
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
        return { base: this.base, json: this.routeJson() };
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

    createArchetype(name: string): Promise<ArchetypeId> {
        return workbenchClient.createArchetype(this.workbenchTransport(), name);
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

    placeArchetype(pid: ProjectId, archetypeId: ArchetypeId): Promise<PlacementId> {
        return workbenchClient.placeArchetype(this.workbenchTransport(), pid, archetypeId);
    }

    removePlacement(pid: ProjectId, placementId: PlacementId): Promise<void> {
        return workbenchClient.removePlacement(this.workbenchTransport(), pid, placementId);
    }

    createChatUnderArchetype(archetypeId: ArchetypeId, title: string): Promise<EngagementId> {
        return workbenchClient.createChatUnderArchetype(this.workbenchTransport(), archetypeId, title);
    }

    createChatUnderPlacement(
        pid: ProjectId,
        placementId: PlacementId,
        title: string,
        targetId: WorkTargetId,
    ): Promise<EngagementId> {
        return workbenchClient.createChatUnderPlacement(this.workbenchTransport(), pid, placementId, title, targetId);
    }

    useArchetype(archetypeId: ArchetypeId, title: string): Promise<EngagementId> {
        return workbenchClient.useArchetype(this.workbenchTransport(), archetypeId, title);
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

    createWorkstream(placementId: PlacementId, name: string, targetId: WorkTargetId): Promise<WorkstreamNode> {
        return workbenchClient.createWorkstream(this.workbenchTransport(), placementId, name, targetId);
    }

    joinWorkstream(ws: WorkstreamId, chat: EngagementId): Promise<void> {
        return workbenchClient.joinWorkstream(this.workbenchTransport(), ws, chat);
    }

    leaveWorkstream(ws: WorkstreamId, chat: EngagementId): Promise<void> {
        return workbenchClient.leaveWorkstream(this.workbenchTransport(), ws, chat);
    }

    promoteWorkstream(ws: WorkstreamId): Promise<void> {
        return workbenchClient.promoteWorkstream(this.workbenchTransport(), ws);
    }

    archiveWorkstream(ws: WorkstreamId): Promise<void> {
        return workbenchClient.archiveWorkstream(this.workbenchTransport(), ws);
    }

    runTask(
        id: EngagementId,
        prompt: string,
        images: { data: string; mimeType: string }[] = [],
    ): Promise<unknown> {
        return workbenchClient.runTask(this.workbenchTransport(), id, prompt, images);
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

    subscribeWorkspace(onChange: (change: WorkspaceChange) => void): () => void {
        return workbenchClient.subscribeWorkspace(this.workbenchTransport(), onChange);
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
