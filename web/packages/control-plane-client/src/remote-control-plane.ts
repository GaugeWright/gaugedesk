import {
    browserRouteEventStream,
    browserRouteJson,
    browserRouteRequest,
    type BrowserRouteJsonOptions,
    type RouteEventStream,
    type RouteRequest,
} from "./browser-route-json";
import type {
    Engagement,
    EngagementId,
    FileEntry,
    MergeAction,
    MergeState,
    PlacementId,
    ProjectId,
    StreamEvent,
    TargetActKind,
    WorkTargetId,
    WorkstreamId,
    WorkstreamNode,
    Workspace,
} from "./control-plane-domain";
import { newIdempotencyKey, type RouteJson } from "./control-plane-transport";
import * as workbench from "./control-plane-workbench";
import type { StopTurnResult } from "./control-plane-workbench";

/** The placement-neutral product transport shared by desktop, managed web,
 * embeds, and future in-page environments (ADR 0076). */
export interface ControlPlane {
    setBearer(token: string | null): void;
    listEngagements(): Promise<EngagementId[]>;
    createEngagement(id?: EngagementId): Promise<Engagement>;
    deleteChat(id: EngagementId): Promise<void>;
    getTranscript(id: EngagementId): Promise<StreamEvent[]>;
    subscribe(
        id: EngagementId,
        onEvent: (event: StreamEvent) => void,
        onOpen?: () => void,
    ): () => void;
    runTask(
        id: EngagementId,
        prompt: string,
        images?: { data: string; mimeType: string }[],
    ): Promise<unknown>;
    stopTurn(id: EngagementId): Promise<StopTurnResult>;
    engagementDiff(id: EngagementId): Promise<string>;
    getMerge(id: EngagementId): Promise<MergeState>;
    mergeCommand(
        id: EngagementId,
        action: MergeAction,
    ): Promise<MergeState>;
    getTree(id: EngagementId): Promise<FileEntry[]>;
    getFile(id: EngagementId, path: string): Promise<string>;
    /** `getFile` plus the cut the read serves (SUB-6 §12) — the base a
     *  cut-carrying save sends back. */
    getFileWithCut(
        id: EngagementId,
        path: string,
    ): Promise<{ content: string; cut: string | null }>;
    putFile(id: EngagementId, path: string, content: string): Promise<void>;
    /** Base-carrying save (SUB-6): concurrent changes merge server-side;
     *  divergence resolves to a structured conflict; fold-settled
     *  `resolutions` mint durable region memory. */
    saveFile(
        id: EngagementId,
        path: string,
        content: string,
        base: workbench.SaveBase,
        resolutions?: workbench.RegionResolution[],
    ): Promise<workbench.SaveFileResult>;
    /** Read-only save preview (the live fold, §12.3). */
    previewMerge(
        id: EngagementId,
        path: string,
        draft: string,
        baseCut: string,
    ): Promise<workbench.MergePreviewResult>;
    getConfig(id: EngagementId): Promise<string>;
    putConfig(id: EngagementId, raw: string): Promise<void>;
}

export interface RemoteControlPlaneOptions {
    readonly bearer?: string | null | (() => string | null);
    readonly homeAdmission?: string | null | (() => string | null);
    /** Test/server injection. Production uses credentialed browser fetch. */
    readonly route?: RouteJson;
}

/** HTTP + SSE adapter for a remotely hosted GaugeDesk placement. It carries
 * product commands/projections only; WhippleScript policy and evidence remain
 * behind the server-side runtime boundary. */
export class RemoteControlPlane implements ControlPlane {
    private bearer: string | null;
    private readonly bearerProvider?: () => string | null;
    private homeAdmission: string | null;
    private readonly homeAdmissionProvider?: () => string | null;
    private readonly route: RouteJson;
    private readonly request: RouteRequest;
    private readonly events: RouteEventStream;

    constructor(
        private readonly base: string,
        options: RemoteControlPlaneOptions = {},
    ) {
        this.base = base.replace(/\/+$/, "");
        this.bearerProvider =
            typeof options.bearer === "function" ? options.bearer : undefined;
        this.bearer = typeof options.bearer === "string" ? options.bearer : null;
        this.homeAdmissionProvider =
            typeof options.homeAdmission === "function" ? options.homeAdmission : undefined;
        this.homeAdmission =
            typeof options.homeAdmission === "string" ? options.homeAdmission : null;
        const auth: BrowserRouteJsonOptions = {
            bearer: () => this.currentBearer(),
            homeAdmission: () => this.currentHomeAdmission(),
        };
        this.route = options.route ?? browserRouteJson(this.base, auth);
        this.request = browserRouteRequest(this.base, auth);
        this.events = browserRouteEventStream(this.base, auth);
    }

    setBearer(token: string | null): void {
        this.bearer = token;
    }

    setHomeAdmission(token: string | null): void {
        this.homeAdmission = token;
    }

    /** Authenticate to the target Home after ordinary account login. The
     * credential remains memory-only and is never placed in a URL/storage. */
    async admitHome(): Promise<string> {
        const result = (await this.route("POST", "/home/admissions")) as {
            home?: unknown;
            admission?: unknown;
        };
        if (typeof result.home !== "string" || typeof result.admission !== "string") {
            throw new Error("Home admission response is malformed");
        }
        this.homeAdmission = result.admission;
        return result.home;
    }

    async revokeHomeAdmission(): Promise<void> {
        if (!this.currentHomeAdmission()) return;
        try {
            await this.route("DELETE", "/home/admissions");
        } finally {
            this.homeAdmission = null;
        }
    }

    /** The admitted Home's project/navigation projection. Callers must perform
     * admission first; this never turns a directory pointer into access. */
    getWorkspace(): Promise<Workspace> {
        return workbench.getWorkspace(this.transport());
    }

    createChatUnderPlacement(
        project: ProjectId,
        placement: PlacementId,
        title: string,
        targets: readonly WorkTargetId[],
    ): Promise<EngagementId> {
        return workbench.createChatUnderPlacement(this.transport(), project, placement, title, targets);
    }

    reviseChatTargets(
        chat: EngagementId,
        targets: readonly { targetId: WorkTargetId; participation: "read-only" | "writable" }[],
    ): Promise<unknown> {
        return workbench.reviseChatTargets(this.transport(), chat, targets);
    }

    forkChat(
        chat: EngagementId,
        destination?: workbench.ForkDestination,
    ): Promise<EngagementId> {
        return workbench.forkChat(this.transport(), chat, destination);
    }

    createWorkstream(placement: PlacementId, name: string): Promise<WorkstreamNode> {
        return workbench.createWorkstream(this.transport(), placement, name);
    }

    promoteWorkstream(workstream: WorkstreamId): Promise<workbench.WorkstreamPromotionResult> {
        return workbench.promoteWorkstream(this.transport(), workstream);
    }

    settleWorkstreamTarget(
        workstream: WorkstreamId,
        target: WorkTargetId,
        act: TargetActKind,
        promotionManifestRef?: string,
    ): Promise<unknown> {
        return workbench.settleWorkstreamTarget(
            this.transport(),
            workstream,
            target,
            act,
            promotionManifestRef,
        );
    }

    settleChatTargets(
        chat: EngagementId,
        members: readonly workbench.WorkstreamSettlementRequest[],
    ): Promise<unknown> {
        return workbench.settleChatTargets(this.transport(), chat, members);
    }

    getTargetSettlement(declarationId: string): Promise<unknown> {
        return workbench.getTargetSettlement(this.transport(), declarationId);
    }

    queryTargetSettlementMember(declarationId: string, memberId: string): Promise<unknown> {
        return workbench.queryTargetSettlementMember(this.transport(), declarationId, memberId);
    }

    retryTargetSettlementMember(declarationId: string, memberId: string): Promise<unknown> {
        return workbench.retryTargetSettlementMember(this.transport(), declarationId, memberId);
    }

    supersedeTargetSettlementMember(declarationId: string, memberId: string, laterDeclarationId: string, laterMemberId: string): Promise<unknown> {
        return workbench.supersedeTargetSettlementMember(this.transport(), declarationId, memberId, laterDeclarationId, laterMemberId);
    }

    compensateTargetSettlement(declarationId: string, receiptLinks: readonly workbench.CompensationReceiptLink[]): Promise<unknown> {
        return workbench.compensateTargetSettlement(this.transport(), declarationId, receiptLinks);
    }

    abandonTargetSettlement(declarationId: string, reason: string): Promise<unknown> {
        return workbench.abandonTargetSettlement(this.transport(), declarationId, reason);
    }

    cancelTargetSettlement(declarationId: string, reason: string): Promise<unknown> {
        return workbench.cancelTargetSettlement(this.transport(), declarationId, reason);
    }

    /** A Home-local, count-only notification projection. The caller must admit
     * the Home first; no review/resource/project identifiers leave the Home. */
    async reviewNotificationCount(): Promise<number> {
        const result = await this.route("GET", "/console/review-count") as { review_count?: unknown };
        if (typeof result.review_count !== "number" || !Number.isSafeInteger(result.review_count) || result.review_count < 0) {
            throw new Error("Review notification response is malformed");
        }
        return result.review_count;
    }

    private currentBearer(): string | null {
        return this.bearerProvider?.() ?? this.bearer;
    }

    private currentHomeAdmission(): string | null {
        return this.homeAdmissionProvider?.() ?? this.homeAdmission;
    }

    protected routeJson(): RouteJson {
        return this.route;
    }

    protected transport(): workbench.WorkbenchTransport {
        return {
            base: this.base,
            json: this.route,
            request: this.request,
            events: this.events,
        };
    }

    private async raw(
        method: string,
        path: string,
        body?: string,
        contentType?: string,
        allowStatuses: number[] = [],
    ): Promise<Response> {
        const response = await this.request(path, {
            method,
            headers: {
                ...(contentType ? { "content-type": contentType } : {}),
                ...(method !== "GET" && method !== "HEAD" && method !== "OPTIONS"
                    ? { "idempotency-key": newIdempotencyKey() }
                    : {}),
            },
            body,
        });
        if (!response.ok && !allowStatuses.includes(response.status)) {
            throw new Error(`${method} ${path}: ${response.status}`);
        }
        return response;
    }

    listEngagements() {
        return workbench.listEngagements(this.transport());
    }

    createEngagement(id?: EngagementId) {
        return workbench.createEngagement(this.transport(), id);
    }

    deleteChat(id: EngagementId) {
        return workbench.deleteChat(this.transport(), id);
    }

    getTranscript(id: EngagementId) {
        return workbench.getTranscript(this.transport(), id);
    }

    subscribe(
        id: EngagementId,
        onEvent: (event: StreamEvent) => void,
        onOpen?: () => void,
    ) {
        return workbench.subscribe(this.transport(), id, onEvent, onOpen);
    }

    runTask(
        id: EngagementId,
        prompt: string,
        images: { data: string; mimeType: string }[] = [],
    ) {
        return workbench.runTask(this.transport(), id, prompt, images);
    }

    stopTurn(id: EngagementId) {
        return workbench.stopTurn(this.transport(), id);
    }

    engagementDiff(id: EngagementId) {
        return workbench.engagementDiff(this.transport(), id);
    }

    getMerge(id: EngagementId) {
        return workbench.getMerge(this.transport(), id);
    }

    mergeCommand(id: EngagementId, action: MergeAction) {
        return workbench.mergeCommand(this.transport(), id, action);
    }

    getTree(id: EngagementId) {
        return workbench.getTree(this.transport(), id);
    }

    async getFile(id: EngagementId, path: string) {
        const response = await this.raw(
            "GET",
            `/chats/${id}/file?path=${encodeURIComponent(path)}`,
        );
        return response.text();
    }

    async putFile(id: EngagementId, path: string, content: string) {
        await this.raw(
            "PUT",
            `/chats/${id}/file?path=${encodeURIComponent(path)}`,
            content,
        );
    }

    async getFileWithCut(id: EngagementId, path: string) {
        const response = await this.raw(
            "GET",
            `/chats/${id}/file?path=${encodeURIComponent(path)}`,
        );
        return {
            content: await response.text(),
            cut: response.headers.get("x-workspace-cut"),
        };
    }

    async saveFile(
        id: EngagementId,
        path: string,
        content: string,
        base: workbench.SaveBase,
        resolutions?: workbench.RegionResolution[],
    ) {
        const response = await this.raw(
            "PUT",
            `/chats/${id}/file?path=${encodeURIComponent(path)}`,
            workbench.saveFileBody(content, base, resolutions),
            "application/json",
            [409],
        );
        return workbench.decodeSaveFileResponse(response.status, await response.json());
    }

    async previewMerge(id: EngagementId, path: string, draft: string, baseCut: string) {
        const response = await this.raw(
            "POST",
            `/chats/${id}/merge-preview`,
            JSON.stringify({ path, draft, base_cut: baseCut }),
            "application/json",
        );
        return workbench.decodePreviewResponse(await response.json());
    }

    async getConfig(id: EngagementId) {
        const response = await this.raw("GET", `/chats/${id}/config`);
        return response.text();
    }

    async putConfig(id: EngagementId, raw: string) {
        await this.raw("PUT", `/chats/${id}/config`, raw, "application/json");
    }
}
