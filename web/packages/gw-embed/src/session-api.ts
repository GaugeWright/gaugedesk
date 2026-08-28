import type * as workbenchClient from "@gaugewright/control-plane-client";
import type {
    EngagementId,
    FileEntry,
    MergeAction,
    MergeState,
    StreamEvent,
} from "@gaugewright/control-plane-client";

export interface EdgeUsage {
    readonly usage_ref: string;
    readonly input_tokens: number;
    readonly cached_input_tokens: number;
    readonly output_tokens: number;
}

export interface EmbedQueuedTurn {
    readonly command_id: string;
    readonly text: string;
    readonly position: number;
}

// The live-turn vocabulary is declared once, by the shared panel contract this
// transport feeds. Re-exported rather than restated so the edge frame validator
// and the panel's labels cannot drift apart.
import type { TurnObservation } from "@gaugewright/workbench-ui/session-context";
export { TURN_ACTIVITIES } from "@gaugewright/workbench-ui/session-context";
export type { TurnActivity, TurnObservation } from "@gaugewright/workbench-ui/session-context";

/** Narrow transport consumed by the shared panel Session projection. */
export interface EmbedSessionApi {
    getTranscript(id: EngagementId): Promise<StreamEvent[]>;
    subscribe(id: EngagementId, onEvent: (ev: StreamEvent) => void, onOpen?: () => void): () => void;
    engagementDiff(id: EngagementId): Promise<string>;
    getMerge(id: EngagementId): Promise<MergeState>;
    runEmbedTurn(id: EngagementId, prompt: string, images?: { data: string; mimeType: string }[]): Promise<unknown>;
    /** `composedId` carries the outbox identity so a resend is idempotent
     *  (ADR 0137 §3). An implementation that cannot key on it may ignore it;
     *  what it must not do is treat two sends of the same id as two turns. */
    runTask(
        id: EngagementId,
        prompt: string,
        images?: { data: string; mimeType: string }[],
        composedId?: string,
    ): Promise<unknown>;
    mergeCommand(id: EngagementId, action: MergeAction): Promise<MergeState>;
    getFile(id: EngagementId, path: string): Promise<string>;
    getFileWithCut?(
        id: EngagementId,
        path: string,
    ): Promise<{ content: string; cut: string | null }>;
    putFile(id: EngagementId, path: string, content: string): Promise<void>;
    saveFile?(
        id: EngagementId,
        path: string,
        content: string,
        base: workbenchClient.SaveBase,
        resolutions?: workbenchClient.RegionResolution[],
    ): Promise<workbenchClient.SaveFileResult>;
    previewMerge?(
        id: EngagementId,
        path: string,
        draft: string,
        baseCut: string,
    ): Promise<workbenchClient.MergePreviewResult>;
    getTree(id: EngagementId): Promise<FileEntry[]>;
    readonly embedAudience?: boolean;
    embedMyChats(): Promise<{ chat: string; title: string }[]>;
    embedOpenChat?(chat: string): Promise<void>;
    embedNewChat?(): Promise<void>;
    embedEraseChat?(chat: string): Promise<void>;
    embedGetConfig(): Promise<{ white_label: boolean }>;
    getUsage?(): EdgeUsage | null;
    stopTurn?(): Promise<void>;
    compactTurn?(): Promise<void>;
    getTurnQueue?(): readonly EmbedQueuedTurn[];
    subscribeTurnQueue?(listener: (queue: readonly EmbedQueuedTurn[]) => void): () => void;
    getTurnActivity?(): TurnObservation;
    subscribeTurnActivity?(listener: (activity: TurnObservation) => void): () => void;
    followUpTurn?(text: string, images?: { data: string; mimeType: string }[]): Promise<void>;
    steerTurn?(text: string, images?: { data: string; mimeType: string }[]): Promise<void>;
    editQueuedTurn?(commandId: string, text: string): Promise<void>;
    removeQueuedTurn?(commandId: string): Promise<void>;
    reorderQueuedTurns?(commandIds: readonly string[]): Promise<void>;
    promoteQueuedTurn?(commandId: string): Promise<void>;
    recordFirstTextRendered?(): void;
}
