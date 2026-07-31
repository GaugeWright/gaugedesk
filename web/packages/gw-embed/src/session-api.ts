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

/** Narrow transport consumed by the shared panel Session projection. */
export interface EmbedSessionApi {
    getTranscript(id: EngagementId): Promise<StreamEvent[]>;
    subscribe(id: EngagementId, onEvent: (ev: StreamEvent) => void, onOpen?: () => void): () => void;
    engagementDiff(id: EngagementId): Promise<string>;
    getMerge(id: EngagementId): Promise<MergeState>;
    runEmbedTurn(id: EngagementId, prompt: string, images?: { data: string; mimeType: string }[]): Promise<unknown>;
    runTask(id: EngagementId, prompt: string, images?: { data: string; mimeType: string }[]): Promise<unknown>;
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
    recordFirstTextRendered?(): void;
}
