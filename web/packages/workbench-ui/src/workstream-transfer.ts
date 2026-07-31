import type {
    EngagementId,
    WorkspaceRootId,
    WorkstreamId,
    WorkstreamNode,
} from "@gaugewright/control-plane-client";

export interface WorkstreamTransferChat {
    readonly id: EngagementId;
    readonly workspaceRoot: WorkspaceRootId;
    readonly workstream?: WorkstreamId | null;
    readonly rehomeBlocked: boolean;
}

/** Client-side affordance only; the control plane repeats these rules atomically. */
export function canTransferToWorkstream(
    chat: WorkstreamTransferChat | null,
    destination: WorkstreamNode,
): boolean {
    return !!chat
        && !chat.rehomeBlocked
        && chat.workspaceRoot === destination.workspaceRoot
        && chat.workstream !== destination.id;
}

/** Main is implicit, so its rendered root must be supplied by the containing group. */
export function canTransferToMain(
    chat: WorkstreamTransferChat | null,
    root: WorkspaceRootId | undefined,
): boolean {
    return !!chat?.workstream
        && !chat.rehomeBlocked
        && !!root
        && chat.workspaceRoot === root;
}
