/**
 * The work targets a new chat under a placement can work on, and why none can.
 *
 * A placement names its targets; the workspace lists each target's status and
 * capabilities. A new chat needs at least one that is available and readable.
 * When there is none, the person who asked for the chat is told why, where they
 * asked (action-failure.feature): the navigator's "new chat" and the empty
 * composer used to write "no available work target can be read" only to the
 * workbench status, which is a refresh key and not on screen, so the control
 * did nothing visible and the composer dropped the message (WS-965).
 */

import type { PlacementId, WorkTargetNode, Workspace } from "@gaugewright/control-plane-client";

/** The targets `placementId` works on: an Agent's authoring target for its own
 *  edit placement, else the project placement's target set. */
export function placementTargetIds(workspace: Workspace, placementId: PlacementId): readonly string[] {
    const authoring = workspace.archetypes.find((archetype) => archetype.instanceId === placementId);
    if (authoring) return [authoring.authoringTargetId];
    return workspace.projects
        .flatMap((project) => project.placements)
        .find((placement) => placement.placementId === placementId)?.targetIds ?? [];
}

/** The targets of `placementId` a new chat can read. */
export function readableTargets(workspace: Workspace, placementId: PlacementId): WorkTargetNode[] {
    return placementTargetIds(workspace, placementId)
        .map((id) => workspace.workTargets.find((target) => target.id === id))
        .filter((target): target is WorkTargetNode => !!target && target.status === "available" && target.capabilities.read);
}

/** Why no target of `placementId` can be read, in words for the person who
 *  asked for a chat there. */
export function noReadableTargetReason(workspace: Workspace, placementId: PlacementId): string {
    const ids = placementTargetIds(workspace, placementId);
    if (ids.length === 0) return "this Agent has no work target here";
    const reasons = ids.map((id) => {
        const target = workspace.workTargets.find((candidate) => candidate.id === id);
        if (!target) return "one of its work targets is not listed on this Home";
        if (target.status !== "available") return `"${target.name}" is ${target.status}`;
        return `"${target.name}" cannot be read`;
    });
    return `no work target of this Agent can be read: ${[...new Set(reasons)].join("; ")}`;
}
