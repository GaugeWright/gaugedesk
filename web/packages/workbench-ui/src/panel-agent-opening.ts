/**
 * What opening a Panel agent does (`experience/navigation.md`, PANEL-12).
 *
 * Selecting a Panel agent is one movement across the panes: its edit chat in
 * Chat, the agent itself in Content. Two decisions live here rather than in
 * the tree or the app, so a UI rewrite cannot quietly change them: which edit
 * chat opens, and what a placement pinned to a frozen version may do compared
 * with the Workshop draft.
 */

import type { PlacementNode } from "@gaugewright/control-plane-client";

/** The edit chat to show when a Panel agent opens: the latest, or none, in which
 *  case the opener creates one. The workspace projection lists an archetype's
 *  chats oldest first, so the latest is the last. */
export function editChatToOpen<Id>(chats: readonly { readonly id: Id }[]): Id | null {
    return chats.length ? chats[chats.length - 1]!.id : null;
}

export type PanelAgentSurfaceAction = "publish" | "deploy" | "inbox";

export interface PanelAgentSurfacePlan {
    readonly scope: "draft" | "pinned";
    /** The line under the agent's name: where this contract comes from. */
    readonly subtitle: string;
    /** The draft contract is edited in place; a pinned contract is frozen and shown. */
    readonly contractEditable: boolean;
    /** Header actions. Publish belongs to the draft; deploy and Inbox to a placement,
     *  because a project is the durable owner of a deployment (ADR 0143). */
    readonly actions: readonly PanelAgentSurfaceAction[];
    /** The deploy action's label, which says whether a deployment already exists. */
    readonly deployLabel: string;
}

/** The surface for a Workshop draft, or for a placement pinned to a version. */
export function panelAgentSurfacePlan(
    placement: Pick<PlacementNode, "version" | "deployments"> | null | undefined,
    projectName?: string,
): PanelAgentSurfacePlan {
    if (!placement) {
        return {
            scope: "draft",
            subtitle: "Workshop draft",
            contractEditable: true,
            actions: ["publish"],
            deployLabel: "",
        };
    }
    return {
        scope: "pinned",
        subtitle: `${projectName ?? "Project"} · pinned v${placement.version}`,
        contractEditable: false,
        actions: ["deploy", "inbox"],
        deployLabel: placement.deployments.length ? "Manage deployments…" : "Deploy…",
    };
}
