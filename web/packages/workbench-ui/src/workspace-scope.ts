/**
 * The work navigator follows the organization selector (DR-0325). Selecting
 * Personal shows the person's own projects; selecting an organization shows the
 * projects that organization owns. Recent follows the projects it can see, and
 * the task bar follows both.
 *
 * Workshop is not scoped: an Agent belongs to the person who made it and can be
 * placed in any project they work in, so its edit chats stay in Recent under
 * every selection.
 *
 * Scoping is presentation. It hides nothing the Home has not already decided the
 * person may see, and it grants nothing: a project is opened, and every read and
 * command authorized, by its own Home.
 */

import type { HumanTask, PlacementId, ProjectNode, Workspace } from "@gaugewright/control-plane-client";

/** The selected organization, as the navigator needs it. `organization` is the
 *  owning tenant id the projects carry, or `null` for Personal. */
export interface NavigatorScope {
    readonly organization: string | null;
}

/** The navigator scope for a selected membership, or `undefined` when nothing is
 *  selected — signed out, or before the account's memberships have resolved —
 *  in which case the navigator shows everything this Home lists. */
export function navigatorScope(
    selected: { readonly id: string; readonly personal: boolean } | null | undefined,
): NavigatorScope | undefined {
    if (!selected) return undefined;
    return { organization: selected.personal ? null : selected.id };
}

export function projectInScope(
    project: { readonly organization: string | null },
    scope: NavigatorScope | undefined,
): boolean {
    return !scope || project.organization === scope.organization;
}

/** The workspace as the navigator shows it under `scope`. Rows keep their
 *  identity, so a scoped tree reconciles like the full one. */
export function scopeWorkspace(workspace: Workspace, scope: NavigatorScope | undefined): Workspace {
    if (!scope) return workspace;
    const projects = workspace.projects.filter((project) => projectInScope(project, scope));
    if (projects.length === workspace.projects.length) return workspace;
    const hidden = new Set(workspace.projects
        .filter((project) => !projectInScope(project, scope))
        .flatMap((project) => project.placements.map((placement) => placement.placementId as string)));
    return {
        ...workspace,
        projects,
        // A work chat shows when its project does. An edit chat belongs to a
        // Workshop Agent, which is unscoped.
        recent: workspace.recent.filter((chat) =>
            chat.kind !== "work" || !chat.placement || !hidden.has(chat.placement)),
        workstreams: workspace.workstreams.filter((workstream) =>
            !hidden.has(workstream.placementId as string)),
    };
}

/** The task bar's chat-derived asks under `scope`. A `screen` task belongs to
 *  its project; every other ask belongs to the chat it names, and so to that
 *  chat's project. An ask whose chat no project in this workspace holds is an
 *  Agent edit chat's, and shows under every selection like Workshop does. */
export function scopeTasks(
    tasks: readonly HumanTask[],
    workspace: Workspace,
    scope: NavigatorScope | undefined,
): HumanTask[] {
    if (!scope) return [...tasks];
    const owner = new Map<string, boolean>();
    for (const project of workspace.projects) {
        const visible = projectInScope(project, scope);
        owner.set(project.id, visible);
        for (const placement of project.placements) {
            for (const chat of placement.chats) owner.set(chat.id, visible);
        }
    }
    return tasks.filter((task) => owner.get(task.project ?? task.id) ?? true);
}

/** Where a chat started from the empty composer goes under `scope`: the Home's
 *  Personal placement when its project is in scope, else the default placement
 *  of the first project in scope. `null` when nothing in scope can hold one, so
 *  a chat is never started somewhere the navigator would not show it. */
export function quickStartPlacement(
    workspace: Workspace,
    scope: NavigatorScope | undefined,
): { readonly project: ProjectNode; readonly placementId: PlacementId } | null {
    const projects = scopeWorkspace(workspace, scope).projects
        .filter((project) => project.product?.kind !== "tutorials");
    const personal = workspace.personalPlacement;
    const owner = personal
        ? projects.find((project) => project.placements.some((placement) => placement.placementId === personal))
        : undefined;
    if (owner && personal) return { project: owner, placementId: personal };
    if (!scope && personal) return null;
    for (const project of projects) {
        const placement = project.placements.find((candidate) => candidate.isDefault);
        if (placement) return { project, placementId: placement.placementId };
    }
    return null;
}

/** The projects whose tracker assignments the task bar reads under `scope`. */
export function scopeProjects<T extends { readonly organization: string | null }>(
    projects: readonly T[],
    scope: NavigatorScope | undefined,
): T[] {
    return projects.filter((project) => projectInScope(project, scope));
}
