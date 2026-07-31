import type { Workspace, WorkspaceChange, WorkstreamNode } from "./control-plane-domain";
import { parseWorkspace } from "./control-plane-domain";

export interface WorkspaceOrder {
    readonly archetypes: readonly string[];
    readonly projects: readonly string[];
    readonly recent: readonly string[];
    readonly workstreams: readonly string[];
    readonly workTargets: readonly string[];
}

/** A narrow projection resolved from one reference-only workspace event. Parent
 * nodes are complete replacements because chat/workstream truth is denormalized
 * across the facet tree; `order` carries only visible ids so the patched tree
 * preserves the server's canonical ordering without retransmitting its content. */
export interface WorkspaceDelta {
    readonly change: WorkspaceChange;
    readonly replacements: Workspace;
    readonly order: WorkspaceOrder;
}

function stringArray(value: unknown, field: string): readonly string[] {
    if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
        throw new Error(`workspace delta ${field} must be a string array`);
    }
    return value;
}

/** Parse a delta at the transport edge into the same branded nodes as a full
 * workspace projection. */
export function parseWorkspaceDelta(raw: unknown, change: WorkspaceChange): WorkspaceDelta {
    const value = (raw ?? {}) as Record<string, unknown>;
    const order = (value.order ?? {}) as Record<string, unknown>;
    return {
        change,
        replacements: parseWorkspace(value),
        order: {
            archetypes: stringArray(order.archetypes, "order.archetypes"),
            projects: stringArray(order.projects, "order.projects"),
            recent: stringArray(order.recent, "order.recent"),
            workstreams: stringArray(order.workstreams, "order.workstreams"),
            workTargets: stringArray(order.work_targets, "order.work_targets"),
        },
    };
}

function withoutMember(workstream: WorkstreamNode, id: string): WorkstreamNode {
    return { ...workstream, members: workstream.members.filter((member) => member !== id) };
}

function upsertOrdered<T>(
    current: readonly T[],
    replacements: readonly T[],
    order: readonly string[],
    idOf: (value: T) => string,
): T[] {
    const byId = new Map(current.map((value) => [idOf(value), value]));
    for (const value of replacements) byId.set(idOf(value), value);
    const ranked = new Map(order.map((id, index) => [id, index]));
    return [...byId.values()].sort((a, b) => {
        const ar = ranked.get(idOf(a)) ?? Number.MAX_SAFE_INTEGER;
        const br = ranked.get(idOf(b)) ?? Number.MAX_SAFE_INTEGER;
        return ar - br;
    });
}

/** Apply one delta projection. The reference is removed everywhere first, which
 * makes tombstones and moves safe even though the server no longer knows an old
 * parent; current parent replacements are then upserted atomically. */
export function applyWorkspaceDelta(current: Workspace, delta: WorkspaceDelta): Workspace {
    const { record, id } = delta.change;
    const clearChat = record === "chat";
    const clearWorkstream = record === "workstream";

    const archetypes = current.archetypes
        .filter((archetype) => record !== "archetype" || archetype.id !== id)
        .map((archetype) => ({
            ...archetype,
            chats: clearChat ? archetype.chats.filter((chat) => chat.id !== id) : archetype.chats,
            workstreams: clearWorkstream
                ? archetype.workstreams.filter((workstream) => workstream.id !== id)
                : clearChat
                  ? archetype.workstreams.map((workstream) => withoutMember(workstream, id))
                  : archetype.workstreams,
        }));
    const projects = current.projects
        .filter((project) => record !== "project" || project.id !== id)
        .map((project) => ({
            ...project,
            placements: project.placements
                .filter(
                    (placement) =>
                        (record !== "placement" || placement.placementId !== id) &&
                        (record !== "archetype" || placement.archetypeId !== id),
                )
                .map((placement) => ({
                    ...placement,
                    chats: (clearChat
                        ? placement.chats.filter((chat) => chat.id !== id)
                        : placement.chats
                    ).map((chat) =>
                        clearWorkstream && chat.workstream === id ? { ...chat, workstream: null } : chat,
                    ),
                    workstreams: clearWorkstream
                        ? placement.workstreams.filter((workstream) => workstream.id !== id)
                        : clearChat
                          ? placement.workstreams.map((workstream) => withoutMember(workstream, id))
                          : placement.workstreams,
                })),
        }));
    const recent = current.recent
        .filter(
            (chat) =>
                (!clearChat || chat.id !== id) &&
                (record !== "placement" || chat.placement !== id),
        )
        .map((chat) =>
            clearWorkstream && chat.workstream === id ? { ...chat, workstream: null } : chat,
        );
    const workstreams = current.workstreams
        .filter((workstream) => !clearWorkstream || workstream.id !== id)
        .map((workstream) => (clearChat ? withoutMember(workstream, id) : workstream));
    const workTargets = current.workTargets.filter(
        (target) => record !== "work_target" || target.id !== id,
    );

    return {
        archetypes: upsertOrdered(
            archetypes,
            delta.replacements.archetypes,
            delta.order.archetypes,
            (value) => value.id,
        ),
        projects: upsertOrdered(
            projects,
            delta.replacements.projects,
            delta.order.projects,
            (value) => value.id,
        ),
        recent: upsertOrdered(
            recent,
            delta.replacements.recent,
            delta.order.recent,
            (value) => value.id,
        ),
        workstreams: upsertOrdered(
            workstreams,
            delta.replacements.workstreams,
            delta.order.workstreams,
            (value) => value.id,
        ),
        workTargets: upsertOrdered(
            workTargets,
            delta.replacements.workTargets,
            delta.order.workTargets,
            (value) => value.id,
        ),
        personalPlacement: delta.replacements.personalPlacement,
    };
}
