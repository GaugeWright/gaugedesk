/**
 * An Agent a person reaches as a member of a shared project rather than as its
 * owner (DR-0453). A member of the project authors it — edit chats, settings,
 * previews, new versions, upgrades and deployments — but the Agent stays its
 * owner's: deleting, forking, copying and pulling into it remain the owner's
 * acts, and the Home refuses them to a member.
 */
import type { ArchetypeNode, ProjectId } from "./control-plane-domain";

/** The project whose Home serves this person's authoring of `agent`, when they
 *  author it as a member of a shared project; `null` for their own Agent. */
export function sharedAgentProject(agent: Pick<ArchetypeNode, "sharedThrough">): ProjectId | null {
    return agent.sharedThrough[0] ?? null;
}

/** Whether this person owns `agent`, and so may take the owner's own acts on
 *  it. Every authoring act is offered either way. */
export function ownsAgent(agent: Pick<ArchetypeNode, "sharedThrough">): boolean {
    return sharedAgentProject(agent) === null;
}

/** What a client opens says which project its work is routed to. */
export interface WorkRouteInputs {
    /** Project Settings or a Panel placement's settings, open over the chat. */
    readonly requested: ProjectId | null;
    /** A shared Agent's settings, open over the chat. */
    readonly agentSettings: ProjectId | null;
    /** The project of the open work chat. */
    readonly chatProject: ProjectId | null;
    /** The shared project of the open edit chat or preview's Agent. */
    readonly authoring: ProjectId | null;
}

/** The project whose Home serves the work in hand: settings opened over the
 *  chat first, then the open chat's own project, then — for an edit chat or a
 *  preview of an Agent shared through a project, which name no project of
 *  their own — that project, so they go on reaching the Home that serves it
 *  rather than whichever Home the account last selected. `null` returns to the
 *  selected Home. */
export function workRouteProject(inputs: WorkRouteInputs): ProjectId | null {
    return inputs.requested ?? inputs.agentSettings ?? inputs.chatProject ?? inputs.authoring ?? null;
}

/** The project an open chat's work is routed by, from the project the
 *  workspace read lists it under and the route that read went out under.
 *  A chat in any other project routes by that project. A Personal project is
 *  each Home's own, and every headless Home's is `proj-default`, so its id
 *  names no one Home: a route another Home published for it sent a Personal
 *  chat's turns there while the chat was on the Home that listed it (WS-893).
 *  A Personal chat keeps the route its read went out under instead, which
 *  reached the Home that holds it — the Home it was created on. */
export function chatRouteProject(
    project: { readonly id: ProjectId; readonly isPersonal: boolean },
    readUnder: ProjectId | null,
): ProjectId | null {
    return project.isPersonal ? readUnder : project.id;
}
