import { createEffect, createMemo, createResource, createSignal, For, Show, type JSX } from "solid-js";
import type {
    ArchetypeId,
    ArchetypeNode,
    CollectionRecipient,
    CreatedHomeInvitation,
    FederationPeer,
    HandoffStatus,
    Participant,
    PlacementId,
    KeyDelegationView,
    ProjectId,
    ProjectKeyDelegations,
    ProjectNode,
    PendingHomeInvitation,
    ProjectShareDirectory,
    ProjectUpstream,
} from "@gaugewright/control-plane-client";
import { parseHomeInvitation } from "@gaugewright/control-plane-client";
import { ProjectModelAccessContent, type ProjectModelAccessApi } from "./ProjectModelAccessPanel";
import { WhipCostsSection, type WhipCostsApi } from "./WhipCosts";
import type { DeploymentSelection } from "./DeploymentPanel";
import { availableProjectShareCandidates } from "./project-sharing";
import "./project-settings.css";

export type ProjectSettingsPage = "overview" | "people" | "work-data" | "agents" | "model-access" | "background-work";

const PAGE_LABELS: Readonly<Record<ProjectSettingsPage, string>> = {
    overview: "Overview",
    people: "People & sharing",
    "work-data": "Work & data",
    agents: "Agents & placements",
    "model-access": "Model access",
    "background-work": "Background work",
};

export interface ProjectSettingsApi extends ProjectModelAccessApi, WhipCostsApi {
    handoffStatus(project: ProjectId): Promise<HandoffStatus>;
    handoffParticipants(project: ProjectId): Promise<Participant[]>;
    listPeers(): Promise<FederationPeer[]>;
    readonly desktopFederationAvailable?: boolean;
    handoffRelocate(project: ProjectId, peer: string): Promise<HandoffStatus>;
    handoffRevoke(project: ProjectId, authority: string, owns: string): Promise<void>;
    /** An account chosen from the organization, or an email address the
     *  accepting account must hold verified (DR-0332). */
    createHomeInvitation(
        recipient: string | { readonly email: string },
        project: ProjectId,
        role?: "member" | "viewer",
    ): Promise<CreatedHomeInvitation>;
    /** Ask the account service to email an email invitation's link to the
     *  address it is for; resolves to that address (DR-0332). */
    emailHomeInvitation?(invite: string): Promise<string>;
    /** The project's invitations still waiting to be accepted, with a way to
     *  withdraw one or replace its link (DR-0332). */
    pendingHomeInvitations?(project: ProjectId): Promise<PendingHomeInvitation[]>;
    cancelHomeInvitation?(id: string): Promise<void>;
    resendHomeInvitation?(id: string): Promise<CreatedHomeInvitation>;
    setProjectNetworkIsolated(project: ProjectId, isolated: boolean): Promise<void>;
    /** Rename a work target for the whole project (DR-0248): its name is the
     *  folder every chat and Agent sees it as. */
    renameProjectTarget?(project: ProjectId, target: string, name: string): Promise<void>;
    placeArchetype(project: ProjectId, archetype: ArchetypeId, recipient?: CollectionRecipient): Promise<PlacementId>;
    ensureCollectionRecipient?(recipientId: string): Promise<CollectionRecipient>;
    acceptPlacement(placement: PlacementId): Promise<void>;
    upgradePlacement(placement: PlacementId): Promise<number>;
    removePlacement(project: ProjectId, placement: PlacementId): Promise<void>;
    /** A fork's original and what pulling it would bring (GaugeWright DR-0208). */
    projectUpstream?(project: ProjectId): Promise<ProjectUpstream | null>;
    pullProjectUpstream?(
        project: ProjectId,
        sourceCut: string | null,
        resolutions: Readonly<Record<string, "mine" | "theirs">>,
    ): Promise<{ readonly pulled: number }>;
    /** What background work holds which of the project's keys (DR-0312). */
    getProjectKeyDelegations(project: ProjectId): Promise<ProjectKeyDelegations>;
}

interface ProjectSettingsProps {
    readonly api: ProjectSettingsApi;
    readonly project: ProjectNode;
    readonly library: readonly ArchetypeNode[];
    readonly page: ProjectSettingsPage;
    readonly onSelectPage: (page: ProjectSettingsPage) => void;
    readonly onClose: () => void;
    readonly onChanged: () => Promise<void> | void;
    readonly onAttachTarget?: (kind: "external-vcs" | "external-folder") => void;
    readonly onManageDeployment?: (selection: DeploymentSelection) => void;
    /** The selected organization's members and sharing policy (DR-0332). */
    readonly projectShareDirectory?: () => Promise<ProjectShareDirectory>;
    readonly onOpenOrganizationPeople?: () => void;
    /** The project's Engagement pane: handoff, combined invite and co-drive
     *  with paired devices. */
    readonly onOpenEngagement?: () => void;
}

function describeError(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
}

/** The address an email invitation is for, or nothing for one chosen from
 *  an organization or one that does not parse. */
function invitedAddress(encoded: string): string | undefined {
    try {
        return parseHomeInvitation(encoded).email;
    } catch {
        return undefined;
    }
}

function compactAuthority(authority: string): string {
    if (authority.length <= 38) return authority;
    return `${authority.slice(0, 22)}…${authority.slice(-10)}`;
}

function ProjectPageHeader(props: {
    readonly title: string;
    readonly description: string;
    readonly action?: JSX.Element;
}): JSX.Element {
    return <header class="project-settings-section-head">
        <div><h2>{props.title}</h2><p>{props.description}</p></div>
        {props.action}
    </header>;
}

function PeopleAndSharing(props: ProjectSettingsProps): JSX.Element {
    const [refresh, setRefresh] = createSignal(0);
    const source = () => props.project.isPersonal ? false : [props.project.id, refresh()] as const;
    const [participants] = createResource(source, ([project]) => props.api.handoffParticipants(project));
    const [handoff] = createResource(source, ([project]) => props.api.handoffStatus(project));
    const [peers] = createResource(
        () => props.api.desktopFederationAvailable !== false && source(),
        () => props.api.listPeers(),
    );
    // Only an organization's project has a roster or a policy to read; a
    // project an account owns is shared by email alone (DR-0332).
    const organizationProject = () => !props.project.isPersonal && props.project.organization !== null;
    const [shareDirectory, { refetch: refetchShareDirectory }] = createResource(
        () => !organizationProject() || !props.projectShareDirectory ? false : refresh(),
        () => props.projectShareDirectory?.() ?? Promise.resolve({ candidates: [], sharing: "members" as const }),
    );
    const emailOpen = () => !props.project.isPersonal
        && (props.project.organization === null || shareDirectory()?.sharing === "anyone");
    const [authority, setAuthority] = createSignal("");
    const [email, setEmail] = createSignal("");
    const [role, setRole] = createSignal<"member" | "viewer">("member");
    const [peer, setPeer] = createSignal("");
    const [invite, setInvite] = createSignal<CreatedHomeInvitation | null>(null);
    const [pendingRevoke, setPendingRevoke] = createSignal<Participant | null>(null);
    const [pendingInvites] = createResource(
        () => props.api.pendingHomeInvitations !== undefined && source(),
        ([project]) => props.api.pendingHomeInvitations?.(project) ?? Promise.resolve([]),
    );
    const [pendingCancel, setPendingCancel] = createSignal<string | null>(null);
    const [status, setStatus] = createSignal("");
    const [busy, setBusy] = createSignal(false);
    const activePeers = () => (peers() ?? []).filter((candidate) => candidate.active);
    const availableCandidates = createMemo(() => availableProjectShareCandidates(
        shareDirectory()?.candidates ?? [],
        participants() ?? [],
    ));

    const run = async (action: () => Promise<void>, success: string) => {
        setBusy(true);
        setStatus("");
        try {
            await action();
            setStatus(success);
            setRefresh((value) => value + 1);
            await props.onChanged();
        } catch (error) {
            setStatus(describeError(error));
        } finally {
            setBusy(false);
        }
    };

    const createInvite = async () => {
        const recipient = availableCandidates().find((candidate) => candidate.authority === authority())?.authority;
        if (!recipient) return;
        setBusy(true);
        setStatus("");
        try {
            setInvite(await props.api.createHomeInvitation(recipient, props.project.id, role()));
            setAuthority("");
            setRefresh((value) => value + 1);
            setStatus("Invitation ready. It is shown once and expires automatically.");
        } catch (error) {
            setStatus(describeError(error));
        } finally {
            setBusy(false);
        }
    };

    const createEmailInvite = async () => {
        const address = email().trim();
        if (!address) return;
        setBusy(true);
        setStatus("");
        try {
            setInvite(await props.api.createHomeInvitation({ email: address }, props.project.id, role()));
            setEmail("");
            setRefresh((value) => value + 1);
            setStatus(`Invitation ready. Only an account that has verified ${address} can accept it. It is shown once and expires automatically.`);
        } catch (error) {
            setStatus(describeError(error));
        } finally {
            setBusy(false);
        }
    };

    const [emailed, setEmailed] = createSignal<string | null>(null);
    const emailInvite = async (encoded: string) => {
        if (!props.api.emailHomeInvitation) return;
        setBusy(true);
        setStatus("");
        try {
            const sentTo = await props.api.emailHomeInvitation(encoded);
            setEmailed(encoded);
            setStatus(`Emailed to ${sentTo}, naming you as the person who invited them.`);
        } catch (error) {
            setStatus(describeError(error));
        } finally {
            setBusy(false);
        }
    };

    const resendInvite = async (id: string) => {
        if (!props.api.resendHomeInvitation) return;
        setBusy(true);
        setStatus("");
        try {
            setInvite(await props.api.resendHomeInvitation(id));
            setStatus("New link ready. The earlier link no longer works.");
            setRefresh((value) => value + 1);
        } catch (error) {
            setStatus(describeError(error));
        } finally {
            setBusy(false);
        }
    };

    if (props.project.isPersonal) {
        return <section class="project-settings-section">
            <ProjectPageHeader title="Private by design" description="Personal is your private default project. It cannot be shared or handed off." />
        </section>;
    }

    return <>
        <section class="project-settings-section">
            <ProjectPageHeader title="People with access" description="Access is granted by the Project Host and can be revoked here." />
            <Show when={!participants.loading} fallback={<p class="project-settings-empty">Loading access…</p>}>
                <div class="project-settings-rows">
                    <For each={(participants() ?? []).filter((participant) => !participant.revoked)} fallback={<p class="project-settings-empty">No additional participants.</p>}>
                        {(participant) => <div class="project-settings-row project-settings-person-row">
                            <div><strong>{compactAuthority(participant.authority)}</strong><small>{participant.role} · owns {participant.owns}</small></div>
                            <Show when={pendingRevoke()?.authority === participant.authority && pendingRevoke()?.owns === participant.owns} fallback={
                                <button type="button" class="danger" disabled={busy()} onClick={() => setPendingRevoke(participant)}>Revoke</button>
                            }>
                                <div class="project-settings-inline-actions"><button type="button" onClick={() => setPendingRevoke(null)}>Cancel</button><button type="button" class="danger" disabled={busy()} onClick={() => void run(async () => {
                                    await props.api.handoffRevoke(props.project.id, participant.authority, participant.owns);
                                    setPendingRevoke(null);
                                }, "Access revoked.")}>Confirm</button></div>
                            </Show>
                        </div>}
                    </For>
                </div>
            </Show>
        </section>

        <section class="project-settings-section">
            <ProjectPageHeader title="Invite to this project" description={organizationProject()
                ? emailOpen()
                    ? "Choose a member of this organization, or invite anyone by email."
                    : "Choose someone who already belongs to this organization."
                : "Invite anyone by email. Only an account that has verified that address can accept."} />
            <Show when={organizationProject()}>
                <Show when={props.projectShareDirectory} fallback={<p class="project-settings-empty">Choose an organization to share this project.</p>}>
                    <Show when={!shareDirectory.error} fallback={<div class="project-settings-empty project-settings-empty-action"><span>Organization members could not be loaded.</span><button type="button" onClick={() => void refetchShareDirectory()}>Retry</button></div>}>
                        <Show when={!shareDirectory.loading} fallback={<p class="project-settings-empty">Loading organization members…</p>}>
                            <Show when={availableCandidates().length > 0} fallback={<div class="project-settings-empty project-settings-empty-action"><span>Everyone available from the organization already has access.</span><Show when={props.onOpenOrganizationPeople}><button type="button" onClick={props.onOpenOrganizationPeople}>Open People</button></Show></div>}>
                                <div class="project-settings-form project-settings-invite-form">
                                    <label><span>Person</span><select value={authority()} onChange={(event) => setAuthority(event.currentTarget.value)}><option value="">Choose organization member</option><For each={availableCandidates()}>{(candidate) => <option value={candidate.authority}>{candidate.label}</option>}</For></select></label>
                                    <label><span>Access</span><select value={role()} onChange={(event) => setRole(event.currentTarget.value as "member" | "viewer")}><option value="member">Member</option><option value="viewer">Viewer</option></select></label>
                                    <button type="button" disabled={busy() || !availableCandidates().some((candidate) => candidate.authority === authority())} onClick={() => void createInvite()}>Create invite</button>
                                </div>
                            </Show>
                            <Show when={!emailOpen()}>
                                <p class="project-settings-help" data-sharing-members-only>Only members of this organization can be invited. An owner can allow invitations by email in Organization Policy.<Show when={props.onOpenOrganizationPeople}> <button type="button" class="project-settings-text-action" onClick={props.onOpenOrganizationPeople}>Invite them to the organization first</button>.</Show></p>
                            </Show>
                        </Show>
                    </Show>
                </Show>
            </Show>
            <Show when={emailOpen()}>
                <div class="project-settings-form project-settings-invite-form" data-invite-by-email>
                    <label><span>Email</span><input type="email" autocomplete="off" placeholder="name@example.com" value={email()} onInput={(event) => setEmail(event.currentTarget.value)} /></label>
                    <label><span>Access</span><select value={role()} onChange={(event) => setRole(event.currentTarget.value as "member" | "viewer")}><option value="member">Member</option><option value="viewer">Viewer</option></select></label>
                    <button type="button" disabled={busy() || !email().includes("@")} onClick={() => void createEmailInvite()}>Create invite</button>
                </div>
            </Show>
            <Show when={invite()}>{(value) => <div class="project-settings-once">
                <div><strong>Invitation link</strong><small>Copy it now; the capability is not retained in this page.</small></div>
                <code>{value().url}</code>
                <div class="project-settings-inline-actions">
                    <button type="button" onClick={() => void navigator.clipboard.writeText(value().url)}>Copy</button>
                    <Show when={props.api.emailHomeInvitation && invitedAddress(value().invite)}>{(address) =>
                        <button type="button" disabled={busy() || emailed() === value().invite} onClick={() => void emailInvite(value().invite)}>{emailed() === value().invite ? "Emailed" : `Email it to ${address()}`}</button>
                    }</Show>
                    <button type="button" onClick={() => setInvite(null)}>Done</button>
                </div>
            </div>}</Show>
            <Show when={(pendingInvites() ?? []).length > 0}>
                <div class="project-settings-rows" data-pending-invitations>
                    <h3 class="project-settings-subhead">Waiting to be accepted</h3>
                    <For each={pendingInvites() ?? []}>
                        {(pending) => <div class="project-settings-row project-settings-person-row">
                            <div><strong>{pending.email ?? compactAuthority(pending.authority)}</strong><small>{pending.role} · expires {new Date(pending.expiresAt * 1000).toLocaleDateString()}</small></div>
                            <Show when={pendingCancel() === pending.id} fallback={
                                <div class="project-settings-inline-actions">
                                    <Show when={props.api.resendHomeInvitation}><button type="button" disabled={busy()} onClick={() => void resendInvite(pending.id)}>Send again</button></Show>
                                    <Show when={props.api.cancelHomeInvitation}><button type="button" class="danger" disabled={busy()} onClick={() => setPendingCancel(pending.id)}>Cancel</button></Show>
                                </div>
                            }>
                                <div class="project-settings-inline-actions"><button type="button" onClick={() => setPendingCancel(null)}>Keep</button><button type="button" class="danger" disabled={busy()} onClick={() => void run(async () => {
                                    await props.api.cancelHomeInvitation?.(pending.id);
                                    setPendingCancel(null);
                                }, "Invitation cancelled. Its link no longer works.")}>Cancel invitation</button></div>
                            </Show>
                        </div>}
                    </For>
                </div>
            </Show>
        </section>

        <section class="project-settings-section">
            <ProjectPageHeader title="Project Host" description={handoff()?.home === "target" ? "This project's Home is held by the destination." : "Move this project's Home to a paired, trusted device."}
                action={props.onOpenEngagement && <button type="button" data-project-engagement onClick={props.onOpenEngagement}>Paired devices…</button>} />
            <Show when={activePeers().length > 0} fallback={<p class="project-settings-empty">No paired device is available for handoff.</p>}>
                <div class="project-settings-form project-settings-handoff-form">
                    <label><span>Destination</span><select value={peer()} onChange={(event) => setPeer(event.currentTarget.value)}><option value="">Choose device</option><For each={activePeers()}>{(candidate) => <option value={candidate.authority}>{compactAuthority(candidate.authority)}</option>}</For></select></label>
                    <button type="button" disabled={busy() || !peer()} onClick={() => void run(async () => { await props.api.handoffRelocate(props.project.id, peer()); }, "Handoff started. The destination must accept before the Home moves.")}>Hand off</button>
                </div>
            </Show>
        </section>
        <Show when={status()}>{(message) => <p class="project-settings-status" role="status">{message()}</p>}</Show>
    </>;
}

function WorkAndData(props: ProjectSettingsProps): JSX.Element {
    const [busy, setBusy] = createSignal(false);
    const [status, setStatus] = createSignal("");
    const [renaming, setRenaming] = createSignal<string | null>(null);
    const [draftName, setDraftName] = createSignal("");
    const renameTarget = async (target: string, previous: string) => {
        const name = draftName().trim();
        if (!name || name === previous) {
            setRenaming(null);
            return;
        }
        setBusy(true);
        setStatus("");
        try {
            await props.api.renameProjectTarget?.(props.project.id, target, name);
            setStatus(`Renamed ${previous} to ${name}.`);
            setRenaming(null);
            await props.onChanged();
        } catch (error) {
            setStatus(describeError(error));
        } finally {
            setBusy(false);
        }
    };
    const setNetwork = async () => {
        setBusy(true);
        setStatus("");
        try {
            await props.api.setProjectNetworkIsolated(props.project.id, !props.project.networkIsolated);
            setStatus(props.project.networkIsolated ? "Network access enabled." : "Network access isolated.");
            await props.onChanged();
        } catch (error) {
            setStatus(describeError(error));
        } finally {
            setBusy(false);
        }
    };
    return <>
        <section class="project-settings-section">
            <ProjectPageHeader
                title="Work targets"
                description="These are the repositories and folders Agents can work in for this project."
                action={<Show when={props.onAttachTarget}><div class="project-settings-inline-actions"><button type="button" onClick={() => props.onAttachTarget?.("external-vcs")}>Attach repository</button><button type="button" onClick={() => props.onAttachTarget?.("external-folder")}>Attach folder</button></div></Show>}
            />
            <div class="project-settings-rows">
                <For each={props.project.targets} fallback={<p class="project-settings-empty">No work targets are attached.</p>}>
                    {(target) => <div class="project-settings-row project-settings-target-row">
                        <Show
                            when={renaming() === target.id}
                            fallback={<div><strong>{target.name}</strong><small>{target.kind} · {target.status} · {target.capabilities.propose ? "writable" : "read-only"}</small></div>}
                        >
                            <form class="project-settings-inline-actions" onSubmit={(event) => { event.preventDefault(); void renameTarget(target.id, target.name); }}>
                                <input aria-label={`New name for ${target.name}`} value={draftName()} onInput={(event) => setDraftName(event.currentTarget.value)} disabled={busy()} />
                                <button type="submit" disabled={busy()}>Save</button>
                                <button type="button" disabled={busy()} onClick={() => setRenaming(null)}>Cancel</button>
                            </form>
                        </Show>
                        <span class="project-settings-inline-actions">
                            <span>{target.currentBasis ? "Current" : "No basis"}</span>
                            <Show when={props.api.renameProjectTarget && renaming() !== target.id}>
                                <button type="button" data-rename-target onClick={() => { setDraftName(target.name); setRenaming(target.id); }}>Rename</button>
                            </Show>
                        </span>
                    </div>}
                </For>
            </div>
        </section>
        <section class="project-settings-section">
            <ProjectPageHeader title="Network access" description="This applies to every Agent run in the project." action={<button type="button" disabled={busy()} onClick={() => void setNetwork()}>{props.project.networkIsolated ? "Allow network" : "Isolate"}</button>} />
            <p class="project-settings-policy-state"><strong>{props.project.networkIsolated ? "Isolated" : "Open"}</strong><span>{props.project.networkIsolated ? "Agents cannot make network requests." : "Agents may use admitted network and model connections."}</span></p>
        </section>
        <Show when={status()}>{(message) => <p class="project-settings-status" role="status">{message()}</p>}</Show>
    </>;
}

function plural(count: number, one: string, many = `${one}s`): string {
    return `${count} ${count === 1 ? one : many}`;
}

/** A fork's original: where it came from, and pulling what changed there
 *  since. The fork takes the original's work through its own merge; a file
 *  both changed is settled only by the choice made for it here. */
function ForkedFrom(props: ProjectSettingsProps): JSX.Element {
    const [refresh, setRefresh] = createSignal(0);
    const [upstream] = createResource(
        () => props.project.upstream && props.api.projectUpstream ? [props.project.id, refresh()] as const : false,
        ([project]) => props.api.projectUpstream!(project),
    );
    const [choices, setChoices] = createSignal<Record<string, "mine" | "theirs">>({});
    const [busy, setBusy] = createSignal(false);
    const [status, setStatus] = createSignal("");
    const ready = () => {
        const u = upstream();
        return u && u.available ? u : null;
    };
    const unresolved = () => ready()?.conflicts.filter((path) => !choices()[path]) ?? [];
    const pull = async () => {
        const u = ready();
        if (!u || !props.api.pullProjectUpstream) return;
        setBusy(true);
        setStatus("");
        try {
            const result = await props.api.pullProjectUpstream(props.project.id, u.sourceCut, choices());
            setStatus(result.pulled ? `Pulled ${plural(result.pulled, "file")} from ${u.name ?? "the original"}.` : "Your choices were recorded; nothing else changed.");
            setChoices({});
            setRefresh((n) => n + 1);
            await props.onChanged();
        } catch (error) {
            setStatus(describeError(error));
            setRefresh((n) => n + 1);
        } finally {
            setBusy(false);
        }
    };
    return <Show when={props.project.upstream}>
        <section class="project-settings-section" data-forked-from>
            <ProjectPageHeader
                title="Forked from"
                description="This project began as a copy of another one. Pulling brings in what changed there since; it never changes the original, and it gives neither project access to the other."
                action={<Show when={ready()}>{(u) => <button type="button" disabled={busy() || unresolved().length > 0 || (u().take.length + u().remove.length + u().conflicts.length === 0)} onClick={() => void pull()}>Pull changes</button>}</Show>}
            />
            <Show when={upstream()} fallback={<p class="project-settings-empty">{upstream.loading ? "Checking the original…" : "Pulling is not available here."}</p>}>
                {(u) => <Show
                    when={ready()}
                    fallback={<p class="project-settings-policy-state"><strong>{u().name ?? "The original"}</strong><span>{u().available ? "" : (u() as { reason: string }).reason}</span></p>}
                >
                    {(r) => <>
                        <p class="project-settings-policy-state">
                            <strong>{r().name ?? "The original"}</strong>
                            <span>{r().take.length + r().remove.length + r().conflicts.length === 0
                                ? "Up to date with the original."
                                : [
                                    r().take.length ? `${plural(r().take.length, "file")} to bring in` : "",
                                    r().remove.length ? `${plural(r().remove.length, "file")} the original removed` : "",
                                    r().conflicts.length ? `${plural(r().conflicts.length, "file")} changed in both` : "",
                                ].filter(Boolean).join(" · ")}</span>
                        </p>
                        <Show when={r().conflicts.length > 0}>
                            <div class="project-settings-rows">
                                <For each={r().conflicts}>
                                    {(path) => <div class="project-settings-row" data-conflict={path}>
                                        <div><strong>{path}</strong><small>Changed here and in the original</small></div>
                                        <span class="project-settings-inline-actions">
                                            <button type="button" aria-pressed={choices()[path] === "mine"} classList={{ active: choices()[path] === "mine" }} onClick={() => setChoices({ ...choices(), [path]: "mine" })}>Keep mine</button>
                                            <button type="button" aria-pressed={choices()[path] === "theirs"} classList={{ active: choices()[path] === "theirs" }} onClick={() => setChoices({ ...choices(), [path]: "theirs" })}>Take theirs</button>
                                        </span>
                                    </div>}
                                </For>
                            </div>
                        </Show>
                    </>}
                </Show>}
            </Show>
            <Show when={status()}>{(message) => <p class="project-settings-status" role="status">{message()}</p>}</Show>
        </section>
    </Show>;
}

function AgentsAndPlacements(props: ProjectSettingsProps): JSX.Element {
    const placements = () => props.project.placements.filter((placement) => !placement.isDefault);
    const available = createMemo(() => props.library.filter((agent) => !agent.isDefault));
    const [agent, setAgent] = createSignal("");
    const [busy, setBusy] = createSignal("");
    const [status, setStatus] = createSignal("");
    const [pendingRemoval, setPendingRemoval] = createSignal("");
    const addAgent = async () => {
        const chosen = available().find((candidate) => candidate.id === agent());
        if (!chosen) throw new Error("Choose an Agent from the Workshop.");
        const recipient = chosen.kind === "panel" && chosen.panelProfile?.collection
            ? await props.api.ensureCollectionRecipient?.(`${props.project.id}-${chosen.id}`)
            : undefined;
        await props.api.placeArchetype(props.project.id, chosen.id, recipient);
    };
    const run = async (key: string, action: () => Promise<unknown>, success: string) => {
        setBusy(key);
        setStatus("");
        try {
            await action();
            setPendingRemoval("");
            setStatus(success);
            await props.onChanged();
        } catch (error) {
            setStatus(describeError(error));
        } finally {
            setBusy("");
        }
    };
    return <>
        <section class="project-settings-section">
            <ProjectPageHeader title="Placed Agents" description="Each placement pins an Agent from the Workshop to this project." />
            <div class="project-settings-rows">
                <For each={placements()} fallback={<p class="project-settings-empty">No Agents have been placed in this project.</p>}>
                    {(placement) => <div class="project-settings-row project-settings-agent-row">
                        <div><strong>{placement.archetypeName}</strong><small>{placement.kind === "panel" ? "Panel agent" : "Agent"} · v{placement.version}{placement.pending ? " · awaiting acceptance" : ""}</small></div>
                        <span>{placement.deployments.length ? `${placement.deployments.length} deployment${placement.deployments.length === 1 ? "" : "s"}` : placement.upgradeAvailable ? `v${placement.currentVersion} available` : "Current"}</span>
                        <div class="project-settings-inline-actions">
                            <Show when={placement.kind === "panel" && placement.panelProfile && props.onManageDeployment}><button type="button" disabled={!!busy()} onClick={() => props.onManageDeployment?.({
                                projectId: props.project.id,
                                projectName: props.project.name,
                                placementId: placement.placementId,
                                archetypeName: placement.archetypeName,
                                version: placement.version,
                                profile: placement.panelProfile!,
                                deployments: placement.deployments,
                            })}>{placement.deployments.length ? "Manage" : "Deploy"}</button></Show>
                            <Show when={placement.pending}><button type="button" disabled={!!busy()} onClick={() => void run(placement.placementId, () => props.api.acceptPlacement(placement.placementId), "Placement accepted.")}>Accept</button></Show>
                            <Show when={placement.upgradeAvailable && !placement.pending}><button type="button" disabled={!!busy()} onClick={() => void run(placement.placementId, () => props.api.upgradePlacement(placement.placementId), "Agent upgraded.")}>Upgrade</button></Show>
                            <Show when={pendingRemoval() === placement.placementId} fallback={<button type="button" class="danger" disabled={!!busy()} onClick={() => setPendingRemoval(placement.placementId)}>Remove</button>}>
                                <button type="button" onClick={() => setPendingRemoval("")}>Cancel</button><button type="button" class="danger" disabled={!!busy()} onClick={() => void run(placement.placementId, () => props.api.removePlacement(props.project.id, placement.placementId), "Agent removed.")}>Confirm</button>
                            </Show>
                        </div>
                    </div>}
                </For>
            </div>
        </section>
        <section class="project-settings-section">
            <ProjectPageHeader title="Add from Workshop" description="Place an existing Agent archetype in this project." />
            <div class="project-settings-form project-settings-add-agent">
                <label><span>Agent</span><select value={agent()} onChange={(event) => setAgent(event.currentTarget.value)}><option value="">Choose Agent</option><For each={available()}>{(candidate) => <option value={candidate.id}>{candidate.name} · {candidate.kind === "panel" ? "Panel agent" : "Agent"}</option>}</For></select></label>
                <button type="button" disabled={!!busy() || !agent()} onClick={() => void run("add", addAgent, "Agent placed.")}>Add</button>
            </div>
        </section>
        <Show when={status()}>{(message) => <p class="project-settings-status" role="status">{message()}</p>}</Show>
    </>;
}

function day(ms: number): string {
    return new Date(ms).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function workTitle(delegation: KeyDelegationView): string {
    return delegation.work.targetName ? `${delegation.work.path} · ${delegation.work.targetName}` : delegation.work.path;
}

function steps(count: number): string {
    return `${count} unattended ${count === 1 ? "step" : "steps"}`;
}

/** What background work holds which of the project's keys (DR-0312). It is a
 *  record, never a control: nothing here grants or revokes anything. Reading
 *  it is a member using the project, which is what renews paused work. */
function BackgroundWork(props: ProjectSettingsProps): JSX.Element {
    const [record, { refetch }] = createResource(
        () => props.project.id,
        (project) => props.api.getProjectKeyDelegations(project),
    );
    // Opening the project renewed any paused work, so whatever showed it as
    // paused — the task bar's pill — is read again once, after the first read.
    let refreshed = false;
    createEffect(() => {
        if (record() && !refreshed) {
            refreshed = true;
            void props.onChanged();
        }
    });
    const held = (delegation: KeyDelegationView) => delegation.state === "held"
        ? `Holds its keys until ${day(delegation.expiresAtMs ?? 0)} unless someone uses this project first`
        : `Paused ${day(delegation.lapsedSinceMs ?? 0)}: nobody had used this project for 30 days. Opening it renewed the work, which resumes on the Home's next pass.`;
    return <>
        <section class="project-settings-section">
            <ProjectPageHeader
                title="Holding keys now"
                description="Work that runs while nobody is here holds only the keys it declared. It pauses after 30 days in which nobody uses this project, and resumes when someone does."
                action={<button type="button" onClick={() => void refetch()}>Refresh</button>}
            />
            <Show when={!record.error} fallback={<p class="project-settings-status" role="alert">Background work could not be read: {describeError(record.error)}</p>}>
                <div class="project-settings-rows">
                    <For each={record()?.delegations ?? []} fallback={<p class="project-settings-empty">{record.loading ? "Reading…" : "No background work holds this project's keys."}</p>}>
                        {(delegation) => <div class="project-settings-row project-settings-delegation" data-delegation-state={delegation.state}>
                            <div>
                                <strong>{workTitle(delegation)}</strong>
                                <small>Started by {compactAuthority(delegation.grantedFrom)} on {day(delegation.grantedAtMs)} · holds {delegation.keys.map((key) => key.label).join(", ") || "no keys"}</small>
                                <small>{held(delegation)}</small>
                                <Show when={delegation.refusals.length > 0}>
                                    <small class="project-settings-delegation-refused">Refused outside its declaration: {[...new Set(delegation.refusals.map((refusal) => refusal.label))].join(", ")}</small>
                                </Show>
                            </div>
                            <span>{delegation.state === "lapsed" ? "Paused" : steps(delegation.useCount)}</span>
                        </div>}
                    </For>
                </div>
            </Show>
        </section>
        <Show when={(record()?.ended.length ?? 0) > 0}>
            <section class="project-settings-section">
                <ProjectPageHeader title="Finished" description="Work that has ended holds no keys." />
                <div class="project-settings-rows">
                    <For each={record()?.ended ?? []}>
                        {(delegation) => <div class="project-settings-row project-settings-delegation" data-delegation-state="ended">
                            <div>
                                <strong>{workTitle(delegation)}</strong>
                                <small>Started by {compactAuthority(delegation.grantedFrom)} · {delegation.ended?.outcome ?? "ended"} {day(delegation.ended?.atMs ?? 0)}</small>
                            </div>
                            <span>{steps(delegation.useCount)}</span>
                        </div>}
                    </For>
                </div>
            </section>
        </Show>
    </>;
}

export function ProjectSettingsContent(props: ProjectSettingsProps): JSX.Element {
    return <main class="project-settings-content">
        <article class="project-settings-page">
            <header class="project-settings-page-head">
                <div><span>Project settings</span><h1>{props.project.name}</h1></div>
                <button type="button" onClick={props.onClose}>Close</button>
            </header>
            <div class="project-settings-title"><h2>{PAGE_LABELS[props.page]}</h2></div>
            <Show when={props.page === "overview"}>
                <section class="project-settings-overview" aria-label={`Settings for ${props.project.name}`}>
                    <p>Choose what to manage in this project. Organization rules still apply to every change.</p>
                    <div class="project-settings-overview-grid">
                        <Show when={!props.project.isPersonal}>
                            <button type="button" onClick={() => props.onSelectPage("people")}><strong>People & sharing</strong><span>Participants and project access</span></button>
                        </Show>
                        <button type="button" onClick={() => props.onSelectPage("work-data")}><strong>Work & data</strong><span>{props.project.upstream ? "forked · pull from the original · " : ""}{props.project.targets.length} work {props.project.targets.length === 1 ? "target" : "targets"} · {props.project.networkIsolated ? "network isolated" : "network open"}</span></button>
                        <button type="button" onClick={() => props.onSelectPage("agents")}><strong>Agents & placements</strong><span>{props.project.placements.filter((placement) => !placement.isDefault).length} placed</span></button>
                        <button type="button" onClick={() => props.onSelectPage("model-access")}><strong>Model access</strong><span>Connections, models, and usage</span></button>
                        <button type="button" onClick={() => props.onSelectPage("background-work")}><strong>Background work</strong><span>What runs while nobody is here, and the keys it holds</span></button>
                    </div>
                </section>
            </Show>
            <Show when={props.page === "people"}><PeopleAndSharing {...props} /></Show>
            <Show when={props.page === "work-data"}><ForkedFrom {...props} /><WorkAndData {...props} /></Show>
            <Show when={props.page === "agents"}><AgentsAndPlacements {...props} /></Show>
            <Show when={props.page === "model-access"}>
                <section class="project-settings-section project-settings-model"><ProjectModelAccessContent api={props.api} project={props.project.id} projectName={props.project.name} /></section>
                {/* What those models have actually cost, beside the page that
                    says which ones this project may use. */}
                <WhipCostsSection api={props.api} project={props.project.id} />
            </Show>
            <Show when={props.page === "background-work"}><BackgroundWork {...props} /></Show>
        </article>
    </main>;
}

export function ProjectSettingsMenu(props: {
    readonly projectName: string;
    readonly isPersonal?: boolean;
    readonly page: ProjectSettingsPage;
    readonly onSelect: (page: ProjectSettingsPage) => void;
    readonly onClose: () => void;
    readonly closeLabel?: string;
    readonly compact?: boolean;
}): JSX.Element {
    const pages = (): readonly ProjectSettingsPage[] => props.isPersonal === undefined
        ? []
        : props.isPersonal
            ? ["overview", "work-data", "agents", "model-access", "background-work"]
            : ["overview", "people", "work-data", "agents", "model-access", "background-work"];
    if (props.compact) return <nav class="project-settings-menu project-settings-menu-compact" aria-label={`Settings for ${props.projectName}`}>
        <button type="button" class="project-settings-menu-close" onClick={props.onClose}>{props.closeLabel ?? "Back to files"}</button>
        <label>
            <span>Page</span>
            <select aria-label={`Settings page for ${props.projectName}`} value={props.page} onChange={(event) => props.onSelect(event.currentTarget.value as ProjectSettingsPage)}>
                <For each={pages()}>{(page) => <option value={page}>{PAGE_LABELS[page]}</option>}</For>
            </select>
        </label>
    </nav>;
    return <nav class="project-settings-menu" aria-label={`Settings for ${props.projectName}`}>
        <header><span>Project</span><strong>{props.projectName}</strong></header>
        <For each={pages()}>{(page) => <button type="button" classList={{ active: props.page === page }} aria-current={props.page === page ? "page" : undefined} onClick={() => props.onSelect(page)}>{PAGE_LABELS[page]}</button>}</For>
        <button type="button" class="project-settings-menu-close" onClick={props.onClose}>{props.closeLabel ?? "Back to files"}</button>
    </nav>;
}
