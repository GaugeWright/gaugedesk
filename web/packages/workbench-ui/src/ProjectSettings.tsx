import { createMemo, createResource, createSignal, For, Show, type JSX } from "solid-js";
import type {
    ArchetypeId,
    ArchetypeNode,
    CollectionRecipient,
    CreatedHomeInvitation,
    FederationPeer,
    HandoffStatus,
    Participant,
    PlacementId,
    ProjectId,
    ProjectNode,
    ProjectShareCandidate,
} from "@gaugewright/control-plane-client";
import { ProjectModelAccessContent, type ProjectModelAccessApi } from "./ProjectModelAccessPanel";
import { WhipCostsSection, type WhipCostsApi } from "./WhipCosts";
import type { DeploymentSelection } from "./DeploymentPanel";
import { availableProjectShareCandidates } from "./project-sharing";
import "./project-settings.css";

export type ProjectSettingsPage = "people" | "work-data" | "agents" | "model-access";

const PAGE_LABELS: Readonly<Record<ProjectSettingsPage, string>> = {
    people: "People & sharing",
    "work-data": "Work & data",
    agents: "Agents & placements",
    "model-access": "Model access",
};

export interface ProjectSettingsApi extends ProjectModelAccessApi, WhipCostsApi {
    handoffStatus(project: ProjectId): Promise<HandoffStatus>;
    handoffParticipants(project: ProjectId): Promise<Participant[]>;
    listPeers(): Promise<FederationPeer[]>;
    handoffRelocate(project: ProjectId, peer: string): Promise<HandoffStatus>;
    handoffRevoke(project: ProjectId, authority: string, owns: string): Promise<void>;
    createHomeInvitation(
        authority: string,
        project: ProjectId,
        role?: "member" | "viewer",
    ): Promise<CreatedHomeInvitation>;
    setProjectNetworkIsolated(project: ProjectId, isolated: boolean): Promise<void>;
    placeArchetype(project: ProjectId, archetype: ArchetypeId, recipient?: CollectionRecipient): Promise<PlacementId>;
    ensureCollectionRecipient?(recipientId: string): Promise<CollectionRecipient>;
    acceptPlacement(placement: PlacementId): Promise<void>;
    upgradePlacement(placement: PlacementId): Promise<number>;
    removePlacement(project: ProjectId, placement: PlacementId): Promise<void>;
}

interface ProjectSettingsProps {
    readonly api: ProjectSettingsApi;
    readonly project: ProjectNode;
    readonly library: readonly ArchetypeNode[];
    readonly page: ProjectSettingsPage;
    readonly onClose: () => void;
    readonly onChanged: () => Promise<void> | void;
    readonly onAttachTarget?: (kind: "external-vcs" | "external-folder") => void;
    readonly onManageDeployment?: (selection: DeploymentSelection) => void;
    readonly projectShareCandidates?: () => Promise<readonly ProjectShareCandidate[]>;
    readonly onOpenOrganizationPeople?: () => void;
}

function describeError(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
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
    const [peers] = createResource(source, () => props.api.listPeers());
    const [shareCandidates, { refetch: refetchShareCandidates }] = createResource(
        () => props.project.isPersonal || !props.projectShareCandidates ? false : refresh(),
        () => props.projectShareCandidates?.() ?? Promise.resolve([]),
    );
    const [authority, setAuthority] = createSignal("");
    const [role, setRole] = createSignal<"member" | "viewer">("member");
    const [peer, setPeer] = createSignal("");
    const [invite, setInvite] = createSignal<CreatedHomeInvitation | null>(null);
    const [pendingRevoke, setPendingRevoke] = createSignal<Participant | null>(null);
    const [status, setStatus] = createSignal("");
    const [busy, setBusy] = createSignal(false);
    const activePeers = () => (peers() ?? []).filter((candidate) => candidate.active);
    const availableCandidates = createMemo(() => availableProjectShareCandidates(
        shareCandidates() ?? [],
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
            setStatus("Invitation ready. It is shown once and expires automatically.");
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
            <ProjectPageHeader title="Invite to this project" description="Choose someone who already belongs to this organization." />
            <Show when={props.projectShareCandidates} fallback={<p class="project-settings-empty">Choose an organization to share this project.</p>}>
                <Show when={!shareCandidates.error} fallback={<div class="project-settings-empty project-settings-empty-action"><span>Organization members could not be loaded.</span><button type="button" onClick={() => void refetchShareCandidates()}>Retry</button></div>}>
                    <Show when={!shareCandidates.loading} fallback={<p class="project-settings-empty">Loading organization members…</p>}>
                        <Show when={availableCandidates().length > 0} fallback={<div class="project-settings-empty project-settings-empty-action"><span>Everyone available from the organization already has access.</span><Show when={props.onOpenOrganizationPeople}><button type="button" onClick={props.onOpenOrganizationPeople}>Open People</button></Show></div>}>
                            <div class="project-settings-form project-settings-invite-form">
                                <label><span>Person</span><select value={authority()} onChange={(event) => setAuthority(event.currentTarget.value)}><option value="">Choose organization member</option><For each={availableCandidates()}>{(candidate) => <option value={candidate.authority}>{candidate.label}</option>}</For></select></label>
                                <label><span>Access</span><select value={role()} onChange={(event) => setRole(event.currentTarget.value as "member" | "viewer")}><option value="member">Member</option><option value="viewer">Viewer</option></select></label>
                                <button type="button" disabled={busy() || !availableCandidates().some((candidate) => candidate.authority === authority())} onClick={() => void createInvite()}>Create invite</button>
                            </div>
                            <Show when={props.onOpenOrganizationPeople}><p class="project-settings-help">Need someone else? <button type="button" class="project-settings-text-action" onClick={props.onOpenOrganizationPeople}>Invite them to the organization first</button>.</p></Show>
                        </Show>
                    </Show>
                </Show>
            </Show>
            <Show when={invite()}>{(value) => <div class="project-settings-once">
                <div><strong>Invitation link</strong><small>Copy it now; the capability is not retained in this page.</small></div>
                <code>{value().url}</code>
                <div class="project-settings-inline-actions"><button type="button" onClick={() => void navigator.clipboard.writeText(value().url)}>Copy</button><button type="button" onClick={() => setInvite(null)}>Done</button></div>
            </div>}</Show>
        </section>

        <section class="project-settings-section">
            <ProjectPageHeader title="Project Host" description={handoff()?.home === "target" ? "This project's Home is held by the destination." : "Move this project's Home to a paired, trusted device."} />
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
                        <div><strong>{target.name}</strong><small>{target.kind} · {target.status} · {target.capabilities.propose ? "writable" : "read-only"}</small></div>
                        <span>{target.currentBasis ? "Current" : "No basis"}</span>
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

function AgentsAndPlacements(props: ProjectSettingsProps): JSX.Element {
    const placements = () => props.project.placements.filter((placement) => !placement.isDefault);
    const available = createMemo(() => props.library.filter((agent) => !agent.isDefault));
    const [agent, setAgent] = createSignal("");
    const [busy, setBusy] = createSignal("");
    const [status, setStatus] = createSignal("");
    const [pendingRemoval, setPendingRemoval] = createSignal("");
    const addAgent = async () => {
        const chosen = available().find((candidate) => candidate.id === agent());
        if (!chosen) throw new Error("Choose an Agent from the Library.");
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
            <ProjectPageHeader title="Placed Agents" description="Each placement pins an Agent from the Library to this project." />
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
            <ProjectPageHeader title="Add from Library" description="Place an existing Agent archetype in this project." />
            <div class="project-settings-form project-settings-add-agent">
                <label><span>Agent</span><select value={agent()} onChange={(event) => setAgent(event.currentTarget.value)}><option value="">Choose Agent</option><For each={available()}>{(candidate) => <option value={candidate.id}>{candidate.name} · {candidate.kind === "panel" ? "Panel agent" : "Agent"}</option>}</For></select></label>
                <button type="button" disabled={!!busy() || !agent()} onClick={() => void run("add", addAgent, "Agent placed.")}>Add</button>
            </div>
        </section>
        <Show when={status()}>{(message) => <p class="project-settings-status" role="status">{message()}</p>}</Show>
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
            <Show when={props.page === "people"}><PeopleAndSharing {...props} /></Show>
            <Show when={props.page === "work-data"}><WorkAndData {...props} /></Show>
            <Show when={props.page === "agents"}><AgentsAndPlacements {...props} /></Show>
            <Show when={props.page === "model-access"}>
                <section class="project-settings-section project-settings-model"><ProjectModelAccessContent api={props.api} project={props.project.id} projectName={props.project.name} /></section>
                {/* What those models have actually cost, beside the page that
                    says which ones this project may use. */}
                <WhipCostsSection api={props.api} project={props.project.id} />
            </Show>
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
            ? ["work-data", "agents", "model-access"]
            : ["people", "work-data", "agents", "model-access"];
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
