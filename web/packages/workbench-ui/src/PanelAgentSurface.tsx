/**
 * The opened Panel agent (`experience/navigation.md` Workshop, PANEL-12).
 *
 * Selecting a Panel agent puts its edit chat in the Chat pane and this surface
 * in the Content pane, the way project settings take that pane. It hosts the
 * two things developing a Panel agent is made of, side by side: the public
 * contract, edited in place while it is the Workshop draft, and Preview, the
 * real disposable public session, mounted but not started.
 *
 * A placement pinned to a frozen version opens the same surface. Its contract
 * is shown rather than edited, and Deploy and Inbox take the place of edit and
 * publish, because a project is the durable owner of a deployment (ADR 0143).
 * `panel-agent-opening.ts` decides which of the two this is.
 */

import { createEffect, createMemo, createResource, createSignal, Show, type JSX } from "solid-js";
import type {
    ArchetypeId,
    ArchetypeNode,
    PanelPublicProfile,
    PlacementNode,
    ProjectNode,
} from "@gaugewright/control-plane-client";
import { PanelAgentPreview, type PanelAgentPreviewApi } from "./PanelAgentPreview";
import { PanelContractEditor } from "./PanelContractEditor";
import { plainConfigError } from "./AgentSettings";
import { panelAgentSurfacePlan } from "./panel-agent-opening";
import "./project-settings.css";

export interface PanelAgentSurfaceApi extends PanelAgentPreviewApi {
    getPanelProfile(id: ArchetypeId): Promise<PanelPublicProfile>;
    setPanelProfile(id: ArchetypeId, profile: PanelPublicProfile): Promise<PanelPublicProfile>;
    publishArchetype(id: ArchetypeId, autoUpgrade?: boolean): Promise<{ version: number; autoUpgraded: number }>;
}

export function PanelAgentSurface(props: {
    api: PanelAgentSurfaceApi;
    agent: ArchetypeNode;
    /** Present when opened from a project placement: the surface is pinned to it. */
    project?: ProjectNode;
    placement?: PlacementNode;
    defaultEdgeOrigin: string;
    defaultCredentialRef: string;
    onClose: () => void;
    /** Start another edit chat on this agent (the draft scope only). */
    onNewEditChat?: () => void;
    onDeploy?: () => void;
    onOpenInbox?: () => void;
    /** A new version was frozen from the draft; the nav should pick it up. */
    onPublished?: (version: number) => void;
}): JSX.Element {
    const plan = createMemo(() => panelAgentSurfacePlan(props.placement, props.project?.name));
    // The draft contract is read from the Home, not from the tree's snapshot, so
    // an edit saved from Agent Settings a moment ago is what this surface edits.
    const [loaded, { refetch }] = createResource(
        () => plan().scope === "draft" ? props.agent.id : null,
        (id) => props.api.getPanelProfile(id),
    );
    const [draft, setDraft] = createSignal<PanelPublicProfile | null>(null);
    const [dirty, setDirty] = createSignal(false);
    const [message, setMessage] = createSignal("");
    const [busy, setBusy] = createSignal(false);
    createEffect(() => {
        const profile = loaded();
        if (profile && !dirty()) setDraft(profile);
    });
    const frozen = () => props.placement?.panelProfile ?? null;

    function edit(next: PanelPublicProfile) {
        setDraft(next);
        setDirty(true);
        setMessage("");
    }

    async function save() {
        const profile = draft();
        if (!profile) return;
        setBusy(true);
        try {
            const saved = await props.api.setPanelProfile(props.agent.id, profile);
            setDraft(saved);
            setDirty(false);
            setMessage("Contract saved. Preview runs it from the next start.");
            await refetch();
        } catch (reason) {
            setMessage(plainConfigError(String(reason)));
        } finally {
            setBusy(false);
        }
    }

    async function publish() {
        setBusy(true);
        try {
            const published = await props.api.publishArchetype(props.agent.id);
            setMessage(`Published v${published.version}.`);
            props.onPublished?.(published.version);
        } catch (reason) {
            setMessage(String(reason));
        } finally {
            setBusy(false);
        }
    }

    const contractRows = (profile: PanelPublicProfile) => <div class="member-list">
        <div class="member-row"><span>Panels</span><span class="member-id">{profile.panels.components.join(", ")}</span></div>
        <div class="member-row"><span>Abilities</span><span class="member-id">{profile.public_abilities.join(", ") || "Chat only"}</span></div>
        <div class="member-row"><span>Provider</span><span class="member-id">{profile.provider.provider} · {profile.provider.model}</span></div>
        <div class="member-row"><span>Audience inputs</span><span class="member-id">{profile.audience_inputs.join(", ")}</span></div>
        <div class="member-row"><span>Initial content</span><span class="member-id">{profile.initial_workspace.length} file(s)</span></div>
        <div class="member-row"><span>Collection</span><span class="member-id">{profile.collection ? `${profile.collection.schema_ref} → project Inbox` : "Off"}</span></div>
    </div>;

    return <main class="project-settings-content panel-agent-surface" data-panel-agent-surface data-panel-agent-scope={plan().scope}>
        <article class="project-settings-page">
            <header class="project-settings-page-head">
                <div><span>Panel agent</span><h1>{props.agent.name}</h1><p class="muted panel-agent-subtitle">{plan().subtitle}</p></div>
                <button type="button" onClick={props.onClose}>Close</button>
            </header>
            <div class="project-settings-title">
                <h2>{plan().scope === "draft" ? "Develop" : "Placement"}</h2>
                <div class="deployment-actions">
                    <Show when={plan().scope === "draft" && props.onNewEditChat}>
                        <button type="button" onClick={props.onNewEditChat}>New edit chat</button>
                    </Show>
                    <Show when={plan().actions.includes("publish")}>
                        <button type="button" class="primary" disabled={busy()} onClick={() => void publish()}>Publish a new version</button>
                    </Show>
                    <Show when={plan().actions.includes("deploy") && props.onDeploy}>
                        <button type="button" class="primary" onClick={props.onDeploy}>{plan().deployLabel}</button>
                    </Show>
                    <Show when={plan().actions.includes("inbox") && props.onOpenInbox}>
                        <button type="button" onClick={props.onOpenInbox}>Inbox</button>
                    </Show>
                </div>
            </div>

            <section class="project-settings-section">
                <PanelAgentPreview
                    api={props.api}
                    agent={props.agent}
                    project={props.project}
                    placementId={props.placement?.placementId}
                    defaultEdgeOrigin={props.defaultEdgeOrigin}
                    defaultCredentialRef={props.defaultCredentialRef} />
            </section>

            <section class="project-settings-section" data-panel-agent-contract>
                <Show when={plan().contractEditable} fallback={<div class="admin-section">
                    <h3>Frozen public contract</h3>
                    <p class="settings-hint">This is the pinned version. To change it, edit the Panel agent in the Workshop, publish a new version, and upgrade the placement.</p>
                    <Show when={frozen()} fallback={<p class="status">This placement has no frozen public profile.</p>}>{(profile) => contractRows(profile())}</Show>
                </div>}>
                    <Show when={draft()} fallback={<div class="admin-section"><h3>Public contract</h3>
                        <Show when={loaded.error} fallback={<p class="status">loading…</p>}>{(error) => <p class="error">Could not load the contract: {String(error())}</p>}</Show>
                    </div>}>
                        {(profile) => <div class="settings-form"><PanelContractEditor profile={profile()} onChange={edit} onNotice={setMessage} /></div>}
                    </Show>
                    <div class="bar">
                        <button type="button" data-panel-contract-save disabled={busy() || !dirty()} onClick={() => void save()}>Save contract</button>
                        <span class="status" data-panel-contract-status>{message()}</span>
                    </div>
                    <p class="settings-hint">Preview runs the saved contract. Publishing freezes it into a version; deployments cannot redefine it.</p>
                </Show>
            </section>
        </article>
    </main>;
}
