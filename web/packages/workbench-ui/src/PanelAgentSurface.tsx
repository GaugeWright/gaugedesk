/**
 * The opened Panel agent (`experience/navigation.md` Workshop, PANEL-12).
 *
 * Opening a Panel agent puts its edit chat in the Chat pane and this surface in
 * the Content pane, the way project settings take that pane. It holds the
 * public contract, edited in place while it is the Workshop draft. A save bar
 * stays at the foot of the pane, and publishing an unsaved draft saves it
 * first, so what is frozen is what the owner is looking at.
 *
 * It offers no way to try the agent. Trying one is a mode of the workbench,
 * where it is built (DR-0245); settings are for what visitors get.
 *
 * A placement pinned to a frozen version opens the same surface. Its contract
 * is read back in plain words rather than edited, and Deploy and Inbox take the
 * place of save and publish, because a project is the durable owner of a
 * deployment (ADR 0143). `panel-agent-opening.ts` decides which of the two this is.
 */

import { createEffect, createMemo, createResource, createSignal, Show, type JSX } from "solid-js";
import type {
    AgentAbility,
    ArchetypeId,
    ArchetypeNode,
    PanelPublicProfile,
    PlacementNode,
    ProjectNode,
} from "@gaugewright/control-plane-client";
import { PanelContractEditor } from "./PanelContractEditor";
import { PanelContractSummary } from "./PanelContractSummary";
import { plainConfigError } from "./AgentSettings";
import { panelAgentSurfacePlan } from "./panel-agent-opening";
import "./project-settings.css";
import "./panel-agent.css";

export interface PanelAgentSurfaceApi {
    getPanelProfile(id: ArchetypeId): Promise<PanelPublicProfile>;
    setPanelProfile(id: ArchetypeId, profile: PanelPublicProfile): Promise<PanelPublicProfile>;
    publishArchetype(id: ArchetypeId, autoUpgrade?: boolean): Promise<{ version: number; autoUpgraded: number }>;
    /** The authored agent's abilities, which bound what the contract may offer visitors. */
    getArchetypeAbilities?(id: ArchetypeId): Promise<AgentAbility[]>;
}

export function PanelAgentSurface(props: {
    api: PanelAgentSurfaceApi;
    agent: ArchetypeNode;
    /** Present when opened from a project placement: the surface is pinned to it. */
    project?: ProjectNode;
    placement?: PlacementNode;
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
    const [authoredAbilities] = createResource(
        () => plan().scope === "draft" && props.api.getArchetypeAbilities ? props.agent.id : null,
        (id) => props.api.getArchetypeAbilities!(id),
    );
    const [draft, setDraft] = createSignal<PanelPublicProfile | null>(null);
    const [dirty, setDirty] = createSignal(false);
    const [message, setMessage] = createSignal("");
    const [failed, setFailed] = createSignal(false);
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
        setFailed(false);
    }

    function discard() {
        setDirty(false);
        setDraft(loaded() ?? null);
        setMessage("");
        setFailed(false);
    }

    async function save(): Promise<boolean> {
        const profile = draft();
        if (!profile) return false;
        setBusy(true);
        try {
            const saved = await props.api.setPanelProfile(props.agent.id, profile);
            setDraft(saved);
            setDirty(false);
            setFailed(false);
            setMessage("Saved.");
            await refetch();
            return true;
        } catch (reason) {
            setFailed(true);
            setMessage(plainConfigError(String(reason)));
            return false;
        } finally {
            setBusy(false);
        }
    }

    async function publish() {
        if (dirty() && !await save()) return;
        setBusy(true);
        try {
            const published = await props.api.publishArchetype(props.agent.id);
            setFailed(false);
            setMessage(`Published version ${published.version}. Projects on an earlier version can upgrade to it.`);
            props.onPublished?.(published.version);
        } catch (reason) {
            setFailed(true);
            setMessage(String(reason));
        } finally {
            setBusy(false);
        }
    }

    const status = () => message() || (dirty() ? "Unsaved changes" : "All changes saved");

    // No page header: the nav already says which agent this is, and the pane is
    // left by selecting something else. What the header carried — which draft or
    // version this is, and its actions — sits in the bar at the foot.
    return <main class="project-settings-content panel-agent-surface pa-root" data-panel-agent-surface data-panel-agent-scope={plan().scope}>
        <article class="project-settings-page" aria-label={`${props.agent.name}, ${plan().subtitle}`}>
            <div class="pa-body">
                <Show when={plan().contractEditable} fallback={<section class="pa-section" data-panel-agent-contract>
                    <div class="pa-section-head">
                        <h3>What visitors get</h3>
                        <p>This project runs version {props.placement?.version}, which is frozen. To change it, edit the agent in the
                            Workshop, publish a new version, and upgrade this placement.</p>
                    </div>
                    <Show when={frozen()} fallback={<p class="pa-empty">This placement has no frozen public profile.</p>}>
                        {(profile) => <PanelContractSummary profile={profile()} />}
                    </Show>
                </section>}>
                    <div data-panel-agent-contract>
                        <Show when={draft()} fallback={<section class="pa-section">
                            <Show when={loaded.error} fallback={<p class="pa-hint">Loading…</p>}>
                                {(error) => <p class="pa-error">Could not load the settings: {String(error())}</p>}
                            </Show>
                        </section>}>
                            {(profile) => <PanelContractEditor profile={profile()} onChange={edit}
                                authoredAbilities={authoredAbilities()} />}
                        </Show>
                    </div>
                </Show>
            </div>

            <footer class="pa-savebar">
                <span class="pa-savebar-where"><span class="panel-agent-subtitle">{plan().subtitle}</span>
                    <Show when={plan().contractEditable}>
                        <span class={failed() ? "pa-error" : "pa-savebar-status"} data-dirty={dirty() && !message()}
                            data-panel-contract-status role="status">{status()}</span>
                    </Show>
                </span>
                <div class="pa-savebar-actions">
                    <Show when={plan().contractEditable}>
                        <Show when={dirty()}><button type="button" class="pa-button" disabled={busy()} onClick={discard}>Discard</button></Show>
                        <button type="button" class="pa-button" data-panel-contract-save disabled={busy() || !dirty()}
                            onClick={() => void save()}>Save</button>
                    </Show>
                    <Show when={plan().actions.includes("publish")}>
                        <button type="button" class="pa-button primary" disabled={busy() || !draft()}
                            title="Freeze these settings into a new version that projects can deploy"
                            onClick={() => void publish()}>{dirty() ? "Save and publish" : "Publish new version"}</button>
                    </Show>
                    <Show when={plan().actions.includes("inbox") && props.onOpenInbox}>
                        <button type="button" class="pa-button" onClick={props.onOpenInbox}>Inbox</button>
                    </Show>
                    <Show when={plan().actions.includes("deploy") && props.onDeploy}>
                        <button type="button" class="pa-button primary" onClick={props.onDeploy}>{plan().deployLabel}</button>
                    </Show>
                </div>
            </footer>
        </article>
    </main>;
}
