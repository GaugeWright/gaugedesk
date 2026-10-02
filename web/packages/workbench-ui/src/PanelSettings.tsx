/**
 * Panel Settings: a Panel placement's own GaugeApp (DR-0305).
 *
 * A Panel placement hosts no chats, so selecting one opens this — settings in
 * Content, pages in Menu, and its management conversation in Chat, the
 * composition Project Settings and Agent Settings use. Everything shown is read
 * from the placement's GaugeApp pages, which are the models its management
 * agent reads.
 *
 * The Inbox is this placement's part of the project's Inbox. Reading an item is
 * a person's act, through the reviewer's route, and so is keeping or flagging
 * it; the agent sees only the index (ADR 0110). A kept item becomes a file in
 * the project's folder, where the project's work chats read it.
 */

import { createMemo, createResource, createSignal, For, Show, type JSX } from "solid-js";
import { PanelContractSummary } from "./PanelContractSummary";
import { quarantineSize } from "./QuarantineIndex";
import type { DeploymentSelection } from "./DeploymentPanel";
import {
    keptItemCopy,
    PANEL_SETTINGS_PAGE_LABELS,
    PANEL_SETTINGS_PAGES,
    panelInboxStatusCopy,
    panelSettingsView,
    type PanelInboxItem,
    type PanelSettingsPage,
    type PanelSettingsView,
} from "./panel-settings";
import "./project-settings.css";
import "./panel-agent.css";

export interface PanelSettingsApi {
    /** The placement's GaugeApp pages, freshly admitted at its project's Home. */
    panelSettingsPages(project: string, placement: string): Promise<readonly { readonly id: string; readonly model: unknown }[]>;
    /** A person reads one item's content to judge it. */
    readQuarantinedItem(project: string, item: string): Promise<string>;
    /** A person keeps or flags an item; the project's gate rules on it. */
    reviewPanelInboxItem(project: string, placement: string, item: string, verdict: "keep" | "flag"): Promise<void>;
}

export interface PanelSettingsProps {
    readonly api: PanelSettingsApi;
    readonly projectId: string;
    readonly projectName: string;
    readonly placementId: string;
    readonly page: PanelSettingsPage;
    /** Changes whenever the workspace does, so a new deployment or arrival shows. */
    readonly refreshKey: unknown;
    readonly onSelectPage: (page: PanelSettingsPage) => void;
    readonly onClose: () => void;
    readonly onDeploy: (selection: DeploymentSelection) => void;
    readonly onChanged: () => void | Promise<void>;
}

function arrived(unixMs: number): string {
    return Number.isFinite(unixMs) && unixMs > 0 ? new Date(unixMs).toLocaleString() : "unknown";
}

function idleWindow(seconds: number | null): string | null {
    if (seconds === null || seconds <= 0) return null;
    if (seconds % 3600 === 0) return `${seconds / 3600} h`;
    if (seconds % 60 === 0) return `${seconds / 60} min`;
    return `${seconds} s`;
}

export function PanelSettingsContent(props: PanelSettingsProps): JSX.Element {
    const [reload, setReload] = createSignal(0);
    const [view] = createResource(
        () => [props.projectId, props.placementId, props.refreshKey, reload()] as const,
        async ([project, placement]) => panelSettingsView(await props.api.panelSettingsPages(project, placement)),
    );
    const refresh = () => setReload((value) => value + 1);
    return <main class="project-settings-content panel-settings" data-panel-settings={props.placementId}>
        <article class="project-settings-page">
            <header class="project-settings-page-head">
                <div><span>Panel agent · {props.projectName}</span><h1>{view()?.overview.name ?? "Panel agent"}</h1></div>
                <button type="button" onClick={props.onClose}>Close</button>
            </header>
            <div class="project-settings-title"><h2>{PANEL_SETTINGS_PAGE_LABELS[props.page]}</h2></div>
            <Show when={view()} fallback={<Show when={view.error} fallback={<p class="pa-hint" role="status">Loading…</p>}>
                {(error) => <div class="project-settings-empty" role="alert">
                    <p>Panel settings unavailable: {String(error())}</p>
                    <button type="button" onClick={refresh}>Retry</button>
                </div>}
            </Show>}>
                {(current) => <>
                    <Show when={props.page === "overview"}><Overview {...props} view={current()} /></Show>
                    <Show when={props.page === "deployments"}><Deployments {...props} view={current()} /></Show>
                    <Show when={props.page === "inbox"}><Inbox {...props} view={current()} refresh={refresh} /></Show>
                </>}
            </Show>
        </article>
    </main>;
}

function deploymentSelection(props: PanelSettingsProps, view: PanelSettingsView): DeploymentSelection | null {
    const profile = view.overview.profile;
    if (!profile) return null;
    return {
        projectId: props.projectId,
        projectName: props.projectName,
        placementId: props.placementId as DeploymentSelection["placementId"],
        archetypeName: view.overview.name,
        version: view.overview.version,
        profile,
        deployments: view.deployments.map(({ id, deploymentId, edgeOrigin, activeReleaseId, status }) =>
            ({ id, deploymentId, edgeOrigin, activeReleaseId, status })),
    };
}

function Overview(props: PanelSettingsProps & { readonly view: PanelSettingsView }): JSX.Element {
    const pending = () => "items" in props.view.inbox ? props.view.inbox.pending : null;
    return <>
        <section class="project-settings-overview">
            <p>This project runs version {props.view.overview.version} of {props.view.overview.name}, which is frozen.
                <Show when={props.view.overview.upgradeAvailable}> Version {props.view.overview.currentVersion} is available to upgrade to.</Show></p>
            <div class="project-settings-overview-grid">
                <button type="button" onClick={() => props.onSelectPage("deployments")}><strong>Deployments</strong>
                    <span>{props.view.deployments.length ? `${props.view.deployments.length} on the web` : "Not deployed yet"}</span></button>
                <button type="button" onClick={() => props.onSelectPage("inbox")}><strong>Inbox</strong>
                    <span>{pending() === null ? "Unavailable" : `${pending()} awaiting review`}</span></button>
            </div>
        </section>
        <section class="project-settings-section" data-panel-agent-contract>
            <div class="pa-section-head">
                <h3>What visitors get</h3>
                <p>To change it, edit the Agent in the Workshop, publish a new version, and upgrade this placement.</p>
            </div>
            <Show when={props.view.overview.profile} fallback={<p class="pa-empty">This placement has no frozen public profile.</p>}>
                {(profile) => <PanelContractSummary profile={profile()} />}
            </Show>
        </section>
    </>;
}

function Deployments(props: PanelSettingsProps & { readonly view: PanelSettingsView }): JSX.Element {
    const selection = createMemo(() => deploymentSelection(props, props.view));
    return <section class="project-settings-section" data-panel-settings-deployments>
        <div class="project-settings-rows">
            <For each={props.view.deployments} fallback={<p class="project-settings-empty">This version is not on any website yet.</p>}>
                {(deployment) => <div class="project-settings-row project-settings-agent-row">
                    <div><strong>{deployment.deploymentId}</strong>
                        <small>{deployment.allowedOrigins.length ? deployment.allowedOrigins.join(", ") : "No website admitted yet"}
                            {idleWindow(deployment.retentionIdleSeconds) ? ` · results arrive ${idleWindow(deployment.retentionIdleSeconds)} after a visitor's last message` : ""}</small></div>
                    <span>{deployment.status === "active" ? "Live" : deployment.status === "pending_publish" ? "Publishing" : "Needs confirming"}</span>
                </div>}
            </For>
        </div>
        <Show when={selection()} fallback={<p class="pa-empty">This placement has no frozen public profile to deploy.</p>}>
            {(chosen) => <div class="project-settings-inline-actions">
                <button type="button" data-panel-settings-deploy onClick={() => props.onDeploy(chosen())}>
                    {props.view.deployments.length ? "Manage deployments…" : "Deploy…"}</button>
            </div>}
        </Show>
    </section>;
}

function Inbox(props: PanelSettingsProps & { readonly view: PanelSettingsView; readonly refresh: () => void }): JSX.Element {
    const [open, setOpen] = createSignal<string | null>(null);
    const [message, setMessage] = createSignal("");
    const [busy, setBusy] = createSignal(false);
    const [body] = createResource(
        () => open() ? [props.projectId, open()!] as const : null,
        ([project, item]) => props.api.readQuarantinedItem(project, item),
    );
    async function review(item: PanelInboxItem, verdict: "keep" | "flag") {
        setBusy(true);
        setMessage("");
        try {
            await props.api.reviewPanelInboxItem(props.projectId, props.placementId, item.itemId, verdict);
            setOpen(null);
            props.refresh();
            await props.onChanged();
        } catch (reason) {
            setMessage(reason instanceof Error ? reason.message : String(reason));
        } finally {
            setBusy(false);
        }
    }
    return <section class="project-settings-section quarantine" data-panel-settings-inbox>
        <p>What visitors returned stays here, unread by any agent, until a person keeps it. A kept item becomes a file in this
            project's folder, where the project's work chats can read it. New results arrive from a deployment's
            “Bring results into the Inbox”.</p>
        <Show when={"items" in props.view.inbox ? props.view.inbox : null} fallback={
            <p class="pa-error" role="alert">{"unavailable" in props.view.inbox ? props.view.inbox.unavailable : ""}</p>}>
            {(inbox) => <>
                <div class="quarantine-head"><span class="quarantine-title">inbound</span>
                    <span class="status">{inbox().items.length} item(s) · {inbox().pending} awaiting review</span>
                    <button type="button" class="ghost" onClick={props.refresh}>refresh</button></div>
                <Show when={message()}><p class="status warn" role="alert">{message()}</p></Show>
                <Show when={inbox().items.length} fallback={<p class="status">Nothing has arrived from this placement's deployments.</p>}>
                    <ul class="quarantine-list"><For each={inbox().items}>{(item) => {
                        const state = () => panelInboxStatusCopy(item);
                        const showing = () => open() === item.itemId;
                        return <li class="quarantine-item" classList={{ open: showing() }} data-panel-inbox-item={item.itemId}>
                            <button type="button" class="quarantine-row" aria-expanded={showing()} onClick={() => setOpen(showing() ? null : item.itemId)}>
                                <span class="quarantine-source" title={item.sessionId ?? item.itemId}>{item.deploymentId ?? item.itemId}</span>
                                <span class="quarantine-schema">{item.schema}</span>
                                <span class="quarantine-when">{arrived(item.arrivedAtUnixMs)}</span>
                                <span class="quarantine-size">{quarantineSize(item.bytes)}</span>
                                <span class={`quarantine-status ${state().tone}`}>{state().label}</span>
                            </button>
                            <Show when={showing()}><div class="quarantine-body">
                                <pre class="quarantine-payload">{body.error ? `Could not read this item: ${String(body.error)}` : body() ?? "reading…"}</pre>
                                <Show when={item.status === "pending"}><div class="quarantine-actions">
                                    <button type="button" class="primary" disabled={busy()} onClick={() => void review(item, "keep")}>keep</button>
                                    <button type="button" class="ghost" disabled={busy()} onClick={() => void review(item, "flag")}>flag</button>
                                </div></Show>
                                <Show when={keptItemCopy(item)}>{(copy) => <p class="status">{copy()}</p>}</Show>
                            </div></Show>
                        </li>;
                    }}</For></ul>
                </Show>
            </>}
        </Show>
    </section>;
}

export function PanelSettingsMenu(props: {
    readonly name: string;
    readonly page: PanelSettingsPage;
    readonly onSelect: (page: PanelSettingsPage) => void;
    readonly onClose: () => void;
}): JSX.Element {
    return <nav class="project-settings-menu" aria-label={`Settings for ${props.name}`}>
        <header><span>Panel agent</span><strong>{props.name}</strong></header>
        <For each={PANEL_SETTINGS_PAGES}>{(page) => <button type="button" classList={{ active: props.page === page }}
            aria-current={props.page === page ? "page" : undefined} onClick={() => props.onSelect(page)}>{PANEL_SETTINGS_PAGE_LABELS[page]}</button>}</For>
        <button type="button" class="project-settings-menu-close" onClick={props.onClose}>Back to files</button>
    </nav>;
}
