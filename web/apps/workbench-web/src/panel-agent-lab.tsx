/**
 * Prototype bench for the Panel-agent surfaces: the opened Panel agent in the
 * Content pane (Workshop draft and a project's pinned placement), its Agent
 * settings, and the deploy / manage-deployment dialog. It runs the real
 * components against the real stylesheet and an in-memory stand-in for the
 * control plane, so what is agreed here is what ships.
 *
 * Served in development only (`/panel-agent-lab.html`); no shipped bundle names
 * this entry.
 */
import { createSignal, For, Show } from "solid-js";
import { render } from "solid-js/web";
import {
    AgentSettings,
    DeploymentPanel,
    PanelAgentSurface,
    type DeploymentSelection,
} from "@gaugewright/workbench-ui";
import type {
    AccountTenant,
    ArchetypeId,
    ArchetypeNode,
    PanelPublicProfile,
    PlacementId,
    PlacementNode,
    ProjectNode,
    PublicCredentialMetadata,
    PublicDeploymentBindingSummary,
    PublicDeploymentInspection,
} from "@gaugewright/control-plane-client";
import "@gaugewright/workbench-ui/styles.css";

const EDGE = "https://panels.gaugewright.com";
const wait = (ms = 350) => new Promise((resolve) => setTimeout(resolve, ms));

/** What a new Panel agent starts with (`library.rs`, `PanelPublicProfile::default`),
 *  with a little authored on top so the surfaces have real content to show. */
const PROFILE: PanelPublicProfile = {
    panels: { components: ["gw-chat", "gw-files"], default_component: "gw-chat", attribution: "gauge_wright" },
    public_abilities: ["workspace.read", "workspace.write"],
    model: {},
    audience_inputs: ["text"],
    initial_workspace: [
        { path: "welcome.md", media_type: "text/markdown", sha256: "0".repeat(64), bytes: [...new TextEncoder().encode("# Welcome\n\nTell us about your project.")] },
        { path: "pricing.pdf", media_type: "application/pdf", sha256: "1".repeat(64), bytes: new Array(48_213).fill(0) },
    ],
    retention: { idle_ttl_seconds: 86_400, absolute_ttl_seconds: 2_592_000, transcript_retained: true, workspace_retained: true },
    collection: {
        exportable_paths: ["artifacts/*"],
        transcript_eligible: false,
        schema_ref: "gaugewright.panel-output/v1",
        recipient_class: "project",
        max_artifact_bytes: 1_048_576,
    },
};

const AGENT = {
    id: "agent-public-intake" as ArchetypeId,
    name: "Public intake",
    kind: "panel",
    panelProfile: PROFILE,
    instanceId: "inst-public-intake" as PlacementId,
    authoringTargetId: "target-public-intake",
    isDefault: false,
    forkedFrom: null,
    forkedFromName: null,
    sharedThrough: [],
    chats: [],
    workstreams: [],
} as unknown as ArchetypeNode;

const ACTIVE_BINDING: PublicDeploymentBindingSummary = {
    id: "binding-1",
    deploymentId: "public-intake",
    edgeOrigin: EDGE,
    activeReleaseId: "rel_8f2c19a04be1",
    status: "active",
};

function placement(deployments: readonly PublicDeploymentBindingSummary[]): PlacementNode {
    return {
        placementId: "placement-intake" as PlacementId,
        kind: "panel",
        archetypeId: AGENT.id,
        archetypeName: AGENT.name,
        isDefault: false,
        hasConfig: false,
        pinnedVersion: "3",
        version: 3,
        currentVersion: 3,
        panelProfile: PROFILE,
        upgradeAvailable: false,
        pending: false,
        deployments,
        targetIds: [],
        chats: [],
        workstreams: [],
    } as unknown as PlacementNode;
}

function project(deployments: readonly PublicDeploymentBindingSummary[]): ProjectNode {
    return {
        id: "project-theorya",
        homeId: "home-1",
        name: "Theory A website",
        isPersonal: false,
        networkIsolated: false,
        targets: [],
        placements: [placement(deployments)],
    } as unknown as ProjectNode;
}

const TENANTS: AccountTenant[] = [
    { id: "tenant-personal", displayName: "Jack Scully", role: "owner", personal: true, providerCommercial: false },
    { id: "tenant-theorya", displayName: "Theory A", role: "admin", personal: false, providerCommercial: true },
];

let credentials: PublicCredentialMetadata[] = [
    { credential_ref: "credential:production:openai:v1", provider: "openai", credential_class: "openai-api-key", label: "Theory A OpenAI key", created_at_unix_ms: Date.now() - 86_400_000 * 12 },
];

let inspection: PublicDeploymentInspection = {
    deployment: {
        lifecycle: "active",
        config: {
            deployment_id: "public-intake",
            allowed_origins: ["https://theorya.com", "https://www.theorya.com"],
            panel_ceiling: ["gw-chat", "gw-files"],
            max_spend_cents: 5_000,
            max_session_spend_cents: 100,
            max_turn_spend_cents: 5,
            per_visitor_turn_limit: 20,
            max_concurrent_sessions: 100,
            funding_ref: "managed:tenant-theorya",
            audience: { anonymous_allowed: true },
            retention: { idle_ttl_seconds: 86_400, absolute_ttl_seconds: 604_800 },
            white_label: false,
        },
        active_release_id: "rel_8f2c19a04be1",
        activation_revision: 4,
        spent_cents: 1_284,
        reserved_cents: 20,
        sessions: 37,
        settled_turns: 412,
    },
    audience: [
        { session_id: "ses_7Hq2kd91", release_id: "rel_8f2c19a04be1", origin: "https://theorya.com", principal_mode: "anonymous", audience_id: null, created_at_unix_ms: Date.now() - 3_600_000 * 2, settled_turns: 9 },
        { session_id: "ses_Lm40ax2P", release_id: "rel_8f2c19a04be1", origin: "https://www.theorya.com", principal_mode: "anonymous", audience_id: null, created_at_unix_ms: Date.now() - 3_600_000 * 26, settled_turns: 3 },
    ],
};

let draft: PanelPublicProfile = PROFILE;
let config = "{}";

/** One in-memory control plane for every surface on the bench. */
const api = {
    async getPanelProfile() { await wait(); return draft; },
    async setPanelProfile(_id: ArchetypeId, profile: PanelPublicProfile) { await wait(); draft = profile; return draft; },
    async publishArchetype() { await wait(600); return { version: 4, autoUpgraded: 0 }; },
    async getArchetypeConfig() { await wait(); return config; },
    async setArchetypeConfig(_id: ArchetypeId, next: string) { await wait(); config = next; },
    async getArchetypeAbilities() { await wait(); return draft.public_abilities.slice(); },
    async setArchetypeAbilities() { await wait(); },
    async deploymentManagedTenants() { await wait(); return TENANTS; },
    async listPublicCredentials() { await wait(); return credentials; },
    async provisionPublicCredential(input: { label: string; provider: "openai" | "anthropic"; credential_class: string }) {
        await wait();
        const created = { credential_ref: `credential:${Date.now()}`, provider: input.provider, credential_class: input.credential_class, label: input.label, created_at_unix_ms: Date.now() };
        credentials = [...credentials, created];
        return created;
    },
    async revokePublicCredential(_edge: string, reference: string) { await wait(); credentials = credentials.filter((c) => c.credential_ref !== reference); },
    async inspectDeployment() { await wait(); return inspection; },
    async controlDeployment(_edge: string, _deployment: string, command: "pause" | "resume" | "revoke") {
        await wait();
        inspection = { ...inspection, deployment: { ...inspection.deployment, lifecycle: command === "pause" ? "paused" : command === "resume" ? "active" : "revoked", activation_revision: inspection.deployment.activation_revision + 1 } };
        return inspection.deployment;
    },
    async erasePublicSession(_edge: string, _deployment: string, session: string) {
        await wait();
        inspection = { ...inspection, audience: inspection.audience.filter((s) => s.session_id !== session) };
    },
    async publishDeployment(input: { deployment_id: string; edge_origin: string; placement_id: PlacementId }) {
        await wait(1_000);
        return {
            binding_id: "binding-1",
            project_id: "project-theorya",
            placement_id: input.placement_id,
            deployment_id: input.deployment_id,
            release_id: "rel_8f2c19a04be1",
            edge_origin: input.edge_origin,
            deployment_url: `${input.edge_origin}/d/${input.deployment_id}`,
            embed_html: `<script type="module" src="${input.edge_origin}/embed.js"></script>\n<gw-session host="${input.edge_origin}/d/${input.deployment_id}" panels="chat,files"></gw-session>`,
            deployment: {},
        };
    },
    async drainCollections() { await wait(); return { landed: ["item-1", "item-2"], refused: [] }; },
    async screenQuarantinedItem() { return { workspacePath: null, parked: true }; },
};

type Case = "workshop" | "settings" | "placement" | "deploy-new" | "deploy-manage";

const CASES: { key: Case; title: string; note: string }[] = [
    { key: "workshop", title: "Workshop draft", note: "Opening a Panel agent in the Workshop: its edit chat in Chat, this in Content." },
    { key: "settings", title: "Agent settings", note: "The gear on a Panel agent row in the Workshop." },
    { key: "placement", title: "Project placement", note: "Selecting the Panel agent under a project: pinned to a frozen version." },
    { key: "deploy-new", title: "Deploy (first time)", note: "Deploy… on a placement with no deployment yet." },
    { key: "deploy-manage", title: "Manage deployment", note: "Manage deployments… on a placement with a live deployment." },
];

function selection(deployments: readonly PublicDeploymentBindingSummary[]): DeploymentSelection {
    return {
        projectId: "project-theorya",
        projectName: "Theory A website",
        placementId: "placement-intake" as PlacementId,
        archetypeName: AGENT.name,
        version: 3,
        profile: PROFILE,
        deployments,
    };
}

function Bench() {
    const initial = (new URLSearchParams(location.search).get("case") as Case | null) ?? "workshop";
    const [current, setCurrent] = createSignal<Case>(initial);
    const [narrow, setNarrow] = createSignal(false);
    const [modal, setModal] = createSignal<DeploymentSelection | null>(null);
    const pick = (key: Case) => {
        setCurrent(key);
        history.replaceState(null, "", `?case=${key}`);
        setModal(key === "deploy-new" ? selection([]) : key === "deploy-manage" ? selection([ACTIVE_BINDING]) : null);
    };
    if (initial === "deploy-new" || initial === "deploy-manage") queueMicrotask(() => pick(initial));
    const note = () => CASES.find((c) => c.key === current())?.note ?? "";

    return <div class="lab">
        <header class="lab-head">
            <h1>Panel agent</h1>
            <p>The real Panel-agent surfaces against the real stylesheet and an in-memory control plane.</p>
        </header>
        <div class="lab-tabs">
            <For each={CASES}>{(c) => <button type="button" class={`lab-tab${current() === c.key ? " active" : ""}`} onClick={() => pick(c.key)}>{c.title}</button>}</For>
            <button type="button" class={`lab-tab${narrow() ? " active" : ""}`} onClick={() => setNarrow(!narrow())}>narrow pane</button>
        </div>
        <p class="lab-note">{note()}</p>
        <div class={`lab-stage${narrow() ? " narrow" : ""}`}>
            <Show when={current() === "workshop" || current() === "deploy-new" || current() === "deploy-manage"}>
                <PanelAgentSurface api={api} agent={AGENT} onPublished={() => {}} />
            </Show>
            <Show when={current() === "settings"}>
                <AgentSettings api={api} id={AGENT.id} name={AGENT.name} kind="panel" onClose={() => {}} />
            </Show>
            <Show when={current() === "placement"}>
                <PanelAgentSurface api={api} agent={AGENT} project={project([ACTIVE_BINDING])}
                    placement={placement([ACTIVE_BINDING])}
                    onDeploy={() => setModal(selection([ACTIVE_BINDING]))}
                    onOpenInbox={() => {}} />
            </Show>
        </div>
        <Show when={modal()}>{(chosen) => <DeploymentPanel api={api} selection={chosen()}
            defaultEdgeOrigin={EDGE} defaultCredentialRef="credential:production:openai:v1"
            onOpenInbox={() => setModal(null)} onClose={() => setModal(null)} />}</Show>
    </div>;
}

const root = document.getElementById("root");
if (root) render(() => <Bench />, root);
