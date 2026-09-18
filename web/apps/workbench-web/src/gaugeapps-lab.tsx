/** Fixture-only GaugeDesk composition for exploring GaugeApps. The projections
 * are local; the workbench shell and every pane are the real shared UI. */
import { batch, createContext, createEffect, createMemo, createSignal, For, Show, useContext, type JSX } from "solid-js";
import {
    engagementId, workTargetId, workstreamId,
    type ArchetypeId, type Engagement, type EngagementId, type HomeId, type HumanTask,
    type ChatTargetMember,
    type PanelPublicProfile, type PlacementId, type ProjectId, type SearchHit, type Workspace, type WorkspaceRootId,
    type WorkTargetNode, type WorkstreamNode,
} from "@gaugewright/control-plane-client";
import {
    AccountMenu, ChatPaneHeader, ChatPanel, createWorkbenchShellState, emptyTranscript,
    FacetBrowser, localTurnActivity, pairingTicket, qrSvg, TaskBar, WorkbenchShell, type AccountMenuItem,
    type FacetBrowserApi, type Session, type Transcript,
} from "@gaugewright/workbench-ui";
import "@gaugewright/workbench-ui/styles.css";
import "./gaugeapps-lab.css";

type ScopeId = "signed-out" | "personal-free" | "personal-plus" | "acorn" | "brightworks" | "northstar" | "gaugewright";
type GaugeAppId = "project" | "vend" | "administration" | "settings";
interface GaugeApp { readonly id: GaugeAppId; readonly label: string; readonly description: string; readonly group: "apps" | "manage"; }
interface ProjectFixture {
    readonly id: string;
    readonly name: string;
    /** Product identity, not presentation: renaming a project never makes it Personal. */
    readonly isPersonal: boolean;
    readonly detail: string;
    readonly conversations: number;
}
interface ProjectGovernanceFixture {
    readonly people: number;
    readonly explicitGrants: number;
    readonly agents: number;
    readonly targets: number;
    readonly state: "healthy" | "attention";
    readonly activity: string;
}
interface ScopeFixture {
    readonly id: ScopeId;
    readonly label: string;
    readonly kind: "signed-out-local" | "personal" | "organization";
    readonly posture: string;
    readonly cloudHome: "none" | "self-managed" | "managed";
    readonly providerCommerce: "not-applicable" | "not-added" | "active";
    readonly enterpriseControls: "not-applicable" | "not-added" | "active";
    readonly organizationRole: "owner" | "admin" | "member" | null;
    readonly commercialRole: "owner" | "manager" | null;
    readonly apps: readonly GaugeApp[];
    readonly administrationTabs: readonly string[];
    readonly settingsTabs: readonly string[];
}
type OrganizationPlanId = "base" | "managed";
interface PrototypeOrganizationState {
    readonly plan?: OrganizationPlanId;
    readonly purchasedSeats?: number;
    readonly scheduledPlan?: OrganizationPlanId | null;
    readonly scheduledSeats?: number | null;
    readonly providerCommerce?: "not-added" | "active";
    readonly enterpriseControls?: "not-added" | "active";
    readonly scheduledServiceRemoval?: "commercial" | "enterprise" | null;
}
interface PrototypeOrganizationStateApi {
    get: (scope: ScopeId) => PrototypeOrganizationState;
    update: (scope: ScopeId, change: Partial<PrototypeOrganizationState>) => void;
}
interface NavigationTab { readonly id: string; readonly label: string; }
interface AdministrationDestination {
    readonly id: string;
    readonly label: string;
    readonly description: string;
    readonly tabs: readonly NavigationTab[];
}
type DetailFamily =
    | "project-access" | "project-target" | "project-resource" | "project-placement" | "project-model"
    | "project-governance"
    | "sales-setup" | "client" | "offer" | "agreement" | "transaction" | "invoice" | "stripe-connect"
    | "organization" | "capability" | "member" | "identity" | "policy" | "project-host" | "backup" | "deployment"
    | "software" | "client-session" | "billing" | "account" | "model" | "trusted-device" | "application" | "sign-in";
interface InteractionTarget {
    readonly action: string;
    readonly title: string;
    readonly description?: string;
    readonly kind?: string;
    readonly meta?: string;
}
interface DetailPageRequest extends InteractionTarget {
    readonly id: string;
    readonly family: DetailFamily;
    readonly appId: GaugeAppId;
    readonly sourceTab: string;
    readonly sourceLabel: string;
}
interface DetailMetric { readonly label: string; readonly value: string; readonly note: string; readonly warn?: boolean; }
interface DetailField { readonly label: string; readonly value: string; readonly wide?: boolean; readonly readOnly?: boolean; readonly options?: readonly string[]; }
interface DetailRow { readonly label: string; readonly value: string; readonly note?: string; readonly actions?: readonly DetailCommand[]; }
interface DetailSection { readonly title: string; readonly intro?: string; readonly rows?: readonly DetailRow[]; readonly fields?: readonly DetailField[]; }
interface DetailCommand {
    readonly label: string;
    readonly danger?: boolean;
    readonly destination?: {
        readonly appId: GaugeAppId;
        readonly tab: string;
        readonly target?: InteractionTarget;
        readonly projectId?: string;
    };
}
interface DetailBlueprint {
    readonly description: string;
    readonly notice?: string;
    readonly metrics?: readonly DetailMetric[];
    readonly sections: readonly DetailSection[];
    readonly commands: readonly DetailCommand[];
}

const PROJECT: GaugeApp = { id: "project", label: "Project Settings", description: "People, work, Agents, and authority for the selected project", group: "manage" };
const VEND: GaugeApp = { id: "vend", label: "Commercial Operations", description: "Products, clients, engagements, and payments", group: "apps" };
const ADMIN: GaugeApp = { id: "administration", label: "Administration", description: "Organization data, identity, access, policy, and fleet controls", group: "manage" };
const PERSONAL_ADMIN: GaugeApp = { id: "administration", label: "Your Account", description: "Personal services, Project Hosts, recovery, and billing", group: "manage" };
const LOCAL_ADMIN: GaugeApp = { id: "administration", label: "This Computer", description: "Local services and Project Host state", group: "manage" };
const SETTINGS: GaugeApp = { id: "settings", label: "Settings", description: "GaugeDesk account, model, Trusted Device, and application settings", group: "manage" };
const SIGNED_OUT_ADMIN_TABS = ["Project Hosts"] as const;
const PERSONAL_FREE_ADMIN_TABS = ["Project Hosts", "Billing"] as const;
const PERSONAL_PLUS_ADMIN_TABS = ["Project Hosts", "Backups", "Billing"] as const;
const ORGANIZATION_BASE_TABS = [
    "Organization", "Services", "Projects", "People & Access", "Clients", "Model Providers", "Policy", "Project Hosts", "Backups",
    "Billing",
] as const;
const ORGANIZATION_ENTERPRISE_TABS = [
    "Organization", "Services", "Projects", "People & Access", "Identity", "Clients", "Model Providers", "Policy", "Project Hosts", "Backups",
    "Software", "Billing",
] as const;
const SIGNED_OUT_SETTINGS = ["Sign In", "Provider Connections", "Trusted Devices", "Application Settings"] as const;
const ACCOUNT_SETTINGS = ["Account Settings", "Provider Connections", "Trusted Devices", "Application Settings"] as const;
const PROJECT_TABS: readonly NavigationTab[] = [
    { id: "Project Permissions", label: "People & sharing" },
    { id: "Project Work", label: "Work & data" },
    { id: "Project Placements", label: "Agents & placements" },
    { id: "Project Models", label: "Model access" },
];
const PROJECTS_BY_SCOPE: Readonly<Record<ScopeId, readonly ProjectFixture[]>> = {
    "signed-out": [
        { id: "personal-local", name: "Personal", isPersonal: true, detail: "this computer", conversations: 2 },
        { id: "local-notes", name: "Local notes", isPersonal: false, detail: "this computer", conversations: 1 },
    ],
    "personal-free": [
        { id: "personal-local-free", name: "Personal", isPersonal: true, detail: "GaugeDesk desktop · no Cloud Home", conversations: 1 },
    ],
    "personal-plus": [
        { id: "personal", name: "Personal", isPersonal: true, detail: "Personal Cloud Project Host", conversations: 4 },
        { id: "product-lab", name: "Product lab", isPersonal: false, detail: "GaugeDesk desktop", conversations: 2 },
    ],
    acorn: [
        { id: "acorn-design", name: "Acorn design", isPersonal: false, detail: "Office Mac · self-managed Home", conversations: 1 },
    ],
    gaugewright: [
        { id: "gaugedesk", name: "GaugeDesk", isPersonal: false, detail: "GaugeWright Cloud Project Host", conversations: 3 },
        { id: "gaugewright-operations", name: "GaugeWright operations", isPersonal: false, detail: "GaugeWright Cloud Project Host", conversations: 1 },
    ],
    brightworks: [
        { id: "studio-operations", name: "Studio operations", isPersonal: false, detail: "Brightworks managed Project Host", conversations: 5 },
        { id: "client-launch", name: "Client launch", isPersonal: false, detail: "Brightworks managed Project Host", conversations: 2 },
    ],
    northstar: [
        { id: "northstar-platform", name: "Platform", isPersonal: false, detail: "Northstar Cloud Project Host", conversations: 6 },
        { id: "security-operations", name: "Security operations", isPersonal: false, detail: "Northstar Cloud Project Host", conversations: 3 },
    ],
};
const PROJECT_GOVERNANCE_BY_ID: Readonly<Record<string, ProjectGovernanceFixture>> = {
    "personal-local-free": { people: 1, explicitGrants: 0, agents: 1, targets: 1, state: "healthy", activity: "18 minutes ago" },
    "acorn-design": { people: 1, explicitGrants: 0, agents: 1, targets: 1, state: "healthy", activity: "yesterday" },
    gaugedesk: { people: 3, explicitGrants: 1, agents: 4, targets: 2, state: "healthy", activity: "9 minutes ago" },
    "gaugewright-operations": { people: 2, explicitGrants: 0, agents: 2, targets: 1, state: "healthy", activity: "32 minutes ago" },
    "studio-operations": { people: 4, explicitGrants: 2, agents: 3, targets: 3, state: "healthy", activity: "4 minutes ago" },
    "client-launch": { people: 3, explicitGrants: 1, agents: 4, targets: 2, state: "attention", activity: "2 hours ago" },
    "northstar-platform": { people: 18, explicitGrants: 12, agents: 8, targets: 5, state: "healthy", activity: "3 minutes ago" },
    "security-operations": { people: 7, explicitGrants: 5, agents: 3, targets: 4, state: "attention", activity: "41 minutes ago" },
};
const ADMINISTRATION_DESTINATIONS: readonly AdministrationDestination[] = [
    {
        id: "organization", label: "Organization",
        description: "Organization identity, ownership, verified domains, transfer, and deletion.",
        tabs: [{ id: "Organization", label: "Organization" }],
    },
    {
        id: "plans-services", label: "Plans & services",
        description: "Organization plan, capacity, and optional services.",
        tabs: [{ id: "Services", label: "Plans & services" }],
    },
    {
        id: "organization-projects", label: "Projects",
        description: "Every project governed by this organization, its authoritative Home, and its access posture.",
        tabs: [{ id: "Projects", label: "Projects" }],
    },
    {
        id: "people", label: "People",
        description: "Members, fixed organization roles, invitations, and project admission.",
        tabs: [{ id: "People & Access", label: "People" }],
    },
    {
        id: "sessions", label: "Sessions",
        description: "Active GaugeDesk sessions and their admitted organization access.",
        tabs: [{ id: "Clients", label: "Sessions" }],
    },
    {
        id: "enterprise-identity", label: "Enterprise Identity",
        description: "Corporate sign-in, verified-domain admission, directory provisioning, and offboarding.",
        tabs: [{ id: "Identity", label: "Enterprise Identity" }],
    },
    {
        id: "model-providers", label: "Model Providers",
        description: "Organization-owned provider connections, approved models, and monthly usage caps for projects and people.",
        tabs: [{ id: "Model Providers", label: "Model Providers" }],
    },
    {
        id: "organization-policy", label: "Organization Policy",
        description: "Resource access, governed Agent runs, execution boundaries, and change admission.",
        tabs: [{ id: "Policy", label: "Policy" }],
    },
    {
        id: "project-hosts-recovery", label: "Project Hosts & Recovery",
        description: "The Project Hosts where project Homes live, their recovery state, and admitted software.",
        tabs: [
            { id: "Project Hosts", label: "Project Hosts" },
            { id: "Backups", label: "Backups" },
            { id: "Software", label: "Software policy" },
        ],
    },
    {
        id: "organization-billing", label: "Billing",
        description: "Payment methods, billing contacts, invoices, credits, and usage charges.",
        tabs: [{ id: "Billing", label: "Billing" }],
    },
];
const APP_TABS: Readonly<Record<GaugeAppId, readonly string[]>> = {
    project: PROJECT_TABS.map((item) => item.id),
    vend: ["Products", "Clients", "Engagements", "Payments"],
    administration: ADMINISTRATION_DESTINATIONS.flatMap((destination) => destination.tabs.map((item) => item.id)),
    settings: ["Sign In", ...ACCOUNT_SETTINGS],
};
const SCOPES: readonly ScopeFixture[] = [
    {
        id: "signed-out", label: "Signed out", kind: "signed-out-local", posture: "Local only",
        cloudHome: "self-managed", providerCommerce: "not-applicable", enterpriseControls: "not-applicable", apps: [PROJECT, LOCAL_ADMIN, SETTINGS],
        organizationRole: null, commercialRole: null,
        administrationTabs: SIGNED_OUT_ADMIN_TABS, settingsTabs: SIGNED_OUT_SETTINGS,
    },
    {
        id: "personal-free", label: "Personal · new account", kind: "personal", posture: "Free · no Cloud Home",
        cloudHome: "none", providerCommerce: "not-applicable", enterpriseControls: "not-applicable", apps: [PROJECT, PERSONAL_ADMIN, SETTINGS],
        organizationRole: null, commercialRole: null,
        administrationTabs: PERSONAL_FREE_ADMIN_TABS, settingsTabs: ACCOUNT_SETTINGS,
    },
    {
        id: "personal-plus", label: "Personal · Plus", kind: "personal", posture: "Plus · Cloud Home",
        cloudHome: "managed", providerCommerce: "not-applicable", enterpriseControls: "not-applicable", apps: [PROJECT, PERSONAL_ADMIN, SETTINGS],
        organizationRole: null, commercialRole: null,
        administrationTabs: PERSONAL_PLUS_ADMIN_TABS, settingsTabs: ACCOUNT_SETTINGS,
    },
    {
        id: "acorn", label: "Acorn Workshop", kind: "organization", posture: "Owner · Base organization",
        cloudHome: "self-managed", providerCommerce: "not-added", enterpriseControls: "not-added", apps: [PROJECT, ADMIN, SETTINGS],
        organizationRole: "owner", commercialRole: null,
        administrationTabs: ORGANIZATION_BASE_TABS, settingsTabs: ACCOUNT_SETTINGS,
    },
    {
        id: "brightworks", label: "Brightworks Studio", kind: "organization", posture: "Admin · Commercial",
        cloudHome: "managed", providerCommerce: "active", enterpriseControls: "not-added", apps: [PROJECT, VEND, ADMIN, SETTINGS],
        organizationRole: "admin", commercialRole: "manager",
        administrationTabs: ORGANIZATION_BASE_TABS, settingsTabs: ACCOUNT_SETTINGS,
    },
    {
        id: "northstar", label: "Northstar Labs", kind: "organization", posture: "Member · Enterprise",
        cloudHome: "managed", providerCommerce: "not-added", enterpriseControls: "active", apps: [PROJECT, ADMIN, SETTINGS],
        organizationRole: "member", commercialRole: null,
        administrationTabs: ORGANIZATION_ENTERPRISE_TABS, settingsTabs: ACCOUNT_SETTINGS,
    },
    {
        id: "gaugewright", label: "GaugeWright", kind: "organization", posture: "Owner · Commercial + enterprise",
        cloudHome: "managed", providerCommerce: "active", enterpriseControls: "active", apps: [PROJECT, VEND, ADMIN, SETTINGS],
        organizationRole: "owner", commercialRole: "owner",
        administrationTabs: ORGANIZATION_ENTERPRISE_TABS, settingsTabs: ACCOUNT_SETTINGS,
    },
];
const LAB_ENGAGEMENT = engagementId("gaugeapps:prototype");

const FIXTURE_CHAT_TITLES = [
    "Product direction", "Provider onboarding", "Release readiness",
    "Client handoff", "Access policy", "Quarterly planning",
] as const;
const FIXTURE_TARGET_CAPABILITIES = {
    read: true, propose: true, apply: true, publish: false, release: false,
} as const;
interface LibraryAgentSeed {
    readonly slug: string;
    readonly name: string;
    readonly kind: "work" | "panel";
    readonly isDefault?: boolean;
}
/** The prototype Library and commerce picker read the same archetype set. */
const LIBRARY_AGENT_SEEDS: readonly LibraryAgentSeed[] = [
    { slug: "general", name: "General", kind: "work", isDefault: true },
    { slug: "product-designer", name: "Product designer", kind: "work" },
    { slug: "operations-partner", name: "Operations partner", kind: "work" },
    { slug: "research-analyst", name: "Research Analyst", kind: "panel" },
    { slug: "policy-desk", name: "Policy Desk", kind: "panel" },
    { slug: "release-steward", name: "Release Steward", kind: "work" },
    { slug: "architecture-advisor", name: "Architecture Advisor", kind: "work" },
    { slug: "contract-reviewer", name: "Contract Reviewer", kind: "work" },
    { slug: "support-desk", name: "Support Desk", kind: "panel" },
] as const;

function fixturePanelProfile(): PanelPublicProfile {
    return {
        panels: { components: ["gw-chat", "gw-viewer"], default_component: "gw-chat", attribution: "white_label_eligible" },
        public_abilities: ["command.run"],
        provider: { provider: "managed", model: "configured by placement", base_url: "", credential_class: "deployment" },
        audience_inputs: ["text", "document"], initial_workspace: [],
        retention: { idle_ttl_seconds: 3600, absolute_ttl_seconds: 86400, transcript_retained: true, workspace_retained: false },
        collection: null,
    };
}

function fixtureProjectId(raw: string): ProjectId { return raw as ProjectId; }
function fixtureHomeId(raw: string): HomeId { return raw as HomeId; }
function fixtureArchetypeId(raw: string): ArchetypeId { return raw as ArchetypeId; }
function fixturePlacementId(raw: string): PlacementId { return raw as PlacementId; }
function fixtureWorkspaceRootId(raw: string): WorkspaceRootId { return raw as WorkspaceRootId; }

/** A complete fake workspace shaped exactly like the production navigator's
 * projection. This keeps the prototype honest about the real composition while
 * leaving all records local and disposable. */
/** One target as a chat's execution-scope member. A chat now carries a target
 *  set with a revision; the single-target fields beside it are the compatibility
 *  view the shared UI still reads when the set has exactly one member. */
function fixtureTargetMember(
    target: { readonly id: ReturnType<typeof workTargetId>; readonly name: string; readonly kind: WorkTargetNode["kind"]; readonly adapter: string },
    targetId: ReturnType<typeof workTargetId>,
): ChatTargetMember {
    return {
        targetId, root: `fixture:${target.name}`, name: target.name, kind: target.kind,
        adapter: target.adapter, adapterFamily: target.adapter, basis: "current", pathScope: [],
        capabilityCeiling: FIXTURE_TARGET_CAPABILITIES, participation: "writable",
    };
}

function fixtureWorkspace(scope: ScopeFixture, projectFixtures: readonly ProjectFixture[]): Workspace {
    const libraryAgents = LIBRARY_AGENT_SEEDS.map((seed) => ({
        seed,
        id: fixtureArchetypeId(`${scope.id}:${seed.slug}`),
        targetId: workTargetId(`${scope.id}:${seed.slug}-method`),
    }));
    const libraryAgent = (slug: string) => libraryAgents.find((candidate) => candidate.seed.slug === slug)!;
    const generalId = libraryAgent("general").id;
    const designerId = libraryAgent("product-designer").id;

    const archetypeTarget = (id: ReturnType<typeof workTargetId>, name: string, ownerId: ArchetypeId): WorkTargetNode => ({
        id, name, ownerKind: "archetype", ownerId, authority: scope.kind === "signed-out-local" ? "this computer" : scope.label,
        parties: [scope.kind === "organization" ? scope.label : "Jack Scully"], kind: "managed", adapter: "gaugedesk",
        adapterFamily: "managed", vcsPosture: "managed", currentBasis: "main", pathScope: [],
        capabilities: FIXTURE_TARGET_CAPABILITIES, status: "available", concurrency: "serialized",
    });
    const methodTargets = libraryAgents.map(({ seed, id, targetId }) => archetypeTarget(targetId, `${seed.name} method`, id));
    const projectTargets: WorkTargetNode[] = [];
    let firstChat = true;

    const projects: Workspace["projects"] = projectFixtures.map((projectFixture, projectIndex) => {
        const id = fixtureProjectId(projectFixture.id);
        const targetId = workTargetId(`${scope.id}:${projectFixture.id}:files`);
        const target: WorkTargetNode = {
            id: targetId, name: `${projectFixture.name} files`, ownerKind: "project", ownerId: id,
            authority: projectFixture.detail, parties: [scope.kind === "organization" ? scope.label : "Jack Scully"],
            kind: projectFixture.detail.toLowerCase().includes("desktop") || projectFixture.detail.toLowerCase().includes("computer")
                ? "external-folder" : "managed",
            adapter: projectFixture.detail.toLowerCase().includes("desktop") || projectFixture.detail.toLowerCase().includes("computer")
                ? "local-folder" : "gaugedesk",
            adapterFamily: "workspace", vcsPosture: "unversioned", currentBasis: "current", pathScope: [],
            capabilities: FIXTURE_TARGET_CAPABILITIES, status: "available", concurrency: "compare-before-write-weak",
        };
        projectTargets.push(target);

        const makePlacement = (
            archetypeId: ArchetypeId, archetypeName: string, isDefault: boolean, count: number, start: number,
        ): Workspace["projects"][number]["placements"][number] => {
            const placementId = fixturePlacementId(`${scope.id}:${projectFixture.id}:${isDefault ? "general" : "product-designer"}`);
            const root = fixtureWorkspaceRootId(placementId);
            const chats = Array.from({ length: count }, (_, offset) => {
                const title = FIXTURE_CHAT_TITLES[(projectIndex * 2 + start + offset) % FIXTURE_CHAT_TITLES.length]!;
                const id = firstChat ? LAB_ENGAGEMENT : engagementId(`${scope.id}:${projectFixture.id}:chat:${start + offset}`);
                firstChat = false;
                return {
                    id, title, kind: "work" as const, workstream: null, placement: placementId, workspaceRoot: root,
                    targets: [fixtureTargetMember(target, targetId)], targetSetRevision: 1, collaborationWorkspaceId: null,
                    targetId, targetBasis: "current", targetKind: target.kind, targetAdapter: target.adapter,
                    targetPathScope: [], targetCapabilities: FIXTURE_TARGET_CAPABILITIES,
                    candidateRevision: `fixture-${projectIndex + 1}-${start + offset + 1}`,
                    availableActs: ["read", "propose", "apply"] as const, conflict: false, rehomeBlocked: false,
                };
            });
            return {
                placementId, kind: "work", archetypeId, archetypeName, isDefault, hasConfig: !isDefault && projectIndex === 1,
                pinnedVersion: null, version: isDefault ? 1 : 3, currentVersion: isDefault ? 1 : 4,
                panelProfile: null, upgradeAvailable: !isDefault && projectIndex === 0, pending: false,
                deployments: [], targetIds: [targetId], chats, workstreams: [],
            };
        };
        const generalCount = Math.min(projectFixture.conversations, 3);
        const placements = [
            makePlacement(generalId, "General", true, generalCount, 0),
            ...(projectFixture.conversations > generalCount
                ? [makePlacement(designerId, "Product designer", false, projectFixture.conversations - generalCount, generalCount)]
                : []),
        ];
        return {
            id, homeId: fixtureHomeId(`${scope.id}:${projectFixture.id}:home`), name: projectFixture.name,
            isPersonal: projectFixture.isPersonal, networkIsolated: projectFixture.id === "security-operations",
            targets: [target], placements,
        };
    });

    const editChat = (archetypeId: ArchetypeId, targetId: ReturnType<typeof workTargetId>, title: string) => {
        const instanceId = fixturePlacementId(`${archetypeId}:authoring`);
        return {
            id: engagementId(`${archetypeId}:edit`), title, kind: "edit" as const, workstream: null,
            placement: instanceId, workspaceRoot: fixtureWorkspaceRootId(instanceId),
            targets: [fixtureTargetMember({ id: targetId, name: title, kind: "managed", adapter: "gaugedesk" }, targetId)],
            targetSetRevision: 1, collaborationWorkspaceId: null, targetId,
            targetBasis: "published", targetKind: "managed" as const, targetAdapter: "gaugedesk",
            targetPathScope: [], targetCapabilities: FIXTURE_TARGET_CAPABILITIES, candidateRevision: "draft",
            availableActs: ["read", "propose", "apply"] as const, conflict: false, rehomeBlocked: false,
        };
    };
    const archetype = ({ seed, id, targetId }: typeof libraryAgents[number]): Workspace["archetypes"][number] => ({
        id, name: seed.name, kind: seed.kind, panelProfile: seed.kind === "panel" ? fixturePanelProfile() : null,
        instanceId: fixturePlacementId(`${id}:authoring`), authoringTargetId: targetId,
        isDefault: Boolean(seed.isDefault), forkedFrom: null, forkedFromName: null,
        chats: seed.isDefault ? [] : [editChat(id, targetId, `Improve ${seed.name}`)], workstreams: [],
    });
    const archetypes = libraryAgents.map(archetype);
    const recent = projects.flatMap((project) => project.placements.flatMap((placement) => placement.chats.map((chat) => ({
        id: chat.id, title: chat.title, archetype: placement.archetypeName, kind: chat.kind,
        workstream: chat.workstream, placement: chat.placement, workspaceRoot: chat.workspaceRoot,
        targets: chat.targets, targetSetRevision: chat.targetSetRevision,
        collaborationWorkspaceId: chat.collaborationWorkspaceId,
        targetId: chat.targetId, targetBasis: chat.targetBasis, targetKind: chat.targetKind,
        targetAdapter: chat.targetAdapter, candidateRevision: chat.candidateRevision,
        availableActs: chat.availableActs, conflict: chat.conflict, rehomeBlocked: chat.rehomeBlocked,
    })))).slice(0, 8);
    return {
        archetypes, projects, recent, workstreams: [], workTargets: [...projectTargets, ...methodTargets],
        personalPlacement: projects.find((project) => project.isPersonal)?.placements.find((placement) => placement.isDefault)?.placementId ?? null,
    };
}

function fixtureFacetApi(readWorkspace: () => Workspace): FacetBrowserApi {
    let next = 0;
    const generatedChat = () => engagementId(`gaugeapps:generated:${++next}`);
    return {
        getWorkspaceCarriage: async () => ({
            value: readWorkspace(), freshness: { marker: "live", generatedAt: Date.now(), repairHint: null }, clientRequestId: null,
        }),
        search: async (query: string): Promise<SearchHit[]> => readWorkspace().recent
            .filter((chat) => `${chat.title} ${chat.archetype}`.toLowerCase().includes(query.toLowerCase()))
            .map((chat) => ({ id: chat.id, title: chat.title, snippet: `${chat.archetype} · fixture conversation`, tier: "log" })),
        getPlacementConfig: async () => ({ config: "", notes: "Fixture placement — no backend is connected." }),
        setPlacementConfig: async () => undefined,
        createArchetype: async () => fixtureArchetypeId(`gaugeapps:archetype:${++next}`),
        copyAgentAsPanel: async () => fixtureArchetypeId(`gaugeapps:panel:${++next}`),
        createProject: async () => fixtureProjectId(`gaugeapps:project:${++next}`),
        renameArchetype: async () => undefined,
        renameProject: async () => undefined,
        renameChat: async () => undefined,
        createWorkstream: async (placementId, name): Promise<WorkstreamNode> => ({
            id: workstreamId(`gaugeapps:workstream:${++next}`), name, placementId, projectId: null,
            workspaceRoot: fixtureWorkspaceRootId(placementId), targetId: null,
            status: "active", collaboration: "active",
            promotionManifestRef: null, promotionTargets: [],
            targetSettlement: "not-requested", targetSettlementDeclaration: null, targetSettlementMembers: [],
            members: [],
        }),
        // Target settlement arrived after this prototype was drawn. It is a work
        // lane, not a GaugeApp surface, so the bench answers each call inertly
        // rather than modelling a second settlement authority.
        settleWorkstreamTarget: async () => undefined,
        settleChatTargets: async () => undefined,
        queryTargetSettlementMember: async () => undefined,
        retryTargetSettlementMember: async () => undefined,
        getTargetSettlement: async () => undefined,
        supersedeTargetSettlementMember: async () => undefined,
        compensateTargetSettlement: async () => undefined,
        abandonTargetSettlement: async () => undefined,
        cancelTargetSettlement: async () => undefined,
        reviseChatTargets: async () => undefined,
        joinWorkstream: async () => undefined,
        leaveWorkstream: async () => undefined,
        promoteWorkstream: async () => undefined,
        archiveWorkstream: async () => undefined,
        createChatUnderArchetype: async () => generatedChat(),
        createChatUnderPlacement: async () => generatedChat(),
        useArchetype: async () => generatedChat(),
        createEngagement: async (): Promise<Engagement> => ({ id: generatedChat(), branch: "fixture", path: "/fixture" }),
        deleteChat: async () => undefined,
        forkChat: async () => generatedChat(),
        deleteProject: async () => undefined,
        upgradePlacement: async () => 4,
        acceptPlacement: async () => undefined,
        removePlacement: async () => undefined,
        publishArchetype: async () => ({ version: 4, autoUpgraded: 0 }),
        forkArchetype: async () => fixtureArchetypeId(`gaugeapps:fork:${++next}`),
        pullFromSource: async () => undefined,
        deleteArchetype: async () => undefined,
        placeArchetype: async () => fixturePlacementId(`gaugeapps:placement:${++next}`),
    };
}

const ActionFeedbackContext = createContext<(message: string) => void>(() => undefined);
const InteractionContext = createContext<(target: InteractionTarget) => void>(() => undefined);
const PrototypeOrganizationContext = createContext<PrototypeOrganizationStateApi>({ get: () => ({}), update: () => undefined });

/**
 * A control receives a destination only when the prototype models that exact
 * destination. Never infer pages from verbs: doing so previously turned every
 * "manage" or "review" button into an invented product requirement.
 */
function actionOpensPage(app: GaugeAppId, tab: string, target: InteractionTarget): boolean {
    const action = target.action.trim().toLowerCase();
    if (target.kind === "organization-plan" || target.kind === "organization-seats"
        || target.kind === "provider-commercial" || target.kind === "enterprise-controls") return true;
    if (app === "vend") {
        if (tab === "Products") return ["new product", "view product", "edit product"].includes(action);
        if (tab === "Clients") return ["view client", "view history"].includes(action);
        if (tab === "Engagements") return ["new proposal", "open engagement", "edit proposal", "view proposal", "view record"].includes(action);
        if (tab === "Payments") return [
            "set up payments", "manage stripe account", "resolve requirement", "manage payments", "manage payment",
            "manage payouts", "view documents", "open stripe support", "details", "open invoice", "refund",
        ].includes(action);
    }
    if (app === "project") return [
        "attach work", "attach context", "data policy", "edit data policy", "inspect", "manage access", "manage agent access",
        "view request", "review request", "manage acts", "configure", "manage", "manage placement", "upgrade", "review & accept",
        "review upgrade", "new deployment", "open deployment", "add agent", "deploy panel", "add connection", "edit connection",
    ].includes(action);
    if (app === "administration") {
        if (tab === "Projects") return action === "inspect";
        if (tab === "People & Access") return ["view grants", "manage grants"].includes(action);
        if (tab === "Project Hosts") return ["inspect", "manage", "diagnose", "add project host"].includes(action);
        if (tab === "Backups") return ["schedule & retention", "recovery instructions", "inspect", "view all points"].includes(action);
        if (tab === "Clients") return ["inspect", "view admission"].includes(action);
        if (tab === "Billing") return ["view", "view estimate", "view all", "view usage"].includes(action);
    }
    if (app === "settings" && tab === "Account Settings") return ["edit profile", "reauthenticate", "verify", "open"].includes(action);
    if (app === "settings" && tab === "Trusted Devices") return ["manage trusted device", "view trusted device history"].includes(action);
    return false;
}

function detailNavigationLabel(detail: DetailPageRequest): string {
    const action = detail.action.trim().toLowerCase();
    if (action === "new product") return "New product";
    if (action === "new proposal") return "New proposal";
    if (action === "new deployment") return "New deployment";
    if (action === "add project host") return "Add a Project Host";
    return detail.title;
}

function detailFamily(app: GaugeAppId, tab: string, target: InteractionTarget): DetailFamily {
    const words = `${target.action} ${target.title} ${target.kind ?? ""}`.toLowerCase();
    if (app === "project") {
        if (tab === "Project Permissions") return "project-access";
        if (tab === "Project Work") return words.includes("context") || words.includes("archive") || words.includes("access request")
            || words.includes("data policy") || words.includes("classification") || words.includes("purpose")
            || words.includes("agent access") || target.kind === "project owned" || target.kind === "client owned" || target.kind === "request"
            ? "project-resource" : "project-target";
        if (tab === "Project Placements") {
            if (words.includes("deployment") || words.includes("deploy")) return "deployment";
            return "project-placement";
        }
        return "project-model";
    }
    if (app === "vend") {
        if (tab === "Products") return "sales-setup";
        if (tab === "Clients") return "client";
        if (tab === "Engagements") return target.kind === "agreement" || words.includes("agreement") ? "agreement" : "offer";
        if (["stripe", "payment", "refund", "balance", "payout", "bank", "dispute", "tax", "document", "requirement", "processing setup", "public details", "add funds", "support"].some((term) => words.includes(term))) return "stripe-connect";
        if (words.includes("invoice")) return "invoice";
        return "transaction";
    }
    if (app === "administration") {
        if (tab === "Organization") return "organization";
        if (tab === "Services") return "capability";
        if (tab === "Projects") return "project-governance";
        if (tab === "People & Access") return "member";
        if (tab === "Identity") return "identity";
        if (tab === "Model Providers") return "model";
        if (tab === "Policy") return "policy";
        if (tab === "Project Hosts") return "project-host";
        if (tab === "Backups") return "backup";
        if (tab === "Software") return "software";
        if (tab === "Clients") return "client-session";
        if (tab === "Billing" && (words.includes("invoice") || words.includes("estimate"))) return "invoice";
        return "billing";
    }
    if (tab === "Sign In") return "sign-in";
    if (tab === "Account Settings") return "account";
    if (tab === "Provider Connections") return "model";
    if (tab === "Trusted Devices") return "trusted-device";
    return "application";
}

function appTabs(scope: ScopeFixture, app: GaugeAppId): readonly string[] {
    if (app === "project") return APP_TABS.project;
    if (app === "administration") return scope.administrationTabs;
    if (app === "settings") return scope.settingsTabs;
    return APP_TABS.vend;
}

function tabLabel(scope: ScopeFixture, app: GaugeAppId, tab: string): string {
    if (app === "project") return PROJECT_TABS.find((item) => item.id === tab)?.label ?? tab;
    if (app === "administration") return administrationDestination(scope, tab).tabs.find((item) => item.id === tab)?.label ?? tab;
    return tab;
}

function administrationDestinations(scope: ScopeFixture): readonly AdministrationDestination[] {
    const allowed = new Set(scope.administrationTabs);
    return ADMINISTRATION_DESTINATIONS.map((destination) => {
        const tabs = destination.tabs.filter((item) => allowed.has(item.id));
        if (scope.kind === "organization" && destination.id === "organization") return {
            ...destination,
            description: scope.enterpriseControls === "active"
                ? "Organization identity, ownership, verified domains, transfer, and deletion."
                : "Organization identity, ownership, transfer, and deletion.",
            tabs,
        };
        if (scope.kind === "signed-out-local" && destination.id === "project-hosts-recovery") return {
            ...destination, label: "Project Hosts", description: "This computer is the Project Host for its local project Homes.", tabs,
        };
        if (scope.kind === "personal" && destination.id === "project-hosts-recovery") return {
            ...destination, label: tabs.some((item) => item.id === "Backups") ? "Project Hosts & Recovery" : "Project Hosts",
            description: tabs.some((item) => item.id === "Backups") ? "Where your project Homes live and how they can be recovered." : "Where your project Homes live.", tabs,
        };
        if (scope.kind === "organization" && scope.enterpriseControls !== "active" && destination.id === "project-hosts-recovery") return {
            ...destination, label: "Project Hosts & Recovery", description: "Where organization project Homes live and how they can be recovered.", tabs,
        };
        if (scope.kind === "personal" && destination.id === "organization-billing") return {
            ...destination, description: "GaugeWright services billed to your personal tenant.", tabs,
        };
        return { ...destination, tabs };
    }).filter((destination) => destination.tabs.length > 0);
}

function administrationDestination(scope: ScopeFixture, tab: string): AdministrationDestination {
    return administrationDestinations(scope).find((destination) => destination.tabs.some((item) => item.id === tab))
        ?? administrationDestinations(scope)[0]!;
}

function scopeKindLabel(scope: ScopeFixture): string {
    if (scope.kind === "signed-out-local") return "This computer";
    if (scope.kind === "personal") return "Personal";
    return "Organization";
}

function scopeDomain(scope: ScopeFixture): string {
    if (scope.id === "acorn") return "acornworkshop.com";
    if (scope.id === "brightworks") return "brightworks.studio";
    if (scope.id === "northstar") return "northstarlabs.com";
    return "gaugewright.com";
}

/** The mark the accepted account menu uses: initials for a named scope, the
 *  anonymous diamond otherwise (gaugedesk-src #352). The prototype originally
 *  drew three glyphs the icon set no longer carries. */
function scopeInitials(scope: ScopeFixture): string | null {
    if (scope.kind === "signed-out-local") return null;
    const initials = scope.label.split(/[^A-Za-z0-9]+/).filter(Boolean).slice(0, 2).map((part) => part[0]!).join("");
    return initials.toUpperCase() || null;
}

function ScopeMark(props: { scope: ScopeFixture }): JSX.Element {
    const initials = () => scopeInitials(props.scope);
    return <Show when={initials()} fallback={<span class="account-avatar account-avatar-anon" aria-hidden="true">◇</span>}>
        {(text) => <span class="account-avatar" aria-hidden="true">{text()}</span>}
    </Show>;
}

function canAdministerOrganization(scope: ScopeFixture): boolean {
    return scope.kind === "organization" && (scope.organizationRole === "owner" || scope.organizationRole === "admin");
}

function canUseCommercialOperations(scope: ScopeFixture): boolean {
    return scope.kind === "organization" && scope.providerCommerce === "active" && scope.commercialRole !== null;
}

function availableApps(scope: ScopeFixture): readonly GaugeApp[] {
    return scope.apps.filter((candidate) => {
        if (candidate.id === "vend") return canUseCommercialOperations(scope);
        if (candidate.id === "administration" && scope.kind === "organization") return canAdministerOrganization(scope);
        return true;
    });
}

export function GaugeAppsComposition(): JSX.Element {
    const [scopeId, setScopeId] = createSignal<ScopeId>("gaugewright");
    const [appId, setAppId] = createSignal<GaugeAppId>("vend");
    const [tab, setTab] = createSignal("Products");
    const [projectId, setProjectId] = createSignal("gaugedesk");
    const [busy, setBusy] = createSignal(false);
    const [creatingOrganization, setCreatingOrganization] = createSignal(false);
    const [accountMenuOpen, setAccountMenuOpen] = createSignal(false);
    const [scopeMenuOpen, setScopeMenuOpen] = createSignal(false);
    const [detailPage, setDetailPage] = createSignal<DetailPageRequest | null>(null);
    const [selectedNavChat, setSelectedNavChat] = createSignal<EngagementId | null>(LAB_ENGAGEMENT);
    const [networkOverrides, setNetworkOverrides] = createSignal<Readonly<Record<string, boolean>>>({});
    const scope = createMemo(() => SCOPES.find((candidate) => candidate.id === scopeId())!);
    const app = createMemo(() => availableApps(scope()).find((candidate) => candidate.id === appId()) ?? availableApps(scope())[0]!);
    const projects = createMemo(() => PROJECTS_BY_SCOPE[scopeId()]);
    const project = createMemo(() => projects().find((candidate) => candidate.id === projectId()) ?? projects()[0]!);
    const workspace = createMemo(() => fixtureWorkspace(scope(), projects()));
    const facetApi = fixtureFacetApi(workspace);
    const projectNetworkIsolated = createMemo(() => networkOverrides()[project().id]
        ?? workspace().projects.find((candidate) => candidate.id === project().id)?.networkIsolated
        ?? false);
    const appScopeLabel = createMemo(() => {
        const base = app().id === "project" ? `${scope().label} · ${project().name}` : scope().label;
        return detailPage() ? `${base} · ${detailNavigationLabel(detailPage()!)}` : base;
    });
    const [transcript, setTranscript] = createSignal<Transcript>(emptyTranscript);

    createEffect(() => {
        scopeId(); appId(); projectId(); detailPage()?.id;
        if (!appTabs(scope(), app().id).includes(tab())) setTab(appTabs(scope(), app().id)[0]!);
        setTranscript({ openText: null, lines: [{
            seq: 0, tier: "admitted", kind: "assistant",
            text: app().id === "vend"
                ? "I can help with products, clients, engagements, and payments."
                : `I can help with ${app().label} for ${appScopeLabel()}.`,
        }] });
    });
    const chooseScope = (next: ScopeId) => batch(() => {
        const candidate = SCOPES.find((item) => item.id === next)!;
        const candidateApps = availableApps(candidate);
        const candidateProject = PROJECTS_BY_SCOPE[next][0]!;
        const previousApp = appId();
        setScopeId(next);
        setProjectId(candidateProject.id);
        setSelectedNavChat(LAB_ENGAGEMENT);
        setDetailPage(null);
        setCreatingOrganization(false);
        setScopeMenuOpen(false);
        setAccountMenuOpen(false);
        if (!candidateApps.some((item) => item.id === previousApp)) {
            if (previousApp === "vend" && candidateApps.some((item) => item.id === "administration")) {
                setAppId("administration");
                setTab("Services");
            } else {
                setAppId(candidateApps[0]!.id);
                setTab(candidateApps[0]!.id === "project" && candidateProject.isPersonal
                    ? "Project Work" : appTabs(candidate, candidateApps[0]!.id)[0]!);
            }
        } else {
            const allowed = appTabs(candidate, previousApp);
            setTab(previousApp === "project" && candidateProject.isPersonal && tab() === "Project Permissions"
                ? "Project Work" : allowed.includes(tab()) ? tab() : allowed[0]!);
        }
    });
    const chooseApp = (next: GaugeAppId) => batch(() => {
        if (!availableApps(scope()).some((candidate) => candidate.id === next)) return;
        setCreatingOrganization(false);
        setAccountMenuOpen(false);
        setScopeMenuOpen(false);
        setDetailPage(null);
        setAppId(next);
        setTab(appTabs(scope(), next)[0]!);
    });
    const chooseSetting = (next: string) => {
        chooseApp("settings");
        setTab(next);
    };
    const chooseAdministrationDestination = (next: string) => {
        chooseApp("administration");
        setTab(next);
    };
    const chooseVendDestination = (next: string) => {
        chooseApp("vend");
        setTab(next);
    };
    const chooseProjectDestination = (next: string) => {
        const destination = project().isPersonal && next === "Project Permissions" ? "Project Work" : next;
        chooseApp("project");
        setTab(destination);
    };
    const openProjectSettings = (nextProject: string, nextTab: string = PROJECT_TABS[0]!.id) => {
        const candidate = projects().find((item) => item.id === nextProject);
        setProjectId(nextProject);
        chooseApp("project");
        setTab(candidate?.isPersonal && nextTab === "Project Permissions" ? "Project Work" : nextTab);
    };
    const chooseProject = (next: string) => {
        setProjectId(next);
        setDetailPage(null);
    };
    const navigateTo = (nextApp: GaugeAppId, nextTab: string, target?: InteractionTarget) => {
        if (!availableApps(scope()).some((candidate) => candidate.id === nextApp)) return;
        batch(() => {
            setCreatingOrganization(false);
            setAccountMenuOpen(false);
            setScopeMenuOpen(false);
            setAppId(nextApp);
            setTab(nextTab);
            setDetailPage(target ? {
                ...target,
                id: `${nextApp}:${nextTab}:${target.title}:${target.action}`,
                family: detailFamily(nextApp, nextTab, target),
                appId: nextApp,
                sourceTab: nextTab,
                sourceLabel: tabLabel(scope(), nextApp, nextTab),
            } : null);
        });
    };
    const openRecentConversation = (nextProject: string, title: string) => {
        chooseProject(nextProject);
        setTranscript({ openText: null, lines: [
            { seq: 0, tier: "admitted", kind: "user", text: title === "Product direction"
                ? "Help me turn the current product direction into a concrete next pass."
                : `Help me work through ${title.toLowerCase()} and identify the next concrete action.` },
            { seq: 1, tier: "admitted", kind: "assistant", text: `This fixture conversation is admitted to ${projects().find((candidate) => candidate.id === nextProject)?.name ?? project().name}. Its normal work context remains independent from any GaugeApp page open in the content pane.` },
        ] });
        shell.openPane("chat", { chatSelected: true, fileSelected: true });
    };
    const openNavChat = (id: EngagementId) => {
        setSelectedNavChat(id);
        for (const candidate of workspace().projects) {
            const chat = candidate.placements.flatMap((placement) => placement.chats).find((item) => item.id === id);
            if (chat) {
                openRecentConversation(candidate.id, chat.title);
                return;
            }
        }
        const edit = workspace().archetypes.flatMap((archetype) => archetype.chats).find((item) => item.id === id);
        openRecentConversation(project().id, edit?.title ?? "Untitled chat");
    };
    const openLibraryAgent = (nextProject: string, title: string) => {
        setProjectId(nextProject);
        navigateTo("project", "Project Placements", {
            action: "manage", title,
            description: `Library Agent available to configure as a placement in ${projects().find((candidate) => candidate.id === nextProject)?.name ?? project().name}.`,
            kind: "work Agent", meta: "library",
        });
    };
    // The menu is a door, not a room (gaugedesk-src #352): a row either states a
    // fact or opens a surface that owns its own navigation. A destination with
    // subpages therefore carries the disclosure arrow and opens its first page;
    // the GaugeApp's Menu pane lists the rest. The prototype nested those pages
    // in the menu itself, which the accepted account menu no longer does.
    const administrativeMenuItems = () => administrationDestinations(scope()).map((destination): AccountMenuItem => ({
            id: `administration-${destination.id}`,
            label: destination.label,
            hint: app().id === "administration" && destination.tabs.some((item) => item.id === tab()) ? "current" : undefined,
            submenu: destination.tabs.length > 1,
            run: () => chooseAdministrationDestination(destination.tabs[0]!.id),
        }));
    const organizationItems = createMemo<AccountMenuItem[]>(() => {
        const items: AccountMenuItem[] = [];
        if (canAdministerOrganization(scope())) items.push(...administrativeMenuItems());
        if (canUseCommercialOperations(scope())) {
            items.push({
                id: "commercial-operations",
                label: "Commercial Operations",
                hint: app().id === "vend" ? "current" : scope().commercialRole ?? undefined,
                submenu: true,
                run: () => chooseVendDestination(APP_TABS.vend[0]!),
            });
        }
        return items;
    });
    const accountItems = createMemo<AccountMenuItem[]>(() => {
        const items: AccountMenuItem[] = [];
        items.push(...scope().settingsTabs.map((setting, index): AccountMenuItem => ({
            id: `account-${setting.toLowerCase().replaceAll(" ", "-")}`,
            label: setting,
            hint: app().id === "settings" && tab() === setting ? "current" : index === 0 ? "Ctrl+," : undefined,
            run: () => chooseSetting(setting),
        })));
        if (scope().kind !== "organization") {
            items.push(
                { id: "separator-account-services", label: "", separator: true, run: () => undefined },
                ...administrativeMenuItems(),
            );
        }
        if (scope().kind !== "signed-out-local") items.push(
            { id: "separator-session", label: "", separator: true, run: () => undefined },
            { id: "sign-out", label: "Sign out", danger: true, run: () => setAccountMenuOpen(false) },
        );
        return items;
    });
    const send = async (text: string) => {
        setBusy(true);
        setTranscript((current) => ({ openText: null, lines: [...current.lines,
            { seq: current.lines.length, tier: "admitted", kind: "user", text }] }));
        await Promise.resolve();
        setTranscript((current) => ({ openText: null, lines: [...current.lines, {
            seq: current.lines.length, tier: "admitted", kind: "assistant",
            text: `No tool is wired in this prototype. A real ${app().label} session would expose only commands admitted for ${scope().label}.`,
        }] }));
        setBusy(false);
    };
    const session: Session = {
        api: { getTree: async () => [], getFile: async () => "", putFile: async () => undefined },
        engagementId: () => selectedNavChat() ?? LAB_ENGAGEMENT, worktreeRev: () => `${scopeId()}:${projectId()}:${appId()}:${tab()}:${detailPage()?.id ?? "index"}`,
        selectedFile: () => null, selectFile: () => undefined, diff: () => "",
        mergePhase: () => null, mergeConflicted: () => false, chatKind: () => "work",
        methodName: () => app().label, transcript, busy, turnActivity: localTurnActivity(busy, transcript),
        composerCapabilities: () => ({ queue: true, steer: false, stop: false, hold: true, fork: false, attachments: [] }),
        canCommand: () => true, merge: () => undefined, onContentSaved: () => undefined, send,
    };
    const shell = createWorkbenchShellState({
        storagePrefix: "ui.gaugeapps-prototype", includeFiles: true,
        selection: () => ({ chatSelected: true, fileSelected: true }),
    });
    createEffect(() => {
        void app().id;
        void tab();
        shell.setCollapsed("files", false);
    });
    let composerInput: HTMLTextAreaElement | undefined;
    return <WorkbenchShell
        state={shell} titles={{ nav: "GaugeApps", chat: `${app().label} agent`, content: app().label, files: "Menu" }}
        headings={{ nav: false, chat: false }}
        taskBar={() => <TaskBar api={{
            getTasks: async (): Promise<HumanTask[]> => [], getRoster: async () => [], assignWorkItem: async () => null,
        }} selected={selectedNavChat()} refreshKey={`${scopeId()}:${appId()}`} onSelect={openNavChat} />}
        nav={() => <FacetBrowser api={facetApi} selected={selectedNavChat()} onSelect={openNavChat}
            onOpenArchetypeSettings={(_id, name) => openLibraryAgent(project().id, name)}
            onOpenEngagement={(id) => openProjectSettings(id, "Project Permissions")}
            onOpenModelAccess={(id) => openProjectSettings(id, "Project Models")}
            onOpenProjectHome={(id) => openProjectSettings(id, "Project Work")}
            onOpenInbox={(id) => openProjectSettings(id, "Project Work")}
            onAttachTarget={(id) => openProjectSettings(id, "Project Work")}
            onOpenForkTree={openNavChat}
            onChatDeleted={(id) => id === selectedNavChat() && setSelectedNavChat(null)}
            onStatus={() => undefined}
            refreshKey={scopeId()} />}
        navFooter={() => <div class="nav-footer gaugeapp-account-footer">
            <div class="network-bar" classList={{ isolated: projectNetworkIsolated() }}><div class="network-bar-status">
                <button type="button" class="network-bar-toggle" data-testid="network-toggle"
                    title={projectNetworkIsolated()
                        ? `“${project().name}” is network-isolated. Click to open egress.`
                        : `“${project().name}” has open network egress. Click to isolate.`}
                    onClick={() => setNetworkOverrides((current) => ({ ...current, [project().id]: !projectNetworkIsolated() }))}>
                    <span class="network-bar-dot" />{projectNetworkIsolated() ? "Network · isolated" : "Network · open"}
                </button>
            </div></div>
            <div class="gaugeapp-scope-bar"><ScopePicker scope={scope()} items={organizationItems()} open={scopeMenuOpen()}
                onToggle={() => { setAccountMenuOpen(false); setScopeMenuOpen(!scopeMenuOpen()); }}
                onClose={() => setScopeMenuOpen(false)}
                onScope={chooseScope} onNewOrganization={() => { setCreatingOrganization(true); setScopeMenuOpen(false); }} /></div>
            <div class="account-bar"><AccountMenu
            composition="desktop"
            identity={scope().kind === "signed-out-local" ? null : { name: "Jack Scully", email: "jack@gaugewright.com", edition: scope().posture }}
            version="0.4.5"
            reach={scope().kind === "signed-out-local" ? "this computer" : scope().label}
            items={accountItems()}
            open={accountMenuOpen()}
            onToggle={() => { setScopeMenuOpen(false); setAccountMenuOpen(!accountMenuOpen()); }}
        /></div></div>}
        chat={() => <><ChatPaneHeader title={`${app().label} agent`} context={appScopeLabel()}
            contextKind="work" kind="work" statusLabel="Prototype" mobile={shell.isMobile()}
            onCollapse={() => shell.setCollapsed("chat", true)} />
            <ChatPanel session={session} bare composerPlaceholder={`ask the ${app().label.toLowerCase()} agent…`}
                composerInputRef={(element) => (composerInput = element)} /></>}
        content={() => <GaugeAppContent scope={scope()} project={project()} workspace={workspace()} app={app()} tab={tab()}
            detail={detailPage()} creatingOrganization={creatingOrganization()} onCancelOrganization={() => setCreatingOrganization(false)}
            onDetail={setDetailPage} onNavigate={navigateTo} onProjectNavigate={openProjectSettings} />}
        files={() => <GaugeAppNavigation scope={scope()} project={project()} app={app()} active={tab()} detail={detailPage()}
            onDetailBack={() => setDetailPage(null)}
            onProject={chooseProjectDestination} onVend={chooseVendDestination} onAdministration={chooseAdministrationDestination} onSetting={chooseSetting} />}
        onNewChat={() => { shell.openPane("chat", { chatSelected: true, fileSelected: true }); queueMicrotask(() => composerInput?.focus()); }}
    />;
}

function ScopeMenuRow(props: { item: AccountMenuItem; onRun: () => void }): JSX.Element {
    return <div class="account-menu-branch">
        <button type="button" class="account-menu-item" classList={{ danger: props.item.danger }}
            onClick={() => { props.item.run(); props.onRun(); }}>
            <span class="account-menu-label">{props.item.label}</span>
            <Show when={props.item.hint}>{(hint) => <span class="account-menu-hint">{hint()}</span>}</Show>
            <Show when={props.item.submenu}><span class="account-menu-more" aria-hidden="true">›</span></Show>
        </button>
    </div>;
}

function ScopePicker(props: {
    scope: ScopeFixture;
    items: readonly AccountMenuItem[];
    open: boolean;
    onToggle: () => void;
    onClose: () => void;
    onScope: (scope: ScopeId) => void;
    onNewOrganization: () => void;
}): JSX.Element {
    const choose = (candidate: ScopeFixture) => {
        props.onScope(candidate.id);
        props.onClose();
    };
    return <div class="gaugeapp-scope-picker">
        <button type="button" class="gaugeapp-scope-trigger" aria-haspopup="menu" aria-expanded={props.open} onClick={props.onToggle}>
            <ScopeMark scope={props.scope} />
            <span class="gaugeapp-scope-trigger-text"><strong>{props.scope.label}</strong><small>{props.scope.posture}</small></span><span class="account-trigger-caret">⌃</span>
        </button>
        <Show when={props.open}><>
            <div class="popover-catcher" onClick={props.onClose} />
            <div class="gaugeapp-scope-menu" role="menu" aria-label="Account and organization context">
            <span class="gaugeapp-menu-label">Personal & local</span>
            <For each={SCOPES.filter((candidate) => candidate.kind !== "organization")}>{(candidate) => <ScopeChoice candidate={candidate} current={props.scope.id} onChoose={() => choose(candidate)} />}</For>
            <span class="gaugeapp-menu-label gaugeapp-menu-label-organizations">Organizations</span>
            <For each={SCOPES.filter((candidate) => candidate.kind === "organization")}>{(candidate) => <ScopeChoice candidate={candidate} current={props.scope.id} onChoose={() => choose(candidate)} />}</For>
            <Show when={props.items.length > 0}><div class="account-menu-separator" role="separator" />
                <span class="gaugeapp-menu-label">{props.scope.label}</span>
                <For each={props.items}>{(item) => <ScopeMenuRow item={item} onRun={props.onClose} />}</For>
            </Show>
            <button type="button" class="gaugeapp-new-organization" disabled={props.scope.kind === "signed-out-local"}
                onClick={props.onNewOrganization}>{props.scope.kind === "signed-out-local" ? "Sign in to create an organization" : "＋ New organization"}</button>
        </div></></Show>
    </div>;
}

function ScopeChoice(props: { candidate: ScopeFixture; current: ScopeId; onChoose: () => void }): JSX.Element {
    return <button type="button" class="gaugeapp-scope-choice" classList={{ active: props.candidate.id === props.current }} onClick={props.onChoose}>
        <ScopeMark scope={props.candidate} />
        <span><strong>{props.candidate.label}</strong><small>{scopeKindLabel(props.candidate)}</small></span>
        <small class="gaugeapp-scope-posture">{props.candidate.posture}</small>
    </button>;
}

function AdministrationNavigationList(props: {
    scope: ScopeFixture;
    active: string;
    detail: DetailPageRequest | null;
    selected: boolean;
    onNavigate: (tab: string) => void;
    onDetailBack: () => void;
}): JSX.Element {
    return <For each={administrationDestinations(props.scope)}>{(destination) => {
        const selected = () => props.selected && destination.tabs.some((item) => item.id === props.active);
        const hasChildren = destination.tabs.length > 1;
        return <div class="gaugeapp-navigation-destination">
            <button type="button" class="gaugeapp-navigation-parent" classList={{ selected: selected() }}
                aria-expanded={hasChildren ? selected() : undefined}
                aria-current={!hasChildren && selected() ? "page" : undefined}
                onClick={() => props.onNavigate(destination.tabs[0]!.id)}>{destination.label}</button>
            <Show when={hasChildren && selected()}><div class="gaugeapp-navigation-children" role="group" aria-label={`${destination.label} sections`}>
                <For each={destination.tabs}>{(item) => <><button type="button" class="gaugeapp-navigation-child"
                    classList={{ active: props.active === item.id && !props.detail }} aria-current={props.active === item.id && !props.detail ? "page" : undefined}
                    onClick={() => props.onNavigate(item.id)}>{item.label}</button>
                    <Show when={props.active === item.id && props.detail}><DetailNavigationRow detail={props.detail!} onBack={props.onDetailBack} /></Show></>}</For>
            </div></Show>
            <Show when={!hasChildren && selected() && props.detail}><div class="gaugeapp-navigation-children"><DetailNavigationRow detail={props.detail!} onBack={props.onDetailBack} /></div></Show>
        </div>;
    }}</For>;
}

function AccountNavigationList(props: {
    scope: ScopeFixture;
    active: string;
    detail: DetailPageRequest | null;
    selected: boolean;
    onNavigate: (setting: string) => void;
    onDetailBack: () => void;
}): JSX.Element {
    return <For each={props.scope.settingsTabs}>{(setting) => <><button type="button"
        classList={{ active: props.selected && props.active === setting && !props.detail }}
        aria-current={props.selected && props.active === setting && !props.detail ? "page" : undefined}
        onClick={() => props.onNavigate(setting)}>{setting}</button>
        <Show when={props.selected && props.active === setting && props.detail}><div class="gaugeapp-navigation-children"><DetailNavigationRow detail={props.detail!} onBack={props.onDetailBack} /></div></Show></>}</For>;
}

function GaugeAppNavigation(props: {
    scope: ScopeFixture;
    project: ProjectFixture;
    app: GaugeApp;
    active: string;
    detail: DetailPageRequest | null;
    onDetailBack: () => void;
    onProject: (tab: string) => void;
    onVend: (tab: string) => void;
    onAdministration: (tab: string) => void;
    onSetting: (setting: string) => void;
}): JSX.Element {
    const accountSelected = () => props.app.id === "settings" || (props.scope.kind !== "organization" && props.app.id === "administration");
    return <nav class="gaugeapp-settings-navigation" aria-label="GaugeApp menu">
        <Show when={props.app.id === "project"}><>
            <span class="gaugeapp-navigation-label">{props.scope.kind === "signed-out-local" ? "This computer" : props.scope.kind === "personal" ? "Personal workspace" : props.scope.label}</span>
            <div class="gaugeapp-navigation-destination gaugeapp-navigation-project">
            <button type="button" class="gaugeapp-navigation-parent" classList={{ selected: props.app.id === "project" }}
                aria-expanded={props.app.id === "project"} onClick={() => props.onProject(props.project.isPersonal ? "Project Work" : PROJECT_TABS[0]!.id)}>{props.project.name} Project</button>
            <div class="gaugeapp-navigation-children" role="group" aria-label={`${props.project.name} project settings`}>
                <For each={props.project.isPersonal ? PROJECT_TABS.filter((item) => item.id !== "Project Permissions") : PROJECT_TABS}>{(item) => <><button type="button" class="gaugeapp-navigation-child"
                    classList={{ active: props.active === item.id && !props.detail }} aria-current={props.active === item.id && !props.detail ? "page" : undefined}
                    onClick={() => props.onProject(item.id)}>{item.label}</button>
                <Show when={props.active === item.id && props.detail}><DetailNavigationRow detail={props.detail!} onBack={props.onDetailBack} /></Show></>}</For>
            </div>
            </div>
        </></Show>
        <Show when={props.app.id === "vend"}><>
            <span class="gaugeapp-navigation-label">{props.scope.label} / Commercial Operations</span>
            <div class="gaugeapp-navigation-personal" role="group" aria-label="Commercial Operations sections">
                <For each={APP_TABS.vend}>{(item) => <><button type="button"
                    classList={{ active: props.active === item && !props.detail }} aria-current={props.active === item && !props.detail ? "page" : undefined}
                    onClick={() => props.onVend(item)}>{item}</button>
                    <Show when={props.active === item && props.detail}><div class="gaugeapp-navigation-children"><DetailNavigationRow detail={props.detail!} onBack={props.onDetailBack} /></div></Show></>}</For>
            </div>
        </></Show>
        <Show when={props.scope.kind === "organization" && props.app.id === "administration"}><>
            <span class="gaugeapp-navigation-label">{props.scope.label} / Administration</span>
            <AdministrationNavigationList scope={props.scope} active={props.active} detail={props.detail} selected
                onNavigate={props.onAdministration} onDetailBack={props.onDetailBack} />
        </></Show>
        <Show when={accountSelected()}><>
            <span class="gaugeapp-navigation-label">{props.scope.kind === "signed-out-local" ? "This computer" : "Your Account"}</span>
            <Show when={props.scope.kind !== "organization"}>
                <AdministrationNavigationList scope={props.scope} active={props.active} detail={props.detail} selected={props.app.id === "administration"}
                    onNavigate={props.onAdministration} onDetailBack={props.onDetailBack} />
            </Show>
            <div class="gaugeapp-navigation-personal">
                <AccountNavigationList scope={props.scope} active={props.active} detail={props.detail} selected={props.app.id === "settings"}
                    onNavigate={props.onSetting} onDetailBack={props.onDetailBack} />
            </div>
        </></Show>
    </nav>;
}

function DetailNavigationRow(props: { detail: DetailPageRequest; onBack: () => void }): JSX.Element {
    return <button type="button" class="gaugeapp-navigation-child gaugeapp-navigation-detail active" aria-current="page"
        title={`Back to ${props.detail.sourceLabel}`} onClick={props.onBack}>{detailNavigationLabel(props.detail)}</button>;
}

function GaugeAppContent(props: {
    scope: ScopeFixture;
    project: ProjectFixture;
    workspace: Workspace;
    app: GaugeApp;
    tab: string;
    detail: DetailPageRequest | null;
    creatingOrganization: boolean;
    onCancelOrganization: () => void;
    onDetail: (detail: DetailPageRequest | null) => void;
    onNavigate: (app: GaugeAppId, tab: string, target?: InteractionTarget) => void;
    onProjectNavigate: (project: string, tab?: string) => void;
}): JSX.Element {
    const [actionFeedback, setActionFeedback] = createSignal("");
    const [organizationState, setOrganizationState] = createSignal<Readonly<Record<string, PrototypeOrganizationState>>>({});
    const organizationStateApi: PrototypeOrganizationStateApi = {
        get: (scope) => organizationState()[scope] ?? {},
        update: (scope, change) => setOrganizationState((current) => ({ ...current, [scope]: { ...current[scope], ...change } })),
    };
    createEffect(() => {
        void `${props.scope.id}:${props.project.id}:${props.app.id}:${props.tab}:${props.detail?.id ?? "index"}:${props.creatingOrganization}`;
        setActionFeedback("");
    });
    const interact = (target: InteractionTarget) => {
        const action = target.action.toLowerCase();
        if (action === "manage tenant role") return props.onNavigate("administration", "People & Access", target);
        if (action === "view policy") return props.onNavigate("administration", "Policy");
        if (action === "view clients") return props.onNavigate("administration", "Clients");
        if (action === "manage verified domains") return props.onNavigate("administration", "Organization");
        if (action === "open provisioning") return props.onNavigate("administration", "Identity");
        if (action === "open commercial operations") return props.onNavigate("vend", "Products");
        if (action === "open enterprise identity") return props.onNavigate("administration", "Identity");
        if (action === "open plans and services") return props.onNavigate("administration", "Services");
        if (action === "open billing") return props.onNavigate("administration", "Billing");
        if (action === "open project hosts") return props.onNavigate("administration", "Project Hosts");
        if (action === "open backups") return props.onNavigate("administration", "Backups");
        if (action === "open security policy") return props.onNavigate("administration", "Policy");
        if (action === "open organization projects") return props.onNavigate("administration", "Projects");
        if (action === "open project data") return props.onNavigate("project", "Project Work");
        if (action === "open software admission") return props.onNavigate("administration", "Software");
        if (action === "open people and access") return props.onNavigate("administration", "People & Access");
        if (action === "open model providers" || action === "open model access" || action === "manage model plan") {
            return props.scope.kind === "organization"
                ? props.onNavigate("administration", "Model Providers", target)
                : props.onNavigate("settings", "Provider Connections", target);
        }
        if (action === "add cloud home" || action === "upgrade to plus") return props.onNavigate("administration", "Billing", target);
        if (action === "sign in for cloud services") return props.onNavigate("settings", "Sign In");
        if (action === "view agreement") return props.onNavigate("vend", "Engagements", target);
        if (action === "open in project") return props.onNavigate("project", "Project Placements", target);
        if (action === "open project settings") {
            const governedProject = PROJECTS_BY_SCOPE[props.scope.id].find((candidate) => candidate.id === target.kind || candidate.name === target.title);
            if (governedProject) return props.onProjectNavigate(governedProject.id);
        }
        if (actionOpensPage(props.app.id, props.tab, target)) return props.onDetail({
            ...target,
            id: `${props.app.id}:${props.tab}:${target.title}:${target.action}`,
            family: detailFamily(props.app.id, props.tab, target),
            appId: props.app.id,
            sourceTab: props.tab,
            sourceLabel: tabLabel(props.scope, props.app.id, props.tab),
        });
        const destructive = /archive|cancel|close|deactivate|delete|decline|disconnect|leave|pause|refund|reject|remove|revoke|suspend|turn off/.test(action);
        setActionFeedback(`Prototype: ${target.action} ${destructive ? "requires confirmation for" : "would be applied to"} ${target.title}.`);
    };
    return <PrototypeOrganizationContext.Provider value={organizationStateApi}><ActionFeedbackContext.Provider value={(message) => setActionFeedback(message)}><InteractionContext.Provider value={interact}>
        <div class="viewer gaugeapp-viewer"><div class="filebody markdown-body gaugeapp-content">
            <Show when={props.creatingOrganization} fallback={<Show when={props.detail} fallback={<Show keyed when={`${props.scope.id}:${props.project.id}:${props.app.id}:${props.tab}`}>{(_projectionKey) => <>
                    <Show when={props.app.id === "project"}><ProjectView scope={props.scope} project={props.project} tab={props.tab} onNavigate={props.onNavigate} /></Show>
                    <Show when={props.app.id === "vend"}><VendView scope={props.scope} tab={props.tab} /></Show>
                    <Show when={props.app.id === "administration"}><AdministrationView scope={props.scope} tab={props.tab} /></Show>
                    <Show when={props.app.id === "settings"}><SettingsView scope={props.scope} tab={props.tab} /></Show>
                </>}</Show>}>{(detail) => <DetailPageView scope={props.scope} project={props.project} archetypes={props.workspace.archetypes} detail={detail()} onBack={() => props.onDetail(null)}
                    onNavigate={props.onNavigate} onProjectNavigate={props.onProjectNavigate} />}</Show>}>
                <NewOrganizationView onCancel={props.onCancelOrganization} />
            </Show>
        </div><Show when={actionFeedback()}>{(message) => <div class="gaugeapp-action-feedback" role="status">
            <span>{message()}</span><button type="button" aria-label="Dismiss action status" onClick={() => setActionFeedback("")}>×</button>
        </div>}</Show></div>
    </InteractionContext.Provider></ActionFeedbackContext.Provider></PrototypeOrganizationContext.Provider>;
}

type StripeComponentKind = "onboarding" | "notifications" | "account" | "payments" | "payouts" | "documents" | "support";

function stripeComponentKind(detail: DetailPageRequest): StripeComponentKind {
    const action = detail.action.toLowerCase();
    if (action.includes("set up") || action.includes("onboarding")) return "onboarding";
    if (action.includes("requirement") || action.startsWith("resolve")) return "notifications";
    if (action.includes("dispute") || action.includes("refund") || action.includes("payment")) return "payments";
    if (action.includes("payout") || action.includes("balance") || action.includes("bank") || action.includes("funds")) return "payouts";
    if (action.includes("tax") || action.includes("document") || action.includes("statement")) return "documents";
    if (action.includes("support")) return "support";
    return "account";
}

function StripeComponentView(props: { scope: ScopeFixture; detail: DetailPageRequest; onBack: () => void }): JSX.Element {
    const component = () => stripeComponentKind(props.detail);
    const [completed, setCompleted] = createSignal(false);
    const [onboardingStep, setOnboardingStep] = createSignal(0);
    const title = () => ({
        onboarding: "Set up payments", notifications: "Account requirements", account: "Account details",
        payments: "Payments & disputes", payouts: "Balance & payouts", documents: "Documents", support: "Stripe support",
    } as const)[component()];
    return <>
        <button type="button" class="gaugeapp-back-link" onClick={props.onBack}>← Payments</button>
        <PageHeader eyebrow="Commercial Operations / Payments" title={title()} description={`${props.scope.label}'s connected financial account.`} />
        <div class="gaugeapp-stripe-owner-band"><span>Stripe</span><strong>Secure financial account</strong><small>Operated by Stripe · opened for {props.scope.label}</small></div>
        <section class="admin-section gaugeapp-stripe-component" data-component={component()}>
            <header><span>Stripe</span><strong>{title()}</strong><small>acct_…6P4C</small></header>
            <Show when={component() === "onboarding"}><>
                <div class="gaugeapp-stripe-progress"><span class="done">Business</span><span classList={{ done: onboardingStep() >= 1 }}>Representative</span><span classList={{ done: onboardingStep() >= 2 }}>Payout account</span></div>
                <Show when={onboardingStep() < 3} fallback={<div class="gaugeapp-stripe-complete"><strong>Details submitted</strong><small>Stripe is verifying the account. Charge and payout readiness will update here separately.</small><button type="button" onClick={props.onBack}>return to payments</button></div>}>
                    <Show when={onboardingStep() === 0}><div class="gaugeapp-stripe-fields"><label>Business type<select><option>Company</option><option>Individual</option><option>Nonprofit</option></select></label><label>Legal business name<input value={props.scope.label} /></label><label>Business website<input value="https://example.com" /></label><label>Customer support email<input type="email" value="support@example.com" /></label></div></Show>
                    <Show when={onboardingStep() === 1}><div class="gaugeapp-stripe-fields"><label>Representative name<input placeholder="Legal name" /></label><label>Role at the business<input placeholder="Owner, director…" /></label><label>Date of birth<input type="date" /></label><label>Home address<input placeholder="Street address" /></label></div></Show>
                    <Show when={onboardingStep() === 2}><div class="gaugeapp-stripe-fields"><label>Account holder<input value={props.scope.label} /></label><label>Routing number<input inputMode="numeric" placeholder="Routing number" /></label><label>Account number<input inputMode="numeric" placeholder="Account number" /></label><label>Payout schedule<select><option>Weekly · Monday</option><option>Daily</option><option>Monthly</option></select></label></div></Show>
                    <div class="gaugeapp-stripe-form-actions"><Show when={onboardingStep() > 0}><button class="tree-action" type="button" onClick={() => setOnboardingStep((step) => step - 1)}>back</button></Show><button type="button" onClick={() => setOnboardingStep((step) => step + 1)}>{onboardingStep() === 2 ? "submit to Stripe" : "continue"}</button></div>
                </Show>
            </></Show>
            <Show when={component() === "notifications"}><div class="gaugeapp-stripe-notification" classList={{ resolved: completed() }}>
                <span><strong>{completed() ? "Information submitted" : "Representative address required"}</strong><small>{completed() ? "Stripe is reviewing the update." : "Due Sep 3 · payouts can be restricted after the deadline"}</small></span>
                <button type="button" disabled={completed()} onClick={() => setCompleted(true)}>{completed() ? "submitted" : "provide information"}</button>
            </div></Show>
            <Show when={component() === "account"}><div class="gaugeapp-stripe-list">
                <div><span><strong>{props.scope.label}</strong><small>Company · United States</small></span><button type="button">edit business details</button></div>
                <div><span><strong>Customer-facing details</strong><small>Statement descriptor, website, and support contact</small></span><button type="button">edit public details</button></div>
                <div><span><strong>Account representative</strong><small>Verified · sensitive changes require Stripe authentication</small></span><button type="button">manage</button></div>
            </div></Show>
            <Show when={component() === "payments"}><div class="gaugeapp-stripe-list">
                <div><span><strong>$6,200.00 · succeeded</strong><small>Hearth & Wire · Aug 18</small></span><button type="button">view</button></div>
                <div><span><strong>$4,800.00 · succeeded</strong><small>Northstar Labs · Aug 16</small></span><button type="button">refund</button></div>
                <div class="warn"><span><strong>$760.00 · disputed</strong><small>Cosmos Design · evidence due Aug 29</small></span><button type="button">respond</button></div>
            </div></Show>
            <Show when={component() === "payouts"}><>
                <div class="gaugeapp-stripe-balance"><span><small>Available</small><strong>$2,340.00</strong></span><span><small>Pending</small><strong>$8,420.00</strong></span></div>
                <div class="gaugeapp-stripe-list"><div><span><strong>Operating account · 6789</strong><small>Automatic every Monday</small></span><button type="button">manage</button></div>
                    <div><span><strong>$8,420.00 expected Aug 24</strong><small>Next automatic payout</small></span><button type="button">view payouts</button></div></div>
            </></Show>
            <Show when={component() === "documents"}><div class="gaugeapp-stripe-list">
                <div><span><strong>July 2026 statement</strong><small>Payments, refunds, fees, and payouts</small></span><button type="button">download</button></div>
                <div><span><strong>2025 tax form</strong><small>No form issued</small></span><span class="badge">current</span></div>
            </div></Show>
            <Show when={component() === "support"}><div class="gaugeapp-stripe-complete"><strong>Stripe support</strong><small>Account verification, payments, refunds, disputes, reserves, and payout timing.</small><button type="button">contact Stripe</button></div></Show>
        </section>
        <p class="gaugeapp-stripe-boundary">GaugeDesk controls who may open this account session and links processor events to engagements. Information and actions inside this panel go directly to Stripe.</p>
    </>;
}

function DetailPageView(props: {
    scope: ScopeFixture;
    project: ProjectFixture;
    archetypes: Workspace["archetypes"];
    detail: DetailPageRequest;
    onBack: () => void;
    onNavigate: (app: GaugeAppId, tab: string, target?: InteractionTarget) => void;
    onProjectNavigate: (project: string, tab?: string) => void;
}): JSX.Element {
    const [status, setStatus] = createSignal("");
    const blueprint = () => detailBlueprint(props.detail, props.scope, props.project);
    const specialized = () => {
        const action = props.detail.action.toLowerCase();
        return (props.detail.kind === "organization-plan" && action === "change plan")
            || (props.detail.kind === "organization-seats" && action === "manage seats")
            || ((props.detail.kind === "provider-commercial" || props.detail.kind === "enterprise-controls") && action === "manage service")
            || (props.detail.kind === "provider-commercial" && action === "begin provider onboarding")
            || (props.detail.kind === "enterprise-controls" && action === "begin enterprise onboarding")
            || (props.detail.family === "sales-setup" && (action === "new product" || action === "edit product" || action === "view product"))
            || (props.detail.family === "offer" && action === "new proposal")
            || props.detail.family === "offer"
            || props.detail.family === "agreement"
            || props.detail.family === "stripe-connect";
    };
    const runCommand = (command: DetailCommand) => command.destination
        ? command.destination.projectId
            ? props.onProjectNavigate(command.destination.projectId, command.destination.tab)
            : props.onNavigate(command.destination.appId, command.destination.tab, command.destination.target)
        : setStatus(command.danger ? `${command.label} requires an explicit final confirmation in this prototype.` : `${command.label} would be submitted through the owning command.`);
    return <>
        <Show when={props.detail.family === "sales-setup" && (props.detail.action.toLowerCase() === "new product" || props.detail.action.toLowerCase() === "edit product")}>
            <ListingEditor detail={props.detail} archetypes={props.archetypes} onBack={props.onBack} />
        </Show>
        <Show when={props.detail.family === "sales-setup" && props.detail.action.toLowerCase() === "view product"}>
            <ProductDetailView detail={props.detail} onBack={props.onBack} onNavigate={props.onNavigate} />
        </Show>
        <Show when={props.detail.family === "offer"}>
            <ProposalEditor detail={props.detail} onBack={props.onBack} />
        </Show>
        <Show when={props.detail.family === "agreement"}>
            <EngagementDetailView detail={props.detail} onBack={props.onBack} onNavigate={props.onNavigate} />
        </Show>
        <Show when={props.detail.family === "stripe-connect"}>
            <StripeComponentView scope={props.scope} detail={props.detail} onBack={props.onBack} />
        </Show>
        <Show when={props.detail.family === "capability" && props.detail.kind === "enterprise-controls" && props.detail.action.toLowerCase() === "begin enterprise onboarding"}>
            <EnterpriseOnboardingFlow scope={props.scope} onBack={props.onBack} />
        </Show>
        <Show when={props.detail.kind === "organization-plan" && props.detail.action.toLowerCase() === "change plan"}>
            <OrganizationPlanChangeFlow scope={props.scope} onBack={props.onBack} />
        </Show>
        <Show when={props.detail.kind === "organization-seats" && props.detail.action.toLowerCase() === "manage seats"}>
            <OrganizationSeatFlow scope={props.scope} onBack={props.onBack} onNavigate={props.onNavigate} />
        </Show>
        <Show when={(props.detail.kind === "provider-commercial" || props.detail.kind === "enterprise-controls") && props.detail.action.toLowerCase() === "manage service"}>
            <OrganizationServiceFlow scope={props.scope} service={props.detail.kind === "provider-commercial" ? "commercial" : "enterprise"}
                onBack={props.onBack} onNavigate={props.onNavigate} />
        </Show>
        <Show when={props.detail.kind === "provider-commercial" && props.detail.action.toLowerCase() === "begin provider onboarding"}>
            <CommercialOnboardingFlow scope={props.scope} onBack={props.onBack} onNavigate={props.onNavigate} />
        </Show>
        <Show when={!specialized()}>
        <button type="button" class="gaugeapp-back-link" onClick={props.onBack}>← {props.detail.sourceLabel}</button>
        <PageHeader eyebrow={`${props.detail.sourceLabel} / ${props.detail.action}`} title={detailNavigationLabel(props.detail)}
            description={blueprint().description} />
        <DashboardGrid surface>
        <Show when={blueprint().notice}>{(notice) => <Notice tone="neutral">{notice()}</Notice>}</Show>
        <Show when={blueprint().metrics?.length}><div class="gaugeapp-metrics">
            <For each={blueprint().metrics}>{(metric) => <Metric label={metric.label} value={metric.value} note={metric.note} tone={metric.warn ? "warn" : undefined} />}</For>
        </div></Show>
        <For each={blueprint().sections}>{(section) => <section class="admin-section">
                <SectionHeading title={section.title} />
                <Show when={section.intro}><p class="gaugeapp-section-intro">{section.intro}</p></Show>
                <Show when={section.fields?.length}><div class="gaugeapp-field-grid">
                    <For each={section.fields}>{(field) => <label classList={{ "gaugeapp-field-span": field.wide }}>{field.label}
                        <Show when={field.options} fallback={<input value={field.value} readOnly={field.readOnly} />}>
                            {(options) => <select value={field.value} disabled={field.readOnly}><For each={options()}>{(option) => <option value={option}>{option}</option>}</For></select>}
                        </Show>
                    </label>}</For>
                </div></Show>
                <For each={section.rows}>{(row) => <Definition label={row.label} value={row.value} note={row.note} actions={row.actions} onAction={runCommand} />}</For>
            </section>}</For>
        <Show when={blueprint().commands.length}><section class="admin-section gaugeapp-detail-actions" aria-label="Page actions">
            <div class="bar"><For each={blueprint().commands}>{(command) => <button type="button" classList={{ "tree-action": true, "gaugeapp-danger-action": command.danger }}
                onClick={() => runCommand(command)}>{command.label}</button>}</For></div>
            <Show when={status()}><p class="status" role="status">{status()}</p></Show>
        </section></Show>
        </DashboardGrid>
        </Show>
    </>;
}

function FlowProgress(props: { steps: readonly string[]; current: number; onStep: (step: number) => void }): JSX.Element {
    return <ol class="gaugeapp-setup-steps" style={{ "grid-template-columns": `repeat(${props.steps.length}, minmax(0, 1fr))` }} aria-label="Progress">
        <For each={props.steps}>{(label, index) => <li classList={{ active: props.current === index(), done: props.current > index() }}>
            <button type="button" onClick={() => props.onStep(index())}><span>{index() + 1}</span>{label}</button>
        </li>}</For>
    </ol>;
}

function OrganizationPlanChangeFlow(props: { scope: ScopeFixture; onBack: () => void }): JSX.Element {
    const prototype = useContext(PrototypeOrganizationContext);
    const current = organizationSubscription(props.scope, prototype.get(props.scope.id));
    const steps = ["Plan", "Effects", "Review"] as const;
    const [step, setStep] = createSignal(0);
    const [selected, setSelected] = createSignal<OrganizationPlanId>(current.plan);
    const [seats, setSeats] = createSignal(current.purchasedSeats || 5);
    const [cadence, setCadence] = createSignal(current.cadence.startsWith("Annual") ? "Annual agreement · invoiced monthly" : "Monthly");
    const [confirmed, setConfirmed] = createSignal(false);
    const [completed, setCompleted] = createSignal(false);
    const [cancelling, setCancelling] = createSignal(false);
    const [cancelConfirmed, setCancelConfirmed] = createSignal(false);
    const [cancelled, setCancelled] = createSignal(false);
    const changing = () => selected() !== current.plan;
    const targetName = () => selected() === "managed" ? "Managed organization" : "Base organization";
    const effective = () => selected() === "managed" ? "Immediately after payment succeeds" : `At the end of the current term · ${current.renewal}`;
    const managedEstimate = () => `$${120 + (seats() * 20)}/month + usage`;
    const applyChange = () => {
        if (selected() === "managed") prototype.update(props.scope.id, { plan: "managed", purchasedSeats: seats(), scheduledPlan: null, scheduledSeats: null });
        else prototype.update(props.scope.id, { scheduledPlan: "base" });
        setCompleted(true);
    };
    const scheduleCancellation = () => {
        prototype.update(props.scope.id, { scheduledPlan: "base" });
        setCancelled(true);
    };

    return <Show when={!cancelling()} fallback={<>
        <Show when={!cancelled()} fallback={<>
            <button type="button" class="gaugeapp-back-link" onClick={props.onBack}>← Plans & services</button>
            <PageHeader eyebrow="Plans & services" title="Plan cancellation scheduled"
                description={`${current.name} will end on ${current.renewal}. The organization remains available on the Base organization plan.`} />
            <DashboardGrid surface>
            <Notice tone="neutral"><strong>No organization or project was deleted.</strong> Managed services stop only after their prerequisites are resolved and the current term ends.</Notice>
            <section class="admin-section"><SectionHeading title="Scheduled change" />
                <Definition label="Current plan" value={current.name} note={`active through ${current.renewal}`} />
                <Definition label="Next plan" value="Base organization" note="people, projects, policy, and self-managed operations remain" />
                <Definition label="Managed Home" value="Handoff required" note="the subscription cannot close while it remains authoritative for a project" />
            </section>
            <div class="bar"><button type="button" onClick={props.onBack}>return to Plans & services</button></div>
            </DashboardGrid>
        </>}>
            <button type="button" class="gaugeapp-back-link" onClick={() => setCancelling(false)}>← Change plan</button>
            <PageHeader eyebrow="Plans & services / cancellation" title={`End ${current.name}`}
                description="End paid organization services without deleting the organization or rewriting its work." />
            <DashboardGrid surface>
            <Notice tone="warn">The plan cannot finish until every project on the managed Home is handed off or exported. GaugeDesk will not move or delete one automatically.</Notice>
            <div class="gaugeapp-detail-grid">
                <section class="admin-section"><SectionHeading title="What stops" />
                    <Definition label="Managed Home" value="Stops after project handoff" note="Project Host lifecycle remains under Project Hosts" />
                    <Definition label="Cloud backup" value="Stops with the managed Home" note="download or replace recovery coverage first" />
                    <Definition label="Seat and model charges" value="Stop at term end" note="membership and provider policy remain separate" />
                </section>
                <section class="admin-section"><SectionHeading title="What remains" />
                    <Definition label="Organization" value="Active" note="identity, ownership, and history remain" />
                    <Definition label="People and projects" value="Unchanged" note="subject to each authoritative Home" />
                    <Definition label="Commercial records" value="Retained" note="service removal is managed independently" />
                </section>
            </div>
            <section class="admin-section gaugeapp-detail-actions"><SectionHeading title="Schedule cancellation" />
                <Definition label="Effective" value={current.renewal} note="end of the current agreement" />
                <label class="gaugeapp-check-row"><input type="checkbox" checked={cancelConfirmed()} onChange={(event) => setCancelConfirmed(event.currentTarget.checked)} />
                    <span><strong>I understand the managed Home must be handed off first</strong><small>Scheduling does not move projects or disable the Home today.</small></span></label>
                <div class="bar"><button type="button" class="gaugeapp-danger-action" disabled={!cancelConfirmed()} onClick={scheduleCancellation}>schedule cancellation</button></div>
            </section>
            </DashboardGrid>
        </Show>
    </>}>
        <Show when={!completed()} fallback={<>
            <button type="button" class="gaugeapp-back-link" onClick={props.onBack}>← Plans & services</button>
            <PageHeader eyebrow="Plans & services" title={selected() === "managed" ? "Managed organization activated" : "Plan change scheduled"}
                description={`${props.scope.label} will use ${targetName()}${selected() === "managed" ? "." : ` after ${current.renewal}.`}`} />
            <DashboardGrid surface>
            <Notice tone="neutral">Membership, roles, project access, and model-provider policy are unchanged.</Notice>
            <section class="admin-section"><SectionHeading title="Change record" />
                <Definition label="Previous" value={current.name} />
                <Definition label="New" value={targetName()} note={selected() === "managed" ? managedEstimate() : "$0 recurring plan charge"} />
                <Definition label="Effective" value={effective()} />
            </section>
            <div class="bar"><button type="button" onClick={props.onBack}>return to Plans & services</button></div>
            </DashboardGrid>
        </>}>
            <button type="button" class="gaugeapp-back-link" onClick={props.onBack}>← Plans & services</button>
            <PageHeader eyebrow="Plans & services / change plan" title={`Change ${current.name}`}
                description="Compare the available organization plans and review the operational and billing effects before applying a change." />
            <DashboardGrid surface>
            <FlowProgress steps={steps} current={step()} onStep={(next) => next <= step() && setStep(next)} />
            <Show when={step() === 0}><section class="admin-section"><SectionHeading title="Choose a plan" />
                <div class="gaugeapp-plan-choice-grid">
                    <button type="button" class="gaugeapp-plan-choice" classList={{ active: selected() === "base" }} onClick={() => setSelected("base")}>
                        <span><strong>Base organization</strong><small>{current.plan === "base" ? "current plan" : "$0 recurring plan charge"}</small></span>
                        <ul><li>Organization identity and ownership</li><li>People, projects, and policy</li><li>Self-managed Project Hosts</li></ul>
                    </button>
                    <button type="button" class="gaugeapp-plan-choice" classList={{ active: selected() === "managed" }} onClick={() => setSelected("managed")}>
                        <span><strong>Managed organization</strong><small>{current.plan === "managed" ? "current plan" : "$120/month + seats + usage"}</small></span>
                        <ul><li>Managed Cloud Home and backup</li><li>Purchased seat capacity</li><li>Managed model allowance</li></ul>
                    </button>
                </div>
                <Show when={current.plan === "managed"}><button type="button" class="gaugeapp-text-danger" onClick={() => setCancelling(true)}>review plan cancellation</button></Show>
            </section></Show>
            <Show when={step() === 1}><>
                <Show when={selected() === "managed"} fallback={<>
                    <Notice tone="warn">Moving to Base organization ends managed capacity at the current term. Projects remain where they are until an explicit Home handoff succeeds.</Notice>
                    <section class="admin-section"><SectionHeading title="Services ending" />
                        <Definition label="Managed Home" value={`${props.scope.label} Cloud Project Host`} note="handoff required before shutdown" />
                        <Definition label="Cloud backup" value="Daily · 30 days" note="retained through the effective date" />
                        <Definition label="Seat package" value={`${current.purchasedSeats} purchased`} note="membership and project access are unchanged" />
                    </section>
                </>}><section class="admin-section"><SectionHeading title="Capacity & billing" />
                    <div class="gaugeapp-field-grid"><label>Purchased seats<input type="number" min="1" value={seats()} onInput={(event) => setSeats(Math.max(1, Number(event.currentTarget.value)))} /></label>
                        <label>Billing cadence<select value={cadence()} onChange={(event) => setCadence(event.currentTarget.value)}><option>Monthly</option><option>Annual agreement · invoiced monthly</option></select></label></div>
                    <Definition label="Plan estimate" value={managedEstimate()} note="usage is estimated separately" />
                    <Definition label="Managed Home" value="One Cloud Home" note="existing projects are never moved automatically" />
                </section></Show>
            </></Show>
            <Show when={step() === 2}><>
                <Notice tone="neutral">A plan change affects service eligibility and future billing only. It does not assign seats, grant project access, or change organization roles.</Notice>
                <section class="admin-section"><SectionHeading title="Review change" />
                    <Definition label="From" value={current.name} note={current.cadence} />
                    <Definition label="To" value={targetName()} note={selected() === "managed" ? managedEstimate() : "$0 recurring plan charge"} />
                    <Definition label="Effective" value={effective()} />
                    <Show when={selected() === "managed"}><Definition label="Seats" value={`${seats()} purchased`} note="assignment remains in People" /></Show>
                    <Show when={selected() === "base"}><Definition label="Prerequisite" value="Managed Home handoff" note="the change remains scheduled until resolved" /></Show>
                </section>
                <section class="admin-section gaugeapp-detail-actions"><SectionHeading title="Confirm" />
                    <label class="gaugeapp-check-row"><input type="checkbox" checked={confirmed()} onChange={(event) => setConfirmed(event.currentTarget.checked)} />
                        <span><strong>I approve this organization plan change</strong><small>The effective date and estimated charge are shown above.</small></span></label>
                    <div class="bar"><button type="button" disabled={!confirmed()} onClick={applyChange}>{selected() === "managed" ? "apply plan change" : "schedule downgrade"}</button></div>
                </section>
            </></Show>
            <div class="gaugeapp-setup-navigation"><button type="button" class="tree-action" disabled={step() === 0} onClick={() => setStep((value) => Math.max(0, value - 1))}>back</button>
                <span>Step {step() + 1} of {steps.length}</span><button type="button" disabled={step() === steps.length - 1 || (step() === 0 && !changing())}
                    onClick={() => setStep((value) => Math.min(steps.length - 1, value + 1))}>next</button></div>
            </DashboardGrid>
        </Show>
    </Show>;
}

function OrganizationSeatFlow(props: { scope: ScopeFixture; onBack: () => void; onNavigate: (app: GaugeAppId, tab: string, target?: InteractionTarget) => void }): JSX.Element {
    const prototype = useContext(PrototypeOrganizationContext);
    const current = organizationSubscription(props.scope, prototype.get(props.scope.id));
    const [step, setStep] = createSignal(0);
    const [seats, setSeats] = createSignal(current.purchasedSeats);
    const [confirmed, setConfirmed] = createSignal(false);
    const [completed, setCompleted] = createSignal(false);
    const valid = () => seats() >= current.assignedSeats && seats() !== current.purchasedSeats;
    const delta = () => seats() - current.purchasedSeats;
    const timing = () => delta() > 0 ? "Immediately after confirmation" : `Next billing period · ${current.renewal}`;
    const applyChange = () => {
        prototype.update(props.scope.id, delta() > 0
            ? { purchasedSeats: seats(), scheduledSeats: null }
            : { scheduledSeats: seats() });
        setCompleted(true);
    };
    return <Show when={!completed()} fallback={<>
        <button type="button" class="gaugeapp-back-link" onClick={props.onBack}>← Plans & services</button>
        <PageHeader eyebrow="Plans & services" title="Seat change recorded"
            description={delta() > 0 ? `${props.scope.label} now has ${seats()} purchased seats.` : `${props.scope.label} will have ${seats()} purchased seats next period.`} />
        <DashboardGrid surface>
        <Notice tone="neutral">No seat was assigned by this change. People remains the assignment authority.</Notice>
        <section class="admin-section"><SectionHeading title="Capacity" />
            <Definition label="Purchased" value={`${seats()} seats`} />
            <Definition label="Assigned" value={`${current.assignedSeats} people`} note="unchanged" />
            <Definition label="Effective" value={timing()} />
        </section>
        <div class="bar"><button type="button" onClick={() => props.onNavigate("administration", "People & Access")}>open People</button><button type="button" class="tree-action" onClick={props.onBack}>return to plan</button></div>
        </DashboardGrid>
    </>}>
        <button type="button" class="gaugeapp-back-link" onClick={props.onBack}>← Plans & services</button>
        <PageHeader eyebrow="Plans & services / seat capacity" title="Manage seats" description="Change paid capacity without assigning people or changing their access." />
        <DashboardGrid surface>
        <FlowProgress steps={["Capacity", "Review"]} current={step()} onStep={(next) => next <= step() && setStep(next)} />
        <Show when={step() === 0}><>
            <div class="gaugeapp-metrics"><Metric label="Purchased" value={`${current.purchasedSeats}`} note="current capacity" /><Metric label="Assigned" value={`${current.assignedSeats}`} note="People" />
                <Metric label="Available" value={`${current.purchasedSeats - current.assignedSeats}`} note="unassigned" /><Metric label="Seat price" value="$20" note="per month" /></div>
            <section class="admin-section"><SectionHeading title="New capacity" />
                <div class="gaugeapp-field-grid"><label>Purchased seats<input type="number" min={current.assignedSeats} value={seats()} onInput={(event) => setSeats(Number(event.currentTarget.value))} /></label>
                    <label>Effective<input value={timing()} readOnly /></label></div>
                <Show when={seats() < current.assignedSeats}><p class="gaugeapp-inline-warning">Unassign {current.assignedSeats - seats()} seat{current.assignedSeats - seats() === 1 ? "" : "s"} in People before reducing capacity.</p></Show>
                <Definition label="New seat charge" value={`$${Math.max(0, seats()) * 20} / month`} note={delta() === 0 ? "no change" : `${delta() > 0 ? "+" : ""}${delta()} seat${Math.abs(delta()) === 1 ? "" : "s"}`} />
            </section>
        </></Show>
        <Show when={step() === 1}><>
            <section class="admin-section"><SectionHeading title="Review seat change" />
                <Definition label="Current" value={`${current.purchasedSeats} purchased · ${current.assignedSeats} assigned`} />
                <Definition label="New capacity" value={`${seats()} purchased · ${Math.max(0, seats() - current.assignedSeats)} available`} />
                <Definition label="New seat charge" value={`$${seats() * 20} / month`} />
                <Definition label="Effective" value={timing()} />
            </section>
            <section class="admin-section gaugeapp-detail-actions"><SectionHeading title="Confirm" />
                <label class="gaugeapp-check-row"><input type="checkbox" checked={confirmed()} onChange={(event) => setConfirmed(event.currentTarget.checked)} /><span><strong>I approve this capacity change</strong><small>Seat assignment remains unchanged.</small></span></label>
                <div class="bar"><button type="button" disabled={!confirmed()} onClick={applyChange}>apply seat change</button></div>
            </section>
        </></Show>
        <div class="gaugeapp-setup-navigation"><button type="button" class="tree-action" disabled={step() === 0} onClick={() => setStep(0)}>back</button>
            <span>Step {step() + 1} of 2</span><button type="button" disabled={step() === 1 || !valid()} onClick={() => setStep(1)}>review</button></div>
        </DashboardGrid>
    </Show>;
}

function OrganizationServiceFlow(props: { scope: ScopeFixture; service: "commercial" | "enterprise"; onBack: () => void; onNavigate: (app: GaugeAppId, tab: string, target?: InteractionTarget) => void }): JSX.Element {
    const prototype = useContext(PrototypeOrganizationContext);
    const current = organizationSubscription(props.scope, prototype.get(props.scope.id));
    const [removing, setRemoving] = createSignal(false);
    const [confirmed, setConfirmed] = createSignal(false);
    const [removed, setRemoved] = createSignal(false);
    const title = () => props.service === "commercial" ? "Commercial Operations" : "Enterprise controls";
    const configuration = () => props.service === "commercial" ? "Payments and payouts active" : "Identity setup available";
    const terms = () => props.service === "commercial" ? "Transaction-priced" : "Annual agreement · invoiced monthly";
    const open = () => props.service === "commercial"
        ? props.scope.commercialRole === null
            ? props.onNavigate("administration", "People & Access")
            : props.onNavigate("vend", "Products")
        : props.onNavigate("administration", "Identity");
    const scheduleRemoval = () => {
        prototype.update(props.scope.id, { scheduledServiceRemoval: props.service });
        setRemoved(true);
    };
    return <Show when={!removing()} fallback={<Show when={!removed()} fallback={<>
        <button type="button" class="gaugeapp-back-link" onClick={props.onBack}>← Plans & services</button>
        <PageHeader eyebrow="Plans & services" title={`${title()} removal scheduled`} description={`The service remains available through ${current.renewal}.`} />
        <DashboardGrid surface>
        <Notice tone="neutral">Historical records remain available. The organization plan, membership, and project access are unchanged.</Notice>
        <section class="admin-section"><Definition label="Service" value={title()} /><Definition label="Effective" value={current.renewal} />
            <Definition label="Status" value="Removal scheduled" /></section>
        <div class="bar"><button type="button" onClick={props.onBack}>return to Plans & services</button></div>
        </DashboardGrid>
    </>}>
        <button type="button" class="gaugeapp-back-link" onClick={() => setRemoving(false)}>← Manage {title()}</button>
        <PageHeader eyebrow="Plans & services / remove service" title={`Remove ${title()}`} description="Review the service-specific consequences before scheduling removal." />
        <DashboardGrid surface>
        <Notice tone="warn">{props.service === "commercial" ? "New proposals and charges stop at the effective date. Refund, dispute, balance, payout, and record access remain available while obligations settle." : "Disable SSO enforcement and confirm an alternate owner sign-in before this service can end."}</Notice>
        <div class="gaugeapp-detail-grid"><section class="admin-section"><SectionHeading title="What stops" />
            <Show when={props.service === "commercial"} fallback={<><Definition label="Corporate sign-in" value="SSO enforcement ends" /><Definition label="Provisioning" value="JIT and SCIM stop" /><Definition label="Enterprise software policy" value="Returns to base controls" /></>}>
                <Definition label="New commercial activity" value="New proposals and charges stop" /><Definition label="Client onboarding" value="Stops" /><Definition label="Processor connection" value="Closes after obligations settle" />
            </Show></section>
            <section class="admin-section"><SectionHeading title="What remains" />
                <Show when={props.service === "commercial"} fallback={<><Definition label="Members" value="Retained" note="SCIM removal does not delete history" /><Definition label="Projects" value="Unchanged" /><Definition label="Owner recovery" value="Required" /></>}>
                    <Definition label="Clients and engagements" value="Read-only history retained" /><Definition label="Refunds and disputes" value="Available" /><Definition label="Payout records" value="Available" />
                </Show></section></div>
        <section class="admin-section gaugeapp-detail-actions"><SectionHeading title="Schedule removal" />
            <Definition label="Effective" value={current.renewal} note="end of current terms" />
            <label class="gaugeapp-check-row"><input type="checkbox" checked={confirmed()} onChange={(event) => setConfirmed(event.currentTarget.checked)} /><span><strong>I understand the service-specific prerequisites</strong><small>Scheduling does not disable the service today.</small></span></label>
            <div class="bar"><button type="button" class="gaugeapp-danger-action" disabled={!confirmed()} onClick={scheduleRemoval}>schedule service removal</button></div>
        </section>
        </DashboardGrid>
    </Show>}>
        <button type="button" class="gaugeapp-back-link" onClick={props.onBack}>← Plans & services</button>
        <PageHeader eyebrow="Plans & services / active service" title={title()} description={`Manage ${title()} terms and open its operational controls.`} />
        <DashboardGrid surface>
        <div class="gaugeapp-metrics"><Metric label="Status" value="Active" note="organization service" /><Metric label="Terms" value={terms()} note="current agreement" />
            <Metric label="Configuration" value={configuration()} note={props.service === "commercial" ? "Stripe Connect" : "Enterprise Identity"} /><Metric label="Renews" value={current.renewal} note="with organization terms" /></div>
        <div class="gaugeapp-detail-grid"><section class="admin-section"><SectionHeading title="Service scope" />
            <Show when={props.service === "commercial"} fallback={<><Definition label="Single sign-on" value="OIDC or SAML" /><Definition label="Provisioning" value="JIT or SCIM" /><Definition label="Governance" value="Sessions and software admission" /></>}>
                <Definition label="Commercial records" value="Products, clients, and engagements" /><Definition label="Payments" value="Direct charges and invoices" /><Definition label="Money movement" value="Balances, payouts, refunds, and disputes" />
            </Show></section>
            <section class="admin-section"><SectionHeading title="Configuration" />
                <Show when={props.service === "commercial"} fallback={<><Definition label="Primary domain" value={scopeDomain(props.scope)} /><Definition label="Identity provider" value="Not configured" /><Definition label="Owner recovery" value="Available" /></>}>
                    <Definition label="Stripe account" value="Payments and payouts active" /><Definition label="Requirements" value="Nothing currently due" /><Definition label="Statement details" value="Configured" />
                </Show></section></div>
        <section class="admin-section gaugeapp-detail-actions"><SectionHeading title="Actions" />
            <div class="bar"><button type="button" onClick={open}>{props.service === "commercial"
                ? props.scope.commercialRole === null ? "manage commercial roles" : "open Commercial Operations"
                : "configure Enterprise Identity"}</button>
                <button type="button" class="gaugeapp-text-danger" onClick={() => setRemoving(true)}>review service removal</button></div>
        </section>
        </DashboardGrid>
    </Show>;
}

function CommercialOnboardingFlow(props: { scope: ScopeFixture; onBack: () => void; onNavigate: (app: GaugeAppId, tab: string, target?: InteractionTarget) => void }): JSX.Element {
    const prototype = useContext(PrototypeOrganizationContext);
    const steps = ["Service", "Business", "Review"] as const;
    const [step, setStep] = createSignal(0);
    const [confirmed, setConfirmed] = createSignal(false);
    const [active, setActive] = createSignal(false);
    const activate = () => {
        prototype.update(props.scope.id, { providerCommerce: "active", scheduledServiceRemoval: null });
        setActive(true);
    };
    return <Show when={!active()} fallback={<>
        <button type="button" class="gaugeapp-back-link" onClick={props.onBack}>← Plans & services</button>
        <PageHeader eyebrow="Commercial Operations" title="Commercial Operations is active" description={`${props.scope.label} can now configure products, clients, engagements, and payment processing.`} />
        <DashboardGrid surface>
        <Notice tone="neutral">Activation does not create a storefront, client entitlement, project grant, technical deployment, or Stripe account.</Notice>
        <section class="admin-section"><SectionHeading title="Processor standing" />
            <Definition label="Payment setup" value="Not started" note="complete from Commercial Operations / Payments" />
            <Definition label="Products and clients" value="Available now" note="payment setup is not required to prepare the catalog" />
        </section>
        <Show when={props.scope.commercialRole !== null} fallback={<>
            <Notice tone="neutral"><strong>Operational access is still role-gated.</strong> Assign a Commercial Operations role before opening products or engagements.</Notice>
            <div class="bar"><button type="button" onClick={() => props.onNavigate("administration", "People & Access")}>manage commercial roles</button><button type="button" class="tree-action" onClick={props.onBack}>finish for now</button></div>
        </>}><div class="bar"><button type="button" onClick={() => props.onNavigate("vend", "Products")}>open Commercial Operations</button><button type="button" class="tree-action" onClick={() => props.onNavigate("vend", "Payments")}>set up payments</button></div></Show>
        </DashboardGrid>
    </>}>
        <button type="button" class="gaugeapp-back-link" onClick={props.onBack}>← Plans & services</button>
        <PageHeader eyebrow="Commercial Operations / onboarding" title={`Add Commercial Operations to ${props.scope.label}`} description="Accept the service terms and confirm the business. Payment processing is configured separately when you are ready to collect money." />
        <DashboardGrid surface>
        <FlowProgress steps={steps} current={step()} onStep={(next) => next <= step() && setStep(next)} />
        <Show when={step() === 0}><section class="admin-section"><SectionHeading title="Service" />
            <Definition label="Commercial records" value="Products, clients, engagements, and payments" /><Definition label="Customer relationship" value={`${props.scope.label} remains merchant of record`} />
            <Definition label="Pricing" value="Transaction-priced" note="final fees are shown in the service order before activation" /><Definition label="Marketplace" value="Not included" note="the organization brings each client" />
        </section></Show>
        <Show when={step() === 1}><section class="admin-section"><SectionHeading title="Business" />
            <div class="gaugeapp-field-grid"><label>Legal business name<input value={props.scope.label} /></label><label>Country<select><option>United States</option></select></label>
                <label>Business type<select><option>Company</option><option>Individual</option><option>Nonprofit</option></select></label><label>Account representative<input value="Jack Scully" readOnly /></label></div>
        </section></Show>
        <Show when={step() === 2}><>
            <Notice tone="neutral">Payment readiness gates checkout and invoices, not the ability to prepare products, clients, and engagements.</Notice>
            <section class="admin-section"><SectionHeading title="Activation summary" />
                <Definition label="Organization" value={props.scope.label} /><Definition label="Service" value="Commercial Operations" note="transaction-priced" />
                <Definition label="Stripe" value="Set up later in Payments" note="required before collecting client money" /><Definition label="Authority" value="Owner and admitted commercial roles" />
            </section>
            <section class="admin-section gaugeapp-detail-actions"><SectionHeading title="Confirm" />
                <label class="gaugeapp-check-row"><input type="checkbox" checked={confirmed()} onChange={(event) => setConfirmed(event.currentTarget.checked)} /><span><strong>The service order is approved</strong><small>The organization remains merchant of record.</small></span></label>
                <div class="bar"><button type="button" disabled={!confirmed()} onClick={activate}>activate Commercial Operations</button></div>
            </section>
        </></Show>
        <div class="gaugeapp-setup-navigation"><button type="button" class="tree-action" disabled={step() === 0} onClick={() => setStep((value) => Math.max(0, value - 1))}>back</button>
            <span>Step {step() + 1} of {steps.length}</span><button type="button" disabled={step() === steps.length - 1}
                onClick={() => setStep((value) => Math.min(steps.length - 1, value + 1))}>next</button></div>
        </DashboardGrid>
    </Show>;
}

type ChargeKind = "setup" | "monthly" | "seat" | "cost-plus" | "one-time";
interface PrototypeCharge { readonly label: string; readonly calculation: string; readonly timing: string; readonly sample: string; }

/** Commerce is subordinate to Agent identity: one Agent may have one current
 * listing, with immutable listing revisions captured by proposals and agreements.
 * Never expose this authority boundary as explanatory UI copy.
 * Backend gap: current Vend has only a fixed-amount proposal and optional
 * deployment reference. It still needs Agent-linked listings, structured price
 * plans, agreements, recurring billing, and instantiated service commitments. */
interface AgentProductFixture {
    readonly name: string;
    readonly kind: "Agent" | "Panel agent";
    readonly agentId: string;
    readonly agentVersion: string;
    readonly salesRevision: string;
    readonly summary: string;
    readonly delivery: string;
    readonly versionPolicy: string;
    readonly pricing: string;
    readonly readiness: string;
    readonly obligations: readonly string[];
    readonly agreements: string;
}
interface AvailableAgentFixture {
    readonly id: string;
    readonly name: string;
    readonly kind: "Agent" | "Panel agent";
    readonly agentId: string;
    readonly agentVersion: string;
    readonly summary: string;
    readonly readiness: string;
    readonly headline: string;
    readonly listing: string;
    readonly delivery: string;
    readonly charges: readonly ChargeKind[];
    readonly obligations: readonly PrototypeObligation[];
}
interface PrototypeObligation { readonly label: string; readonly commitment: string; }

/** Prototype-only backend gap: a client needs reusable name/email recipients
 * and engagement-scoped proposal and billing assignments. Historical
 * commercial events retain immutable recipient snapshots. A saved recipient is
 * routing data, never GaugeDesk identity or project authority. */
type ClientContactPurpose = "proposal" | "billing";
interface ClientContactFixture {
    readonly name: string;
    readonly email: string;
    readonly purposes: readonly ClientContactPurpose[];
    readonly archived?: boolean;
}

const CLIENT_CONTACTS: Readonly<Record<string, readonly ClientContactFixture[]>> = {
    "Northstar Labs": [
        { name: "Priya Raman", email: "priya@northstar.example", purposes: ["proposal"] },
        { name: "Morgan Ellis", email: "morgan@northstar.example", purposes: ["proposal"] },
        { name: "Devon Lee", email: "devon@northstar.example", purposes: ["billing"] },
    ],
    "Hearth & Wire": [
        { name: "Ari Bell", email: "ari@hearth.example", purposes: ["proposal"] },
        { name: "Sam Okafor", email: "accounts@hearth.example", purposes: ["billing"] },
    ],
    "Cosmos Design": [
        { name: "Lena Ortiz", email: "lena@cosmos.example", purposes: ["proposal"] },
        { name: "Evan Park", email: "evan@cosmos.example", purposes: ["proposal"] },
        { name: "Accounts payable", email: "billing@cosmos.example", purposes: ["billing"] },
    ],
    "Brightworks Studio": [
        { name: "June Patel", email: "june@brightworks.example", purposes: ["proposal"], archived: true },
        { name: "Finance desk", email: "studio@brightworks.example", purposes: ["billing"], archived: true },
    ],
};

function clientContacts(client: string, purpose?: ClientContactPurpose): readonly ClientContactFixture[] {
    const match = Object.entries(CLIENT_CONTACTS).find(([name]) => client.includes(name));
    const contacts = match?.[1] ?? CLIENT_CONTACTS["Northstar Labs"]!;
    return purpose ? contacts.filter((contact) => contact.purposes.includes(purpose)) : contacts;
}

const AGENT_PRODUCTS: readonly AgentProductFixture[] = [
    {
        name: "Research Analyst", kind: "Panel agent", agentId: "agent_research_analyst", agentVersion: "v7", salesRevision: "sales r3",
        summary: "A research Panel for answering focused questions using approved sources.",
        delivery: "Dedicated customer Panel",
        versionPolicy: "Stable release channel, beginning with v7",
        pricing: "$2,000 setup · $400/month · $30/seat/month · usage cost + 15%",
        readiness: "Panel release v7 publishable",
        obligations: ["Onboarding within 5 business days", "Monthly source-configuration review"], agreements: "1 active agreement · 1 draft proposal",
    },
    {
        name: "Policy Desk", kind: "Panel agent", agentId: "agent_policy_desk", agentVersion: "v4", salesRevision: "sales r2",
        summary: "A policy Q&A Panel for a client's team.",
        delivery: "Access to the provider-hosted Policy Desk Panel",
        versionPolicy: "Stable release channel, beginning with v4",
        pricing: "$30/seat/month · usage cost + 15%",
        readiness: "Deployment panel:policy-desk healthy",
        obligations: ["Quarterly source review", "One-business-day support response"], agreements: "1 active agreement · 1 sent proposal",
    },
    {
        name: "Release Steward", kind: "Agent", agentId: "agent_release_steward", agentVersion: "v2", salesRevision: "sales r2",
        summary: "An Agent that keeps releases ready inside a customer project.",
        delivery: "Installed in one customer project",
        versionPolicy: "Stable update channel, beginning with v2",
        pricing: "$6,200/month",
        readiness: "Package v2 available for admission",
        obligations: ["Monthly release review", "Business-hours operator response"], agreements: "1 active agreement",
    },
    {
        name: "Architecture Advisor", kind: "Agent", agentId: "agent_architecture_advisor", agentVersion: "v4", salesRevision: "sales r4",
        summary: "An Agent for structured architecture reviews with expert follow-through.",
        delivery: "Installed in one customer project",
        versionPolicy: "Fixed v4 for each accepted proposal",
        pricing: "$4,800 once",
        readiness: "Package v4 available for admission",
        obligations: ["Two working sessions", "Written recommendation within 5 business days"], agreements: "1 completed agreement · 1 withdrawn proposal",
    },
] as const;

const AVAILABLE_AGENTS: readonly AvailableAgentFixture[] = [
    {
        id: "product-designer", name: "Product designer", kind: "Agent", agentId: "agent_product_designer", agentVersion: "v4",
        summary: "Turns product goals into clear flows, interfaces, and implementation-ready direction.", readiness: "Ready to list",
        headline: "Product direction from brief to build",
        listing: "Work through product direction, interaction design, and implementation-ready UI decisions inside the customer's project.",
        delivery: "Installed in one customer project", charges: ["setup", "monthly"],
        obligations: [
            { label: "Kickoff session", commitment: "One working session within 5 business days" },
            { label: "Monthly design review", commitment: "One product and interface review each month" },
        ],
    },
    {
        id: "operations-partner", name: "Operations partner", kind: "Agent", agentId: "agent_operations_partner", agentVersion: "v3",
        summary: "Helps a team organize recurring operating work and follow-through.", readiness: "Ready to list",
        headline: "An operations partner inside your project",
        listing: "Keep recurring operational work organized, prepare decisions, and follow through on the team's agreed process.",
        delivery: "Installed in one customer project", charges: ["monthly"],
        obligations: [
            { label: "Monthly operating review", commitment: "Review open work and operating cadence once per month" },
        ],
    },
    {
        id: "contract-reviewer", name: "Contract Reviewer", kind: "Agent", agentId: "agent_contract_reviewer", agentVersion: "v3",
        summary: "Reviews contracts against an approved playbook and produces traceable findings.", readiness: "Ready to list",
        headline: "Contract review with traceable findings",
        listing: "Review agreements against the client's approved playbook and deliver clear, traceable findings.",
        delivery: "Installed in one customer project", charges: ["setup", "monthly"],
        obligations: [
            { label: "Onboarding review", commitment: "Provider joins one setup session within 5 business days of project admission" },
            { label: "Playbook check-in", commitment: "Provider reviews configuration once per quarter while the agreement is active" },
        ],
    },
    {
        id: "support-desk", name: "Support Desk", kind: "Panel agent", agentId: "agent_support_desk", agentVersion: "Draft",
        summary: "Answers customer support questions using approved knowledge.", readiness: "Needs a published version",
        headline: "A support desk grounded in your approved knowledge",
        listing: "Give an authenticated client audience a focused support Panel backed by approved sources and an explicit escalation path.",
        delivery: "Dedicated customer Panel", charges: ["setup", "seat", "cost-plus"],
        obligations: [
            { label: "Launch review", commitment: "Provider validates sources and escalation routes before audience access is granted" },
            { label: "Monthly service report", commitment: "Provider delivers a monthly usage and unresolved-question report" },
        ],
    },
] as const;

const PROTOTYPE_CHARGES: Readonly<Record<ChargeKind, PrototypeCharge>> = {
    setup: { label: "Implementation", calculation: "$2,000 fixed", timing: "once · in advance", sample: "$2,000" },
    monthly: { label: "Managed service", calculation: "$400 fixed", timing: "monthly · in advance", sample: "$400 / month" },
    seat: { label: "Assigned access", calculation: "$30 × assigned seats", timing: "monthly · in advance", sample: "$360 / month at 12 seats" },
    "cost-plus": { label: "Model and compute", calculation: "actual usage cost + 15%", timing: "monthly · after use", sample: "based on usage" },
    "one-time": { label: "Fixed charge", calculation: "$4,800 fixed", timing: "once · on acceptance", sample: "$4,800" },
};

interface EditableCharge extends PrototypeCharge { readonly kind: ChargeKind; }

function editableCharge(kind: ChargeKind, change?: Partial<PrototypeCharge>): EditableCharge {
    return { kind, ...PROTOTYPE_CHARGES[kind], ...change };
}

function productCharges(source: AgentProductFixture | AvailableAgentFixture): readonly EditableCharge[] {
    if ("charges" in source) return source.charges.map((kind) => editableCharge(kind));
    if (source.name === "Research Analyst") return [editableCharge("setup"), editableCharge("monthly"), editableCharge("seat"), editableCharge("cost-plus")];
    if (source.name === "Policy Desk") return [editableCharge("seat"), editableCharge("cost-plus")];
    if (source.name === "Release Steward") return [editableCharge("monthly", { label: "Managed service", calculation: "$6,200 fixed", sample: "$6,200 / month" })];
    return [editableCharge("one-time")];
}

function productServices(source: AgentProductFixture | AvailableAgentFixture): readonly PrototypeObligation[] {
    if ("charges" in source) return source.obligations;
    if (source.name === "Research Analyst") return [
        { label: "Onboarding", commitment: "Complete setup within 5 business days of acceptance" },
        { label: "Source configuration", commitment: "Review the source configuration once per month" },
    ];
    if (source.name === "Policy Desk") return [
        { label: "Source review", commitment: "Review approved sources once per quarter" },
        { label: "Support response", commitment: "Respond within one business day" },
    ];
    if (source.name === "Release Steward") return [
        { label: "Release review", commitment: "Review release readiness once per month" },
        { label: "Operator response", commitment: "Respond during business hours" },
    ];
    return [
        { label: "Working sessions", commitment: "Provide two working sessions" },
        { label: "Written recommendation", commitment: "Deliver within 5 business days" },
    ];
}

function productDeliveryDefault(source: AgentProductFixture | AvailableAgentFixture): string {
    if (source.kind === "Panel agent") {
        return source.delivery.toLowerCase().includes("provider-hosted")
            ? "Access to a provider-hosted Panel"
            : "Dedicated customer Panel";
    }
    return source.delivery.toLowerCase().includes("named")
        ? "Installed in named customer projects"
        : "Installed in one customer project";
}

function ListingEditor(props: { detail: DetailPageRequest; archetypes: Workspace["archetypes"]; onBack: () => void }): JSX.Element {
    const editing = props.detail.action.toLowerCase() === "edit product";
    const existingProduct = editing ? AGENT_PRODUCTS.find((candidate) => props.detail.title.includes(candidate.name)) ?? AGENT_PRODUCTS[0]! : null;
    const requestedId = !existingProduct && AVAILABLE_AGENTS.some((agent) => agent.id === props.detail.kind) ? props.detail.kind! : null;
    const initialAgent = existingProduct ?? AVAILABLE_AGENTS.find((agent) => agent.id === requestedId) ?? null;
    const [agentId, setAgentId] = createSignal<string | null>(requestedId);
    const [choosingAgent, setChoosingAgent] = createSignal(!existingProduct && !initialAgent);
    const [title, setTitle] = createSignal(initialAgent ? ("headline" in initialAgent ? initialAgent.headline : initialAgent.name) : "");
    const [description, setDescription] = createSignal(initialAgent ? ("listing" in initialAgent ? initialAgent.listing : initialAgent.summary) : "");
    const [buyerAccess, setBuyerAccess] = createSignal("Anyone I send a proposal to");
    const [charges, setCharges] = createSignal<readonly EditableCharge[]>(initialAgent ? productCharges(initialAgent) : []);
    const [obligations, setObligations] = createSignal<readonly PrototypeObligation[]>(initialAgent ? productServices(initialAgent) : []);
    const [updates, setUpdates] = createSignal(initialAgent && "versionPolicy" in initialAgent && initialAgent.versionPolicy.includes("Fixed") ? "Deliver the accepted version" : "Keep customers on the current stable release");
    const [delivery, setDelivery] = createSignal(initialAgent ? productDeliveryDefault(initialAgent) : "");
    const [addingCharge, setAddingCharge] = createSignal(false);
    const [nextCharge, setNextCharge] = createSignal<ChargeKind>("one-time");
    const [addingObligation, setAddingObligation] = createSignal(false);
    const [nextObligation, setNextObligation] = createSignal("");
    const [nextCommitment, setNextCommitment] = createSignal("");
    const [status, setStatus] = createSignal("");
    const agent = () => existingProduct ?? AVAILABLE_AGENTS.find((candidate) => candidate.id === agentId())!;
    const hasAgent = () => Boolean(existingProduct || agentId());
    const example = () => charges().length ? charges().map((charge) => charge.sample).join(" · ") : "No default charges";
    const changeAgent = (next: string) => {
        const selected = AVAILABLE_AGENTS.find((candidate) => candidate.id === next)!;
        setAgentId(next);
        setTitle(selected.headline);
        setDescription(selected.listing);
        setCharges(productCharges(selected));
        setObligations(productServices(selected));
        setUpdates("Keep customers on the current stable release");
        setDelivery(productDeliveryDefault(selected));
        setChoosingAgent(false);
        setStatus("");
    };
    const addCharge = () => {
        if (!charges().some((charge) => charge.kind === nextCharge())) setCharges([...charges(), editableCharge(nextCharge())]);
        setAddingCharge(false);
    };
    const updateCharge = (kind: ChargeKind, change: Partial<EditableCharge>) => setCharges((current) => current.map((charge) => charge.kind === kind ? { ...charge, ...change } : charge));
    const updateObligation = (index: number, change: Partial<PrototypeObligation>) => setObligations((current) => current.map((obligation, position) => position === index ? { ...obligation, ...change } : obligation));
    const addObligation = () => {
        if (!nextObligation().trim() || !nextCommitment().trim()) return;
        setObligations([...obligations(), { label: nextObligation().trim(), commitment: nextCommitment().trim() }]);
        setNextObligation("");
        setNextCommitment("");
        setAddingObligation(false);
    };
    return <>
        <button type="button" class="gaugeapp-back-link" onClick={props.onBack}>← Products</button>
        <PageHeader eyebrow={`Commercial Operations / ${editing ? "Edit product" : "New product"}`} title={editing ? existingProduct!.name : "New product"}
            description={editing ? "Change the commercial defaults used for future proposals." : "Choose an Agent from Library, add the commercial defaults, and create the product."} />
        <DashboardGrid surface>
        <section class="admin-section gaugeapp-form-card">
            <SectionHeading title="Agent" meta={editing ? "Library · fixed for this product" : "Library"}
                action={!editing && agentId() && !choosingAgent() ? "change" : undefined} onAction={() => setChoosingAgent(true)} />
            <Show when={hasAgent() && !choosingAgent()} fallback={<LibraryArchetypePicker archetypes={props.archetypes} selectedId={agentId()} onChoose={changeAgent} />}>
                <SelectedLibraryArchetype archetype={props.archetypes.find((candidate) => candidate.name === agent().name)!} agent={agent()} />
            </Show>
        </section>
        <Show when={hasAgent()}><div class="gaugeapp-listing-editor-grid">
            <div class="gaugeapp-listing-editor-main">
                <section class="admin-section">
                    <SectionHeading title="Product details" />
                    <div class="gaugeapp-field-grid">
                        <label class="gaugeapp-field-span">Product title<input value={title()} onInput={(event) => setTitle(event.currentTarget.value)} /></label>
                        <label class="gaugeapp-field-span">Description<textarea value={description()} onInput={(event) => setDescription(event.currentTarget.value)} /></label>
                        <label>Who can buy<select value={buyerAccess()} onChange={(event) => setBuyerAccess(event.currentTarget.value)}><option>Anyone I send a proposal to</option><option>Selected clients only</option></select></label>
                    </div>
                </section>
                <section class="admin-section">
                    <SectionHeading title="Price" meta="USD" action={addingCharge() ? undefined : "add charge"} onAction={() => setAddingCharge(true)} />
                    <div class="gaugeapp-charge-stack"><For each={charges()}>{(charge) => <ChargeComponentRow charge={charge}
                        onChange={(change) => updateCharge(charge.kind, change)} onRemove={() => setCharges(charges().filter((candidate) => candidate.kind !== charge.kind))} />}</For></div>
                    <Show when={!charges().length}><p class="gaugeapp-empty-state">No default charges. Add at least one charge before saving.</p></Show>
                    <Show when={addingCharge()}><div class="gaugeapp-inline-composer"><label>Charge<select value={nextCharge()} onChange={(event) => setNextCharge(event.currentTarget.value as ChargeKind)}>
                        <option value="setup">Setup fee</option><option value="monthly">Monthly fee</option><option value="seat">Per seat, per month</option>
                        <option value="cost-plus">Usage cost + markup</option><option value="one-time">One-time price</option>
                    </select></label><div class="bar"><button class="tree-action" type="button" onClick={() => setAddingCharge(false)}>cancel</button><button type="button" onClick={addCharge}>add charge</button></div></div></Show>
                    <div class="gaugeapp-price-example"><span>Example</span><strong>{example()}</strong><small>Final quantities and discounts are set on each proposal.</small></div>
                </section>
            </div>
            <div class="gaugeapp-listing-editor-side">
                <section class="admin-section">
                    <SectionHeading title="Delivery" />
                    <Definition label="Agent form" value={agent().kind === "Panel agent" ? "Panel agent" : "Agent in a customer project"} note={agent().agentVersion} />
                    <div class="gaugeapp-field-grid">
                        <label>Release policy<select value={updates()} onChange={(event) => setUpdates(event.currentTarget.value)}><option>Keep customers on the current stable release</option><option>Deliver the accepted version</option></select></label>
                        <label>Customer receives<select value={delivery()} onChange={(event) => setDelivery(event.currentTarget.value)}><option>{agent().kind === "Panel agent" ? "Dedicated customer Panel" : "Installed in one customer project"}</option><option>{agent().kind === "Panel agent" ? "Access to a provider-hosted Panel" : "Installed in named customer projects"}</option></select></label>
                    </div>
                    <Show when={agent().agentVersion === "Draft"}><p class="gaugeapp-inline-warning">Publish a Panel version before creating this product.</p></Show>
                </section>
                <section class="admin-section">
                    <SectionHeading title="Services included" meta={`${obligations().length}`} action={addingObligation() ? undefined : "add service"} onAction={() => setAddingObligation(true)} />
                    <p class="gaugeapp-section-intro">Copied into each new proposal; existing agreements do not change.</p>
                    <div class="gaugeapp-obligation-stack"><For each={obligations()}>{(obligation, index) => <div class="gaugeapp-obligation-card gaugeapp-obligation-editor"><span>{index() + 1}</span><div>
                        <label>Service<input aria-label={`Service ${index() + 1} name`} value={obligation.label} onInput={(event) => updateObligation(index(), { label: event.currentTarget.value })} /></label>
                        <label>Commitment<input aria-label={`Service ${index() + 1} commitment`} value={obligation.commitment} onInput={(event) => updateObligation(index(), { commitment: event.currentTarget.value })} /></label>
                    </div><button class="tree-action" type="button" onClick={() => setObligations(obligations().filter((_, position) => position !== index()))}>remove</button></div>}</For></div>
                    <Show when={addingObligation()}><div class="gaugeapp-inline-composer"><label>Service name<input value={nextObligation()} onInput={(event) => setNextObligation(event.currentTarget.value)} placeholder="What is included" /></label><label>Commitment<input value={nextCommitment()} onInput={(event) => setNextCommitment(event.currentTarget.value)} placeholder="What the provider promises" /></label><div class="bar"><button class="tree-action" type="button" onClick={() => setAddingObligation(false)}>cancel</button><button type="button" disabled={!nextObligation().trim() || !nextCommitment().trim()} onClick={addObligation}>add service</button></div></div></Show>
                </section>
                <section class="admin-section gaugeapp-detail-actions"><SectionHeading title={editing ? "Save changes" : "Create product"} />
                    <div class="bar"><button class="tree-action" type="button" onClick={props.onBack}>cancel</button><Show when={!editing}><button class="tree-action" type="button" onClick={() => setStatus("Draft saved.")}>save draft</button></Show><button type="button"
                        disabled={agent().agentVersion === "Draft" || !title().trim() || !description().trim() || !charges().length}
                        title={agent().agentVersion === "Draft" ? "Publish a Panel version first" : !charges().length ? "Add at least one charge" : undefined}
                        onClick={() => setStatus(editing ? "Product changes saved for future proposals." : `${agent().name} is ready to use in proposals.`)}>{editing ? "save changes" : "create product"}</button></div>
                    <Show when={status()}><p class="status" role="status">{status()}</p></Show>
                </section>
            </div>
        </div></Show>
        </DashboardGrid>
    </>;
}

function LibraryArchetypePicker(props: { archetypes: Workspace["archetypes"]; selectedId: string | null; onChoose: (id: string) => void }): JSX.Element {
    const [query, setQuery] = createSignal("");
    const rows = createMemo(() => props.archetypes
        .filter((archetype) => !archetype.isDefault)
        .map((archetype) => ({ archetype, agent: AVAILABLE_AGENTS.find((candidate) => archetype.name === candidate.name), product: AGENT_PRODUCTS.find((candidate) => archetype.name === candidate.name) }))
        .filter((row) => row.agent || row.product)
        .filter((row) => `${row.archetype.name} ${row.archetype.kind}`.toLowerCase().includes(query().trim().toLowerCase())));
    return <div class="gaugeapp-library-picker">
        <input type="search" aria-label="Search Library" placeholder="Search Library…" value={query()} onInput={(event) => setQuery(event.currentTarget.value)} />
        <div class="gaugeapp-library-list"><For each={rows()}>{({ archetype, agent, product }) => {
            const record = () => agent ?? product!;
            return <button type="button" class="gaugeapp-library-row" classList={{ active: props.selectedId === agent?.id }} disabled={Boolean(product) || !agent}
                onClick={() => agent && props.onChoose(agent.id)}>
                <span class="gaugeapp-library-kind">{archetype.kind === "panel" ? "P" : "A"}</span>
                <span><strong>{archetype.name}</strong><small>{record().kind} · {record().agentVersion} · {record().summary}</small></span>
                <span class="badge">{product ? "product exists" : "select"}</span>
            </button>;
        }}</For></div>
        <Show when={!rows().length}><p class="gaugeapp-empty-state">No matching Agents.</p></Show>
    </div>;
}

function SelectedLibraryArchetype(props: { archetype: Workspace["archetypes"][number]; agent: Pick<AvailableAgentFixture, "name" | "kind" | "agentVersion" | "readiness"> }): JSX.Element {
    return <div class="gaugeapp-selected-archetype">
        <span class="gaugeapp-library-kind">{props.archetype.kind === "panel" ? "P" : "A"}</span>
        <span><strong>{props.archetype.name}</strong><small>{props.agent.kind} · {props.agent.agentVersion} · {props.agent.readiness}</small></span>
        <span class="badge">selected</span>
    </div>;
}

function agentProductFor(value: string | undefined): AgentProductFixture {
    return AGENT_PRODUCTS.find((agent) => value?.includes(agent.name)) ?? AGENT_PRODUCTS[0]!;
}

interface ProductActivityFixture {
    readonly state: "Active" | "Draft" | "Sent" | "Closed";
    readonly client: string;
    readonly reference: string;
    readonly value: string;
    readonly note: string;
    readonly action: string;
    readonly family: "offer" | "agreement";
}

function productActivity(agent: AgentProductFixture): readonly ProductActivityFixture[] {
    if (agent.name === "Research Analyst") return [
        { state: "Active", client: "Cosmos Design", reference: "AGR-1054", value: "$760/month + usage", note: "Deployment action needed", action: "manage engagement", family: "agreement" },
        { state: "Draft", client: "Cosmos Design", reference: "Proposal", value: "Revised deployment terms", note: "Not sent", action: "edit proposal", family: "offer" },
    ];
    if (agent.name === "Policy Desk") return [
        { state: "Active", client: "Northstar Labs", reference: "AGR-1051", value: "$360/month + usage", note: "12 assigned seats", action: "manage engagement", family: "agreement" },
        { state: "Sent", client: "Northstar Labs", reference: "Proposal", value: "Expanded audience", note: "Expires Sep 5", action: "view proposal", family: "offer" },
    ];
    if (agent.name === "Release Steward") return [
        { state: "Active", client: "Hearth & Wire", reference: "AGR-1048", value: "$6,200/month", note: "Current period through Sep 17", action: "manage engagement", family: "agreement" },
    ];
    return [
        { state: "Closed", client: "Brightworks Studio", reference: "AGR-1009", value: "$4,800 paid", note: "Completed Aug 7, 2026", action: "view record", family: "agreement" },
    ];
}

function ProductDetailView(props: {
    detail: DetailPageRequest;
    onBack: () => void;
    onNavigate: (app: GaugeAppId, tab: string, target?: InteractionTarget) => void;
}): JSX.Element {
    const agent = () => agentProductFor(props.detail.title);
    const activity = () => productActivity(agent());
    const active = () => activity().filter((item) => item.state === "Active").length;
    const open = () => activity().filter((item) => item.state === "Draft" || item.state === "Sent").length;
    const closed = () => activity().filter((item) => item.state === "Closed").length;
    const contracted = () => agent().name === "Research Analyst" ? "$760/month + usage"
        : agent().name === "Policy Desk" ? "$360/month + usage"
            : agent().name === "Release Steward" ? "$6,200/month" : "$4,800 completed";
    const openActivity = (item: ProductActivityFixture) => props.onNavigate("vend", "Engagements", {
        action: item.action,
        title: `${agent().name} · ${item.client}`,
        description: `${item.reference} · ${item.value}`,
        kind: item.family,
        meta: `${item.state} · ${item.note}`,
    });
    return <>
        <button type="button" class="gaugeapp-back-link" onClick={props.onBack}>← Products</button>
        <article class="gaugeapp-product-portrait">
            <header>
                <div class="gaugeapp-product-identity">
                    <span>{agent().kind} · {agent().agentVersion} · {agent().salesRevision}</span>
                    <h1>{agent().name}</h1>
                    <p>{agent().summary}</p>
                </div>
                <div class="gaugeapp-product-actions">
                    <button type="button" class="tree-action" onClick={() => props.onNavigate("vend", "Products", {
                        action: "edit product", title: agent().name, description: agent().summary, kind: agent().kind, meta: agent().agreements,
                    })}>edit</button>
                    <button type="button" onClick={() => props.onNavigate("vend", "Engagements", {
                        action: "new proposal", title: "New proposal for Northstar Labs", description: `Started from ${agent().name}.`, kind: agent().name,
                    })}>new proposal</button>
                </div>
            </header>
            <div class="gaugeapp-product-ledger">
                <span class="gaugeapp-product-price"><small>Contracted</small><strong>{contracted()}</strong><em>before metered usage</em></span>
                <span><small>Active</small><strong>{active()}</strong><em>accepted</em></span>
                <span><small>Open</small><strong>{open()}</strong><em>proposals</em></span>
                <span><small>Closed</small><strong>{closed()}</strong><em>retained</em></span>
            </div>
        </article>

        <section class="admin-section gaugeapp-product-terms"><SectionHeading title="Commercial terms" />
            <Definition label="Library Agent" value={`${agent().name} · ${agent().agentVersion}`} note={`${agent().kind} · ${agent().salesRevision}`} />
            <Definition label="Price" value={agent().pricing} />
            <Definition label="Delivery" value={agent().delivery} />
            <Definition label="Release" value={agent().versionPolicy} />
            <Definition label="Readiness" value={agent().readiness} />
        </section>

        <section class="admin-section"><SectionHeading title="Engagements" meta={`${activity().length} records`} action="view all" onAction={() => props.onNavigate("vend", "Engagements")} />
            <div class="gaugeapp-product-activity"><For each={activity()}>{(item) => <button type="button" data-state={item.state.toLowerCase()} onClick={() => openActivity(item)}>
                <span class="gaugeapp-product-activity-state">{item.state}</span>
                <span><strong>{item.client}</strong><small>{item.reference} · {item.note}</small></span>
                <span><strong>{item.value}</strong><small>{item.action}</small></span>
                <span aria-hidden="true">›</span>
            </button>}</For></div>
            <Show when={!closed()}><p class="gaugeapp-quiet-empty">No closed engagements.</p></Show>
        </section>

        <section class="admin-section"><SectionHeading title="Services included" meta={`${agent().obligations.length}`} />
            <ol class="gaugeapp-service-register"><For each={agent().obligations}>{(obligation) => <li><span>{obligation}</span></li>}</For></ol>
        </section>
    </>;
}

function ChargeComponentRow(props: { charge: EditableCharge; onChange: (change: Partial<EditableCharge>) => void; onRemove: () => void }): JSX.Element {
    return <div class="gaugeapp-charge-row gaugeapp-charge-editor">
        <label>Charge name<input aria-label={`${props.charge.label} charge name`} value={props.charge.label} onInput={(event) => props.onChange({ label: event.currentTarget.value })} /></label>
        <label>Calculation<input aria-label={`${props.charge.label} calculation`} value={props.charge.calculation} onInput={(event) => props.onChange({ calculation: event.currentTarget.value, sample: event.currentTarget.value })} /></label>
        <label>When charged<input aria-label={`${props.charge.label} timing`} value={props.charge.timing} onInput={(event) => props.onChange({ timing: event.currentTarget.value })} /></label>
        <button type="button" class="tree-action" onClick={props.onRemove}>remove</button></div>;
}

function ProposalEditor(props: { detail: DetailPageRequest; onBack: () => void }): JSX.Element {
    const creating = props.detail.action.toLowerCase() === "new proposal";
    const saved = creating ? null : engagementFixture(props.detail);
    const requestedClient = props.detail.title.replace("New proposal for ", "");
    const initialClient = saved?.client ?? (CLIENT_CONTACTS[requestedClient] ? requestedClient : "Northstar Labs");
    const initialAgent = saved?.agent ?? agentProductFor(props.detail.kind);
    const originalRecipient = saved?.proposalRecipient.split(" · ")[0];
    const originalStage = saved?.stage ?? "Draft";
    const [stage, setStage] = createSignal<EngagementFixture["stage"]>(originalStage);
    const [editing, setEditing] = createSignal(creating || originalStage === "Draft");
    const [clientName, setClientName] = createSignal(initialClient);
    const [agentName, setAgentName] = createSignal(initialAgent.name);
    const [price, setPrice] = createSignal(initialAgent.pricing);
    const [seats, setSeats] = createSignal(12);
    const [term, setTerm] = createSignal(saved?.term.startsWith("One-time") ? "One-time" : "12 months");
    const [starts, setStarts] = createSignal("On acceptance");
    const [startDate, setStartDate] = createSignal("2026-09-15");
    const [validThrough, setValidThrough] = createSignal("2026-09-05");
    const [renewal, setRenewal] = createSignal(saved?.term.includes("renews") ? "Renews monthly after initial term" : "Does not renew");
    const [payment, setPayment] = createSignal("Net 30 invoice");
    const [notes, setNotes] = createSignal("Includes the product and services listed below.");
    const [recipients, setRecipients] = createSignal(
        originalRecipient ? [originalRecipient] : clientContacts(initialClient, "proposal").map((contact) => contact.name),
    );
    const [billingContact, setBillingContact] = createSignal(clientContacts(initialClient, "billing")[0]?.name ?? "");
    const [status, setStatus] = createSignal("");
    const [confirmingDiscard, setConfirmingDiscard] = createSignal(false);
    const [confirmingWithdraw, setConfirmingWithdraw] = createSignal(false);
    const agent = () => agentProductFor(agentName());
    const contacts = () => clientContacts(clientName());
    const recipientSummary = () => recipients().map((name) => {
        const contact = contacts().find((candidate) => candidate.name === name);
        return contact ? `${contact.name} · ${contact.email}` : name;
    }).join(", ");
    const billingSummary = () => {
        const contact = contacts().find((candidate) => candidate.name === billingContact());
        return contact ? `${contact.name} · ${contact.email}` : billingContact();
    };
    const chooseClient = (nextClient: string) => {
        setClientName(nextClient);
        setRecipients(clientContacts(nextClient, "proposal").map((contact) => contact.name));
        setBillingContact(clientContacts(nextClient, "billing")[0]?.name ?? "");
    };
    const chooseProduct = (nextAgent: string) => {
        setAgentName(nextAgent);
        setPrice(agentProductFor(nextAgent).pricing);
    };
    const toggleRecipient = (contact: string, selected: boolean) => setRecipients(selected
        ? [...recipients(), contact]
        : recipients().filter((candidate) => candidate !== contact));
    const sendProposal = () => {
        const sendingRevision = stage() === "Awaiting client";
        setStage("Awaiting client");
        setEditing(false);
        setStatus(`${sendingRevision ? "Revision" : "Proposal"} sent to ${recipients().length} recipient${recipients().length === 1 ? "" : "s"}.`);
    };
    const newDraft = () => creating && stage() === "Draft";
    const editableActions = () => stage() === "Awaiting client" ? "Revision" : "Draft";
    return <>
        <button type="button" class="gaugeapp-back-link" onClick={props.onBack}>← Engagements</button>
        <PageHeader eyebrow={`Commercial Operations / ${newDraft() ? "New proposal" : stage()}`}
            title={`${editing() ? newDraft() ? "New proposal" : "Edit proposal" : "Proposal"} · ${clientName()}`}
            description={editing() ? "Set the commercial terms, recipients, and commitment in one document." : `${agent().name} · ${saved?.reference ?? "proposal"}`} />

        <div class="gaugeapp-proposal-status" data-stage={stage().toLowerCase().replace(" ", "-")}>
            <span><small>Status</small><strong>{stage()}</strong></span>
            <span><small>Revision</small>{saved?.agent.salesRevision ?? "New draft"}</span>
            <span><small>Valid through</small>{validThrough()}</span>
        </div>

        <section class="admin-section gaugeapp-proposal-primary">
            <SectionHeading title="Commercial terms" meta={editing() ? "editable" : saved?.agent.salesRevision} />
            <Show when={editing()} fallback={<div class="gaugeapp-proposal-readback">
                <Definition label="Client" value={clientName()} />
                <Definition label="Product" value={agent().name} note={`${agent().kind} · ${agent().agentVersion}`} />
                <Definition label="Price" value={price()} note={agent().kind === "Panel agent" ? `${seats()} seats in estimate` : undefined} />
                <Definition label="Term" value={`${term()} · ${starts() === "Specific date" ? `starts ${startDate()}` : "on acceptance"}${term() === "One-time" ? "" : ` · ${renewal().toLowerCase()}`}`} />
                <Definition label="Payment" value={payment()} />
            </div>}>
                <div class="gaugeapp-field-grid">
                    <label>Client<select value={clientName()} onChange={(event) => chooseClient(event.currentTarget.value)}><option>Northstar Labs</option><option>Hearth & Wire</option><option>Cosmos Design</option></select></label>
                    <label>Product<select value={agentName()} onChange={(event) => chooseProduct(event.currentTarget.value)}><For each={AGENT_PRODUCTS}>{(candidate) => <option>{candidate.name}</option>}</For></select></label>
                    <label class="gaugeapp-field-span">Price and billing<input value={price()} onInput={(event) => setPrice(event.currentTarget.value)} /></label>
                    <Show when={agent().kind === "Panel agent"}><label>Seats in estimate<input type="number" min="1" value={seats()} onInput={(event) => setSeats(Number(event.currentTarget.value))} /></label></Show>
                    <label>Term<select value={term()} onChange={(event) => setTerm(event.currentTarget.value)}><option>12 months</option><option>Month to month</option><option>One-time</option></select></label>
                    <label>Starts<select value={starts()} onChange={(event) => setStarts(event.currentTarget.value)}><option>On acceptance</option><option>Specific date</option></select></label>
                    <Show when={starts() === "Specific date"}><label>Start date<input type="date" value={startDate()} onInput={(event) => setStartDate(event.currentTarget.value)} /></label></Show>
                    <label>Proposal valid through<input type="date" value={validThrough()} onInput={(event) => setValidThrough(event.currentTarget.value)} /></label>
                    <Show when={term() !== "One-time"}><label>Renewal<select value={renewal()} onChange={(event) => setRenewal(event.currentTarget.value)}><option>Renews monthly after initial term</option><option>Renews annually</option><option>Does not renew</option></select></label></Show>
                    <label>Payment terms<select value={payment()} onChange={(event) => setPayment(event.currentTarget.value)}><option>Net 30 invoice</option><option>Pay on acceptance</option><option>Monthly automatic payment</option></select></label>
                </div>
            </Show>
        </section>

        <section class="admin-section">
            <SectionHeading title="Recipients" meta={editing() ? `${contacts().length} saved for ${clientName()}` : undefined} />
            <Show when={editing()} fallback={<>
                <Definition label="Proposal to" value={recipientSummary()} />
                <Definition label="Invoices to" value={billingSummary()} note="used if this proposal is accepted" />
            </>}>
                <div class="gaugeapp-contact-assignment-grid">
                    <div class="gaugeapp-contact-choices" role="group" aria-label="Proposal recipients"><span>Proposal recipients</span>
                        <For each={contacts().filter((contact) => contact.purposes.includes("proposal"))}>{(contact) => <label class="gaugeapp-contact-choice">
                            <input type="checkbox" checked={recipients().includes(contact.name)} onChange={(event) => toggleRecipient(contact.name, event.currentTarget.checked)} />
                            <span><strong>{contact.name}</strong><small>{contact.email}</small></span>
                        </label>}</For>
                    </div>
                    <label>Invoice recipient<select value={billingContact()} onChange={(event) => setBillingContact(event.currentTarget.value)}>
                        <For each={contacts().filter((contact) => contact.purposes.includes("billing"))}>{(contact) => <option value={contact.name}>{contact.name} · {contact.email}</option>}</For>
                    </select></label>
                </div>
            </Show>
        </section>

        <section class="admin-section">
            <SectionHeading title="Client receives" meta={agent().agentVersion} />
            <Definition label={agent().name} value={agent().delivery} note={agent().versionPolicy} />
            <For each={agent().obligations}>{(obligation) => <Definition label="Included service" value={obligation} />}</For>
            <Show when={editing()} fallback={<Definition label="Client note" value={notes()} />}>
                <label class="gaugeapp-proposal-note">Client note<textarea value={notes()} onInput={(event) => setNotes(event.currentTarget.value)} /></label>
            </Show>
        </section>

        <Show when={stage() !== "Draft"}><section class="admin-section gaugeapp-engagement-activity">
            <SectionHeading title="Activity" />
            <Definition label={stage() === "Awaiting client" ? "Aug 24" : stage() === "Withdrawn" ? "Jun 4" : "Aug 23"}
                value={stage() === "Awaiting client" ? "Proposal sent" : stage() === "Withdrawn" ? "Proposal withdrawn" : "Draft created"}
                note={stage() === "Awaiting client" ? recipientSummary() : saved?.agent.salesRevision} />
        </section></Show>

        <Show when={editing() || stage() === "Awaiting client"}>
            <section class="admin-section gaugeapp-detail-actions"><SectionHeading title={editing() ? editableActions() : "Proposal actions"} />
                <div class="bar"><Show when={editing()} fallback={<>
                    <button type="button" class="tree-action gaugeapp-danger-action" onClick={() => setConfirmingWithdraw(true)}>withdraw</button>
                    <button type="button" class="tree-action" onClick={() => { setEditing(true); setStatus(""); }}>edit proposal</button>
                    <button type="button" onClick={() => setStatus(`Proposal resent to ${recipients().length} recipient${recipients().length === 1 ? "" : "s"}.`)}>resend</button>
                </>}>
                    <Show when={!creating}><button type="button" class="tree-action" onClick={() => { setEditing(false); setStatus(""); }}>cancel</button></Show>
                    <Show when={stage() === "Draft"}><button type="button" class="tree-action gaugeapp-danger-action" onClick={() => setConfirmingDiscard(true)}>discard draft</button></Show>
                    <button type="button" class="tree-action" onClick={() => setStatus(stage() === "Awaiting client" ? "Revision saved." : "Draft saved.")}>save</button>
                    <button type="button" disabled={!recipients().length} title={!recipients().length ? "Choose at least one proposal recipient" : undefined} onClick={sendProposal}>{stage() === "Awaiting client" ? "send revision" : "send proposal"}</button>
                </Show></div>
                <Show when={confirmingDiscard()}><div class="gaugeapp-danger-review"><strong>Discard this draft?</strong><p>The draft is removed; no engagement, billing instruction, deployment, or entitlement exists.</p><div class="bar"><button type="button" class="tree-action" onClick={() => setConfirmingDiscard(false)}>keep editing</button><button type="button" class="gaugeapp-danger-action" onClick={() => { setConfirmingDiscard(false); setStatus("Draft discarded."); }}>discard draft</button></div></div></Show>
                <Show when={confirmingWithdraw()}><div class="gaugeapp-danger-review"><strong>Withdraw this proposal?</strong><p>The client can no longer accept this revision. Its commercial history remains available.</p><div class="bar"><button type="button" class="tree-action" onClick={() => setConfirmingWithdraw(false)}>cancel</button><button type="button" class="gaugeapp-danger-action" onClick={() => { setConfirmingWithdraw(false); setStage("Withdrawn"); setStatus("Proposal withdrawn."); }}>withdraw proposal</button></div></div></Show>
                <Show when={status()}><p class="status" role="status">{status()}</p></Show>
            </section>
        </Show>
    </>;
}

interface EngagementFixture {
    readonly agent: AgentProductFixture;
    readonly client: string;
    readonly reference: string;
    readonly stage: "Draft" | "Awaiting client" | "Active" | "Setup required" | "Closed" | "Withdrawn";
    readonly accepted: string;
    readonly term: string;
    readonly proposalRecipient: string;
    readonly billingRecipient: string;
    readonly fulfillmentKind: "panel" | "placement";
    readonly fulfillmentReference?: string;
    readonly fulfillmentLabel?: string;
    readonly entitlement: "none" | "active" | "closed";
    readonly runtime: string;
    readonly billingState: string;
    readonly metering: string;
}

function engagementFixture(detail: DetailPageRequest): EngagementFixture {
    const agent = agentProductFor(detail.title);
    if (agent.name === "Research Analyst") return {
        agent, client: "Cosmos Design", reference: detail.family === "offer" ? "Proposal draft" : "AGR-1054",
        stage: detail.family === "offer" ? "Draft" : "Setup required", accepted: detail.family === "offer" ? "Not accepted" : "Aug 20, 2026",
        term: "12 months · renews monthly", proposalRecipient: "Lena Ortiz · lena@cosmos.example",
        billingRecipient: "Accounts payable · billing@cosmos.example", fulfillmentKind: "panel", entitlement: "none",
        runtime: "No runtime evidence until a deployment is linked", billingState: "$2,000 invoice open · recurring schedule waiting",
        metering: "No deployment reference · usage cannot be reconciled",
    };
    if (agent.name === "Policy Desk") return {
        agent, client: "Northstar Labs", reference: detail.family === "offer" ? "Proposal sent" : "AGR-1051",
        stage: detail.family === "offer" ? "Awaiting client" : "Active", accepted: detail.family === "offer" ? "Not accepted" : "Aug 12, 2026",
        term: "12 months · renews monthly", proposalRecipient: "Priya Raman · priya@northstar.example",
        billingRecipient: "Devon Lee · devon@northstar.example", fulfillmentKind: "panel",
        fulfillmentReference: "panel:policy-desk", fulfillmentLabel: "Policy Desk customer Panel", entitlement: "active",
        runtime: "Healthy · release v4 · 18 sessions this period", billingState: "$360 August charge paid · next invoice Sep 12",
        metering: "42,180 model tokens · matched to panel:policy-desk",
    };
    if (agent.name === "Release Steward") return {
        agent, client: "Hearth & Wire", reference: "AGR-1048", stage: "Active", accepted: "Aug 18, 2026",
        term: "12 months · renews monthly", proposalRecipient: "Ari Bell · ari@hearth.example",
        billingRecipient: "Sam Okafor · accounts@hearth.example", fulfillmentKind: "placement",
        fulfillmentReference: "placement:release-steward:v2", fulfillmentLabel: "Release Steward in customer project", entitlement: "active",
        runtime: "Available · release v2 · last admitted run 3 hours ago", billingState: "$6,200 August charge paid · next invoice Sep 18",
        metering: "No usage-priced charge in accepted terms",
    };
    return {
        agent, client: "Brightworks Studio", reference: detail.family === "offer" ? "Withdrawn proposal" : "AGR-1009",
        stage: detail.family === "offer" ? "Withdrawn" : "Closed", accepted: detail.family === "offer" ? "Never accepted" : "Jul 18, 2026",
        term: "One-time", proposalRecipient: "June Patel · june@brightworks.example",
        billingRecipient: "Finance desk · studio@brightworks.example", fulfillmentKind: "placement",
        fulfillmentReference: "placement:architecture-advisor:v4", fulfillmentLabel: "Architecture Advisor in customer project", entitlement: "closed",
        runtime: "Placement closed · last evidence Aug 7", billingState: "$4,800 paid · no balance due",
        metering: "No usage-priced charge in accepted terms",
    };
}

function EngagementDetailView(props: {
    detail: DetailPageRequest;
    onBack: () => void;
    onNavigate: (app: GaugeAppId, tab: string, target?: InteractionTarget) => void;
}): JSX.Element {
    const fixture = () => engagementFixture(props.detail);
    const [linking, setLinking] = createSignal(false);
    const [linkedReference, setLinkedReference] = createSignal(fixture().fulfillmentReference ?? "");
    const [linkedLabel, setLinkedLabel] = createSignal(fixture().fulfillmentLabel ?? "");
    const [entitlement, setEntitlement] = createSignal<EngagementFixture["entitlement"]>(fixture().entitlement);
    const [closed, setClosed] = createSignal(fixture().stage === "Closed");
    const [message, setMessage] = createSignal("");
    const [confirmingClose, setConfirmingClose] = createSignal(false);
    const fulfillmentReady = () => Boolean(linkedReference());
    const engagementState = () => closed() ? "Closed"
        : entitlement() === "active" ? "Active"
            : entitlement() === "closed" ? "Access closed"
                : fulfillmentReady() ? "Access required" : fixture().stage;
    const runtimeEvidence = () => fixture().fulfillmentReference
        ? fixture().runtime
        : fulfillmentReady() ? "Linked · awaiting first deployment report" : "Unavailable";
    const linkFulfillment = () => {
        const isPanel = fixture().fulfillmentKind === "panel";
        setLinkedReference(isPanel ? "panel:research-cosmos" : "placement:customer-project");
        setLinkedLabel(isPanel ? "Research Analyst customer Panel" : `${fixture().agent.name} in customer project`);
        setLinking(false);
        setMessage("Deployment linked. Client access remains inactive until it is admitted separately.");
    };
    return <>
        <button type="button" class="gaugeapp-back-link" onClick={props.onBack}>← Engagements</button>
        <PageHeader eyebrow="Commercial Operations / Engagement" title={`${fixture().agent.name} · ${fixture().client}`}
            description={`${fixture().reference} · accepted ${fixture().accepted}`}
            actions={<Show when={!closed()}><button type="button" class="tree-action gaugeapp-danger-action" onClick={() => setConfirmingClose(true)}>close engagement</button></Show>} />
        <div class="gaugeapp-metrics gaugeapp-engagement-metrics">
            <Metric label="State" value={engagementState()} note={fixture().reference} tone={engagementState() === "Setup required" || engagementState() === "Access required" ? "warn" : undefined} />
            <Metric label="Product" value={fixture().agent.name} note={`${fixture().agent.agentVersion} · ${fixture().agent.salesRevision}`} />
            <Metric label="Deployment" value={fulfillmentReady() ? linkedLabel() : "Not linked"}
                note={fulfillmentReady() ? linkedReference() : "action required"} tone={!fulfillmentReady() ? "warn" : undefined} />
            <Metric label="Billing" value={fixture().billingState.split(" · ")[0]!} note={fixture().billingState.split(" · ").slice(1).join(" · ")} />
        </div>

        <Show when={confirmingClose()}><div class="gaugeapp-danger-review gaugeapp-engagement-close-review"><strong>Close this engagement?</strong><p>Future billing instructions stop. Client access is separate and must be revoked explicitly if it remains active. The accepted agreement, deployment evidence, and processor records remain.</p><div class="bar"><button type="button" class="tree-action" onClick={() => setConfirmingClose(false)}>cancel</button><button type="button" class="gaugeapp-danger-action" onClick={() => { setConfirmingClose(false); setClosed(true); setMessage("Engagement closed; its history and technical evidence were retained."); }}>close engagement</button></div></div></Show>

        <section class="admin-section gaugeapp-engagement-operation" data-tone={!fulfillmentReady() ? "warn" : "neutral"}>
            <SectionHeading title="Deployment & client access" meta={fulfillmentReady() ? entitlement() === "active" ? "available" : "deployment linked" : "next action"} />
            <Definition label="Expected form" value={fixture().agent.delivery} note={fixture().fulfillmentKind === "panel" ? "Panel deployment" : "project Agent placement"} />
            <Definition label="Release" value={fixture().agent.agentVersion} note={fixture().agent.versionPolicy} />
            <Definition label="Deployment" value={fulfillmentReady() ? linkedLabel() : "Not linked"}
                note={fulfillmentReady() ? linkedReference() : "Choose the exact Panel or project placement that fulfills this engagement."} />
            <Definition label="Client access" value={entitlement() === "active" ? "Active" : entitlement() === "closed" ? "Revoked" : "Not active"}
                note="Admitted separately from payment and deployment state" />
            <Definition label="Runtime" value={runtimeEvidence()} note={fulfillmentReady() ? "reported by the linked deployment" : "available after a deployment is linked"} />
            <Show when={!closed() && !fulfillmentReady() && !linking()}><div class="bar"><button type="button" onClick={() => setLinking(true)}>link deployment</button></div></Show>
            <Show when={!closed() && linking()}><div class="gaugeapp-inline-composer"><label>{fixture().fulfillmentKind === "panel" ? "Panel deployment" : "Agent placement"}<select>
                <option>{fixture().fulfillmentKind === "panel" ? `Create customer Panel from ${fixture().agent.name} ${fixture().agent.agentVersion}` : `Link admitted ${fixture().agent.name} placement`}</option>
                <option>{fixture().fulfillmentKind === "panel" ? "Choose an existing Panel deployment" : "Choose another project placement"}</option>
            </select></label><div class="bar"><button type="button" class="tree-action" onClick={() => setLinking(false)}>cancel</button><button type="button" onClick={linkFulfillment}>link</button></div></div></Show>
            <Show when={!closed() && fulfillmentReady() && entitlement() === "none"}><div class="bar"><button type="button" onClick={() => { setEntitlement("active"); setMessage("Client access activated against the linked deployment."); }}>activate client access</button></div></Show>
            <Show when={entitlement() === "active"}><div class="bar"><button type="button" class="tree-action" onClick={() => setMessage(`Runtime evidence opened for ${linkedReference()}.`)}>inspect runtime</button><button type="button" class="tree-action gaugeapp-danger-action" onClick={() => { setEntitlement("closed"); setMessage("Client access revoked. The engagement and prior runtime evidence remain."); }}>revoke client access</button></div></Show>
        </section>

        <section class="admin-section"><SectionHeading title="Accepted agreement" meta={fixture().agent.salesRevision} />
            <Definition label="Price" value={fixture().agent.pricing} />
            <Definition label="Term" value={fixture().term} />
            <Definition label="Accepted" value={fixture().accepted} note={fixture().proposalRecipient} />
            <Definition label="Client receives" value={fixture().agent.delivery} note={fixture().agent.versionPolicy} />
            <For each={fixture().agent.obligations}>{(obligation) => <Definition label="Included service" value={obligation} />}</For>
        </section>

        <section class="admin-section"><SectionHeading title="Billing" action="open Payments" onAction={() => props.onNavigate("vend", "Payments")} />
            <Definition label="Invoice recipient" value={fixture().billingRecipient} />
            <Definition label="Processor" value={fixture().billingState} note="Stripe evidence linked to this engagement" />
            <Definition label="Usage" value={fixture().metering}
                note={!fulfillmentReady() ? "Usage-priced charges remain blocked until evidence can be matched to a deployment." : "matched to the linked deployment"} />
        </section>

        <section class="admin-section gaugeapp-engagement-activity"><SectionHeading title="Activity" />
            <Definition label={fixture().accepted} value="Proposal accepted" note={`${fixture().reference} created from ${fixture().agent.salesRevision}`} />
            <Show when={fulfillmentReady()}><Definition label={fixture().agent.name === "Policy Desk" ? "Aug 12" : fixture().agent.name === "Release Steward" ? "Aug 18" : "Current"}
                value="Deployment linked" note={linkedReference()} /></Show>
            <Show when={entitlement() !== "none"}><Definition label="Client access" value={entitlement() === "active" ? "Activated" : "Revoked"} note="independent authority event" /></Show>
            <Show when={closed()}><Definition label="Current" value="Engagement closed" note="future billing instructions stopped" /></Show>
        </section>
        <Show when={message()}><p class="status" role="status">{message()}</p></Show>
    </>;
}

function EnterpriseOnboardingFlow(props: { scope: ScopeFixture; onBack: () => void }): JSX.Element {
    const prototype = useContext(PrototypeOrganizationContext);
    const steps = ["Plan", "Organization", "Review"] as const;
    const [step, setStep] = createSignal(0);
    const [orderConfirmed, setOrderConfirmed] = createSignal(false);
    const [activated, setActivated] = createSignal(false);
    const [settingUpIdentity, setSettingUpIdentity] = createSignal(false);
    const [message, setMessage] = createSignal("");
    const domain = () => scopeDomain(props.scope);
    const activate = () => {
        prototype.update(props.scope.id, { enterpriseControls: "active", scheduledServiceRemoval: null });
        setActivated(true);
    };
    return <Show when={!settingUpIdentity()} fallback={<SsoSetupFlow scope={props.scope}
        onCancel={() => setSettingUpIdentity(false)}
        onComplete={(result) => { setMessage(result); setSettingUpIdentity(false); }}
        onProvisioning={() => { setMessage("SCIM provisioning is ready to configure from Enterprise Identity after this onboarding handoff."); setSettingUpIdentity(false); }} />}>
        <Show when={activated()} fallback={<>
            <button type="button" class="gaugeapp-back-link" onClick={props.onBack}>← Plans & services</button>
            <PageHeader eyebrow="Enterprise controls / onboarding" title={`Add Enterprise controls to ${props.scope.label}`}
                description="Confirm the organization and activate the service. Identity configuration follows separately." />
            <DashboardGrid surface>
            <ol class="gaugeapp-setup-steps" aria-label="Enterprise onboarding progress">
                <For each={steps}>{(label, index) => <li classList={{ active: step() === index(), done: step() > index() }}>
                    <button type="button" onClick={() => setStep(index())}><span>{index() + 1}</span>{label}</button>
                </li>}</For>
            </ol>
            <Show when={step() === 0}><>
                <section class="admin-section"><SectionHeading title="Enterprise controls" meta="organization add-on" />
                    <Definition label="Identity" value="OIDC or SAML single sign-on" note="connection and enforcement are separate" />
                    <Definition label="Provisioning" value="JIT or SCIM" note="fixed GaugeDesk roles and explicit offboarding" />
                    <Definition label="Governance" value="Authentication, sessions, and software admission" note="organization policy" />
                </section>
                <section class="admin-section"><SectionHeading title="Commercial order" />
                    <div class="gaugeapp-field-grid">
                        <label>Billing contact<input type="email" value={`billing@${domain()}`} /></label>
                        <label>Billing cadence<select><option>Annual agreement · invoiced monthly</option><option>Annual prepayment</option></select></label>
                    </div>
                </section>
            </></Show>
            <Show when={step() === 1}><>
                <section class="admin-section"><SectionHeading title="Organization" />
                    <div class="gaugeapp-field-grid">
                        <label>Primary company domain<input value={domain()} /></label>
                        <label>Recovery owner<input value="Jack Scully · last owner" readOnly /></label>
                    </div>
                </section>
                <section class="admin-section"><SectionHeading title="Before corporate sign-in" />
                    <Definition label="Domain" value={domain()} note="DNS proof happens during identity setup" />
                    <Definition label="Owner recovery" value="Existing account sign-in preserved" note="the last owner remains a break-glass path" />
                    <Definition label="Current members" value="No change" note="activation does not sign anyone out or alter project access" />
                </section>
            </></Show>
            <Show when={step() === 2}><>
                <Notice tone="neutral">Activation adds Enterprise Identity and software policy. It does not configure or enforce sign-in, provision members, or change project access.</Notice>
                <section class="admin-section"><SectionHeading title="Activation summary" />
                    <Definition label="Organization" value={props.scope.label} note={domain()} />
                    <Definition label="Service" value="Enterprise controls" note="identity setup follows activation" />
                    <Definition label="Billing contact" value={`billing@${domain()}`} />
                </section>
                <section class="admin-section"><SectionHeading title="Confirm" />
                    <label class="gaugeapp-check-row"><input type="checkbox" checked={orderConfirmed()} onChange={(event) => setOrderConfirmed(event.currentTarget.checked)} /><span><strong>The commercial order is approved</strong><small>Billing begins when Enterprise controls are activated.</small></span></label>
                    <div class="bar"><button type="button" disabled={!orderConfirmed()} onClick={activate}>activate Enterprise controls</button></div>
                </section>
            </></Show>
            <div class="gaugeapp-setup-navigation">
                <button type="button" class="tree-action" disabled={step() === 0} onClick={() => setStep((current) => Math.max(0, current - 1))}>back</button>
                <span>Step {step() + 1} of {steps.length}</span>
                <button type="button" disabled={step() === steps.length - 1} onClick={() => setStep((current) => Math.min(steps.length - 1, current + 1))}>next</button>
            </div>
            </DashboardGrid>
        </>}>
            <button type="button" class="gaugeapp-back-link" onClick={props.onBack}>← Plans & services</button>
            <PageHeader eyebrow="Enterprise controls" title="Ready for identity setup"
                description={`Enterprise controls are active for ${props.scope.label}. Existing sign-in and project access are unchanged.`} />
            <DashboardGrid surface>
            <Notice tone="neutral"><strong>Activation complete.</strong> Verify the company domain and configure corporate sign-in before enabling managed membership or enforcement.</Notice>
            <section class="admin-section"><SectionHeading title="Next" />
                <Definition label="1" value={`Verify ${domain()}`} note="required for domain-based admission" />
                <Definition label="2" value="Set up corporate sign-in" note="choose OIDC or SAML and test before enforcement" />
                <Definition label="3" value="Choose JIT or SCIM" note="configure provisioning during identity setup" />
                <div class="bar"><button type="button" onClick={() => setSettingUpIdentity(true)}>set up corporate sign-in</button><button type="button" class="tree-action" onClick={props.onBack}>finish for now</button></div>
                <Show when={message()}><p class="status" role="status">{message()}</p></Show>
            </section>
            </DashboardGrid>
        </Show>
    </Show>;
}

function detailBlueprint(detail: DetailPageRequest, scope: ScopeFixture, project: ProjectFixture): DetailBlueprint {
    const supplied = detail.description ? ` Current record: ${detail.description}` : "";
    const projectName = project.name;
    const action = detail.action.toLowerCase();

    if (detail.family === "capability" && detail.kind === "provider-commercial" && action === "begin provider onboarding") return {
        description: `Set up payment processing before Commercial Operations goes live for ${scope.label}.`,
        metrics: [
            { label: "Commercial capability", value: "Pending", note: "accepted before activation" },
            { label: "Stripe account", value: "Not created", note: "created by the platform" },
            { label: "Payments", value: "Off", note: "until Stripe approves" },
            { label: "Payouts", value: "Off", note: "until bank verification" },
        ],
        sections: [
            { title: "Business", fields: [
                { label: "Legal business name", value: scope.label },
                { label: "Country", value: "United States" },
                { label: "Business type", value: "Company" },
                { label: "Account owner", value: "Jack · owner", readOnly: true },
            ] },
            { title: "Stripe will collect", rows: [
                { label: "Business and representatives", value: "Identity, address, ownership, and tax details" },
                { label: "Money movement", value: "Bank account and payout schedule" },
                { label: "Customer-facing details", value: "Statement descriptor, website, and support contact" },
            ] },
            { title: "Activation gates", rows: [
                { label: "Onboarding", value: "Details submitted", note: "Stripe-hosted collection complete" },
                { label: "Payments", value: "card_payments active", note: "direct charges can be created" },
                { label: "Payouts", value: "payouts enabled", note: "external account verified" },
                { label: "Requirements", value: "Nothing currently due", note: "future requirements remain visible in Payments" },
            ] },
        ],
        commands: [{ label: "continue to Stripe" }],
    };
    if (detail.family === "capability" && detail.kind === "provider-commercial") {
        const active = scope.providerCommerce === "active";
        return {
            description: `${active ? "Inspect" : "Add"} Commercial Operations for ${scope.label}.${supplied}`,
            notice: "This capability adds products, client engagements, and payment processing. The organization remains merchant of record; projects continue to own access and technical delivery.",
            metrics: [
                { label: "Standing", value: active ? "Active" : "Not added", note: active ? "admitted organization record" : "no provider commitment" },
                { label: "Merchant", value: scope.label, note: "provider remains merchant of record" },
                { label: "Storefront", value: "None", note: "direct clients only" },
                { label: "Platform price", value: "Unsettled", note: "fee or take rate requires a decision", warn: true },
            ],
            sections: [
                { title: "What activation adds", rows: [
                    { label: "Navigation", value: "Commercial Operations", note: "Products, Clients, Engagements, and Payments" },
                    { label: "Commercial records", value: "Provider-scoped", note: "clients, prices, invoices, refunds, payouts, and entitlements" },
                    { label: "Payment processing", value: "Stripe connected account", note: "onboarding, payments, disputes, balances, payouts, and documents" },
                ] },
                { title: "What it never adds", rows: [
                    { label: "Public marketplace", value: "Not included", note: "the provider brings every client" },
                    { label: "Project access", value: "No change", note: "each authoritative Home still admits" },
                    { label: "Technical deployment", value: "Reference only", note: "the project owns runtime truth" },
                    { label: "Payment", value: "Never authority", note: "payment cannot grant a client entitlement silently" },
                ] },
                { title: active ? "Activation record" : "Decisions before activation", rows: active ? [
                    { label: "Accepted", value: "July 18, 2026", note: "commercial capability recorded for this organization" },
                    { label: "Stripe account", value: "Payments and payouts active", note: "operational processor evidence" },
                    { label: "Actor access", value: "Owner and admitted commercial roles", note: "re-authorized per action" },
                ] : [
                    { label: "Activation path", value: "Not yet settled", note: "self-serve acceptance versus reviewed onboarding" },
                    { label: "Commercial terms", value: "Not yet settled", note: "platform fee or take rate and effective date" },
                    { label: "Required evidence", value: "Business identity and payout readiness", note: "exact verification contract needs a product decision" },
                ] },
            ],
            commands: active ? [{ label: "open Commercial Operations", destination: { appId: "vend", tab: "Products" } }]
                : [{ label: "begin provider onboarding", destination: { appId: "administration", tab: "Services", target: {
                    action: "begin provider onboarding", title: "Commercial Operations", kind: "provider-commercial",
                    description: "Business identity and Stripe processing setup",
                } } }],
        };
    }
    if (detail.family === "capability" && detail.kind === "enterprise-controls") {
        const active = scope.enterpriseControls === "active";
        return {
            description: `${active ? "Inspect" : "Add"} enterprise identity and client-governance controls for ${scope.label}.${supplied}`,
            notice: "Enterprise controls are independent from Commercial Operations and the organization’s basic administration. Owner and admin authorization still gates every change.",
            metrics: [
                { label: "Service", value: active ? "Active" : "Not added", note: "organization-scoped" },
                { label: "SSO", value: active ? "Available" : "Unavailable", note: "OIDC or SAML" },
                { label: "Provisioning", value: active ? "Available" : "Unavailable", note: "JIT and SCIM" },
                { label: "Activation", value: active ? "Complete" : "Onboarding required", note: active ? "service admitted" : "order, owner, and controls" },
            ],
            sections: [
                { title: "What activation adds", rows: [
                    { label: "Enterprise Identity", value: "Single sign-on", note: "OIDC or SAML with tested enforcement and owner recovery" },
                    { label: "Provisioning", value: "JIT and SCIM", note: "group-to-fixed-role mapping and explicit offboarding" },
                    { label: "Software admission", value: "Client version policy", note: "minimum protocol, channel, version, and grace deadline" },
                ] },
                { title: "What remains included in every organization", rows: [
                    { label: "Lifecycle", value: "Identity, ownership, transfer, and deletion", note: "base organization governance" },
                    { label: "People and projects", value: "Fixed roles and project admission", note: "available without enterprise controls" },
                    { label: "Operations", value: "Project Hosts, backups, and billing", note: "service availability varies separately" },
                ] },
                { title: active ? "Activation record" : "Before activation", rows: active ? [
                    { label: "Accepted", value: "August 2, 2026", note: "enterprise controls recorded for this tenant" },
                    { label: "Identity provider", value: "Not configured", note: "activation does not enforce SSO automatically" },
                    { label: "Owner recovery", value: "Available", note: "the last owner cannot be locked out" },
                ] : [
                    { label: "Commercial order", value: "Required", note: "billing terms and effective date" },
                    { label: "Implementation owner", value: "Required", note: "coordinates domain, IdP, and recovery" },
                    { label: "Safe default", value: "Existing sign-in remains", note: "SSO is never enforced by plan activation" },
                ] },
            ],
            commands: active ? [{ label: "open Enterprise Identity", destination: { appId: "administration", tab: "Identity" } }]
                : [{ label: "begin enterprise onboarding", destination: { appId: "administration", tab: "Services", target: {
                    action: "begin enterprise onboarding", title: "Enterprise controls", kind: "enterprise-controls",
                    description: "Commercial order, implementation owner, recovery, and control defaults",
                } } }],
        };
    }
    if (detail.family === "capability") return {
        description: `Inspect the organization service represented by ${detail.title}.${supplied}`,
        notice: "Organization services affect presented surfaces and future service eligibility. They never replace role checks, project admission, or the authority of a project Home.",
        sections: [{ title: "Service", rows: [{ label: "Status", value: detail.meta ?? "Not added", note: "organization-scoped" }] }],
        commands: [{ label: "review service" }],
    };

    if (detail.family === "transaction" && action === "refund") {
        const amount = detail.title.includes("$4,800") ? "$4,800" : "$6,200";
        const client = detail.title.split(" · ")[0]!;
        return {
            description: `Issue a full or partial refund against the settled ${amount} transaction for ${client}.${supplied}`,
            notice: "A refund appends processor and accounting evidence. It does not revoke a client entitlement, deployment, project grant, or prior delivery record; those require their own explicit actions.",
            metrics: [
                { label: "Settled", value: amount, note: "maximum refundable" },
                { label: "Refunded", value: "$0", note: "before this action" },
                { label: "Entitlement", value: "Unchanged", note: "separate provider act" },
                { label: "Processor", value: "Stripe", note: "original payment" },
            ],
            sections: [
                { title: "Refund", fields: [
                    { label: "Client", value: client, readOnly: true },
                    { label: "Maximum", value: amount, readOnly: true },
                    { label: "Refund amount", value: amount },
                    { label: "Reason", value: "Requested by client" },
                    { label: "Internal note", value: "", wide: true },
                ] },
                { title: "Independent follow-up", rows: [
                    { label: "Client entitlement", value: "No change", note: "revoke separately if service should end" },
                    { label: "Deployment", value: "No change", note: "runtime authority remains project-owned" },
                    { label: "Invoice", value: "Credited by refund evidence", note: "original record remains immutable" },
                ] },
            ],
            commands: [{ label: "review refund" }],
        };
    }
    if (detail.family === "project-target" && action.includes("attach")) return {
        description: `Attach an exact body of work to ${projectName} and admit only the acts this project needs.${supplied}`,
        notice: "The locator is validated by the owning Home before it is stored. Discovering a repository or folder does not grant read, mutation, publication, or release authority.",
        metrics: [
            { label: "Project", value: projectName, note: "one trust boundary" },
            { label: "Source", value: "Not selected", note: "managed or external" },
            { label: "Path scope", value: "Not set", note: "must be explicit" },
            { label: "Acts", value: "None yet", note: "least authority" },
        ],
        sections: [
            { title: "Source", fields: [
                { label: "Display name", value: "" },
                { label: "Target kind", value: "GaugeDesk-managed work" },
                { label: "Repository or storage locator", value: "" },
                { label: "Path scope", value: "/**" },
            ] },
            { title: "Initial acts", rows: [
                { label: "Read", value: "Proposed", note: "materialize an exact basis" },
                { label: "Propose", value: "Proposed", note: "candidate overlay only" },
                { label: "Apply", value: "Off", note: "enable deliberately after connection" },
                { label: "Publish / release", value: "Off", note: "separate downstream acts" },
            ] },
        ],
        commands: [{ label: "validate source" }, { label: "attach target" }],
    };
    if (detail.family === "project-resource" && action.includes("data policy")) return {
        description: `Set the purpose for governed runs in ${projectName} and review the labels carried by its attached resources.${supplied}`,
        notice: "These fields do not grant an Agent access to a resource. They add constraints after project, placement, and resource-owner admission; a missing or unknown classification is treated as regulated.",
        sections: [
            { title: "Project run purpose", fields: [
                { label: "Admitted purpose", value: "product-development", wide: true },
            ], rows: [
                { label: "Enforcement", value: "Every governed Agent turn", note: "a purpose-labeled resource is refused when the purpose does not match" },
                { label: "Existing conversations", value: "New epoch on next turn", note: "prior run evidence keeps its original epoch" },
            ] },
            { title: "Attached resource labels", rows: [
                { label: "Company style guide", value: "internal · us · product-development", note: "project owned · 3 Agent placements granted" },
                { label: "Client research archive", value: "PII · us · product-development", note: "client owned · owner consent active" },
                { label: "Client operating plan", value: "regulated · no region · product-development", note: "access request pending; not available to a run" },
            ] },
            { title: "Label behavior", rows: [
                { label: "Classification", value: "public · internal · PII · regulated", note: "unknown and omitted values resolve to regulated" },
                { label: "Region", value: "Optional resource attribute", note: "required when organization policy demands a match" },
                { label: "Purpose", value: "Optional resource attribute", note: "when present, must match the admitted project run purpose" },
                { label: "Stakeholders", value: "Derived from resource ownership and provenance", note: "not editable as a classification shortcut" },
                { label: "Protected output", value: "Inherits labels and stakeholders from inputs read", note: "release to a new audience is a separate project decision" },
            ] },
        ],
        commands: [{ label: "review data-policy change" }],
    };
    if (detail.family === "project-resource" && action.includes("attach")) return {
        description: `Attach protected context to ${projectName} and identify exactly which placement may resolve it.${supplied}`,
        notice: "Single-party project context may be granted by the project owner. Context owned by another party starts as a request and remains unreadable until that owner admits a basis.",
        metrics: [
            { label: "Owner", value: "Select owner", note: "resource authority" },
            { label: "Basis", value: "Not created", note: "immutable on use" },
            { label: "Placements", value: "None", note: "no ambient access" },
            { label: "Purpose", value: "Required", note: "bound to request" },
        ],
        sections: [
            { title: "Context source", fields: [
                { label: "Display name", value: "" },
                { label: "Resource owner", value: scope.label },
                { label: "Protected locator", value: "" },
                { label: "Purpose", value: `Work inside ${projectName}`, wide: true },
            ] },
            { title: "Initial placement access", rows: [
                { label: "General assistant", value: "Off", note: "grant only if needed" },
                { label: "Product designer", value: "Off", note: "grant only if needed" },
                { label: "Financial analyst", value: "Unavailable", note: "placement is still pending" },
            ] },
        ],
        commands: [{ label: "attach or request context" }],
    };
    if (detail.family === "project-placement" && action === "add agent") return {
        description: `Create a pinned Agent placement inside ${projectName}.${supplied}`,
        notice: "This adds an Agent to the project, not a person. The placement begins with no target acts, protected context, or public audience unless each is selected explicitly.",
        metrics: [
            { label: "Admission", value: "Draft", note: "owner review required" },
            { label: "Version", value: "Not selected", note: "must be pinned" },
            { label: "Targets", value: "None", note: "eligibility is not authority" },
            { label: "Context", value: "None", note: "basis required" },
        ],
        sections: [
            { title: "Agent placement", fields: [
                { label: "Agent", value: "Choose from admitted library" },
                { label: "Placement kind", value: "Work Agent" },
                { label: "Pinned version", value: "Current admitted version" },
                { label: "Eligible work target", value: "None" },
                { label: "Project configuration", value: "", wide: true },
            ] },
            { title: "Authority review", rows: [
                { label: "People admitted", value: "No change", note: "placement is not project membership" },
                { label: "Target acts", value: "None", note: "grant separately after placement admission" },
                { label: "Protected context", value: "None", note: "resource owner basis required" },
                { label: "Deployment", value: "None", note: "Panel agents bind through a separate deployment" },
            ] },
        ],
        commands: [{ label: "submit placement for admission" }],
    };
    if (detail.family === "organization" && action === "check dns") return {
        description: `Verify control of ${detail.title} for ${scope.label}.${supplied}`,
        notice: "Verification proves control of this domain. It does not enable automatic membership, SSO enforcement, or project access until those are configured separately.",
        metrics: [
            { label: "Status", value: "Pending", note: "last checked 6 minutes ago", warn: true },
            { label: "Record", value: "TXT", note: "DNS proof" },
            { label: "JIT", value: "Off", note: "separate identity policy" },
            { label: "Auto-join", value: "Off", note: "no access implied" },
        ],
        sections: [
            { title: "DNS record", fields: [
                { label: "Host", value: `_gaugewright.${detail.title}`, readOnly: true },
                { label: "Type", value: "TXT", readOnly: true },
                { label: "Value", value: "gaugewright-verification=gw_7fc2…918e", readOnly: true, wide: true },
            ] },
            { title: "Latest check", rows: [
                { label: "Resolver", value: "No matching TXT record", note: "authoritative answer received" },
                { label: "Next automatic check", value: "In 24 minutes", note: "manual check is safe" },
            ] },
        ],
        commands: [{ label: "check DNS again" }, { label: "remove domain", danger: true }],
    };
    if (detail.family === "member" && (action === "manage grants" || detail.title === "Project grants")) return {
        description: `Manage explicit member-to-project admission records for ${scope.label}.${supplied}`,
        notice: "Project access is assigned directly to people. Organization roles do not open project content, and no project grant changes target, resource, Agent, or export authority.",
        sections: [
            { title: "GaugeDesk", rows: [
                { label: "Jack Scully", value: "Owner", note: "can work and manage access" },
                { label: "Maya Singh", value: "Can work", note: "explicit project access" },
                { label: "Eli Ortiz", value: "Can view", note: "explicit project access" },
                { label: "Rowan Kim", value: "No access", note: "membership invitation pending" },
            ] },
            { title: "GaugeWright operations", rows: [
                { label: "Jack Scully", value: "Owner", note: "can work and manage access" },
                { label: "Maya Singh", value: "Can work", note: "explicit project access" },
                { label: "Eli Ortiz", value: "No access", note: "no explicit grant" },
            ] },
        ],
        commands: [{ label: "save project grants" }],
    };
    if (detail.family === "project-host" && action === "add project host") return {
        description: `Admit a new Project Host for ${scope.label} without granting it project work.${supplied}`,
        notice: "Project Host admission establishes reachability and execution profiles only. Projects must be created or deliberately handed off to it, and people still need project admission.",
        metrics: [
            { label: "State", value: "Not connected", note: "enrollment required" },
            { label: "Projects", value: "0", note: "no implicit Homes" },
            { label: "Region", value: "Choose", note: "physical placement" },
            { label: "Profiles", value: "Unverified", note: "reported after enrollment" },
        ],
        sections: [
            { title: "Project Host", fields: [
                { label: "Name", value: "" },
                { label: "Management", value: scope.kind === "personal" ? "GaugeWright managed" : "Self-hosted" },
                { label: "Region", value: "us-east" },
                { label: "Enrollment lifetime", value: "15 minutes" },
            ] },
            { title: "After enrollment", rows: [
                { label: "Reachability", value: "Checked", note: "unknown until the Project Host reports" },
                { label: "Execution profiles", value: "Reported and admitted", note: "reviewed after the Project Host connects" },
                { label: "Project Homes", value: "None", note: "handoff is a separate operation" },
            ] },
        ],
        commands: [{ label: "generate enrollment ticket" }],
    };
    if (detail.family === "backup" && action === "recovery instructions") return {
        description: `Recovery procedure for the key held by ${detail.title}.${supplied}`,
        notice: "The recovery key never appears in GaugeDesk. These instructions identify the holder, validate Trusted Device access, and start a restore through the admitted recovery protocol.",
        metrics: [
            { label: "Holder", value: detail.title, note: "Trusted Device-held key" },
            { label: "Standing", value: "Active", note: "future restore" },
            { label: "Key export", value: "Never", note: "non-projectable" },
            { label: "Last test", value: "Aug 12", note: "recovery drill" },
        ],
        sections: [
            { title: "Recovery checklist", rows: [
                { label: "1", value: `Open GaugeDesk on ${detail.title}`, note: "the holder must be locally available" },
                { label: "2", value: "Choose the encrypted recovery point", note: "source evidence remains immutable" },
                { label: "3", value: "Approve a new restore destination", note: "never overwrite the source Home" },
                { label: "4", value: "Verify the restored project before handoff", note: "ordinary admission resumes" },
            ] },
        ],
        commands: [{ label: "copy recovery checklist" }],
    };
    if (detail.family === "backup" && action === "add recovery holder") return {
        description: `Add another Trusted Device-held recovery basis for ${scope.label}.${supplied}`,
        notice: "A recovery holder can participate in future restores. It does not receive project visibility, backup payload access, tenant ownership, or a transferable copy of the root key.",
        metrics: [
            { label: "Current holders", value: scope.kind === "organization" ? "2" : "1", note: "independent Trusted Devices" },
            { label: "New holder", value: "Not selected", note: "active member Trusted Device" },
            { label: "Project access", value: "None", note: "unchanged" },
            { label: "Activation", value: "Pending", note: "Trusted Device acceptance" },
        ],
        sections: [{ title: "Recovery holder", fields: [
            { label: "Member", value: scope.kind === "organization" ? "Choose organization member" : "Jack Scully" },
            { label: "Trusted Device", value: "Choose a Trusted Device" },
            { label: "Purpose", value: "Tenant recovery" },
            { label: "Expires", value: "No automatic expiry" },
        ] }],
        commands: [{ label: "send recovery-holder request" }],
    };
    if (detail.family === "backup" && detail.kind === "trusted-device") return {
        description: `Inspect the recovery-holder basis retained by ${detail.title}.${supplied}`,
        notice: "Removing this holder affects future recovery only. It cannot revoke prior participation or delete backup evidence.",
        metrics: [
            { label: "Standing", value: "Active", note: "holder admitted" },
            { label: "Added", value: detail.description?.includes("Aug 16") ? "Aug 16" : "Aug 12", note: "admitted event" },
            { label: "Key", value: "Trusted Device-held", note: "never projected" },
            { label: "Last seen", value: "Today", note: "operational" },
        ],
        sections: [{ title: "Holder", rows: [
            { label: "Authority", value: detail.title, note: "member and Trusted Device" },
            { label: "Recovery scope", value: scope.label, note: "tenant only" },
            { label: "Project access", value: "Unchanged", note: "recovery is not work authority" },
        ] }],
        commands: [{ label: "request recovery test" }, { label: "remove recovery holder", danger: true }],
    };
    if (detail.family === "deployment" && action === "new deployment") return {
        description: `Create a technical panel deployment in ${scope.label}.${supplied}`,
        notice: "A deployment binds a Panel Agent placement, release, audience, origin, credential, and spend guard. It does not create a Vend offer or client entitlement.",
        metrics: [
            { label: "State", value: "Draft", note: "no sessions admitted" },
            { label: "Release", value: "Not selected", note: "immutable artifact" },
            { label: "Audience", value: "Private", note: "restrictive default" },
            { label: "Funding", value: "Not configured", note: "no personal fallback" },
        ],
        sections: [
            { title: "Binding", fields: [
                { label: "Name", value: "" },
                { label: "Project", value: projectName },
                { label: "Panel Agent placement", value: "Choose admitted Panel Agent" },
                { label: "Release", value: "Choose admitted release" },
            ] },
            { title: "Audience & guards", fields: [
                { label: "Audience", value: "Authenticated" },
                { label: "Allowed origin", value: "" },
                { label: "Deployment credential", value: "Not selected" },
                { label: "Per-session spend", value: "$3.00" },
            ] },
        ],
        commands: [{ label: "create draft" }],
    };
    if (detail.family === "account" && (action === "reauthenticate" || action === "verify")) return {
        description: `Verify the ${detail.title} sign-in method for Jack Scully.${supplied}`,
        notice: "This revalidates account authentication only. Model-provider authorization, Trusted Device delegation, tenant membership, and project access are separate.",
        metrics: [
            { label: "Method", value: "Google", note: "primary account sign-in" },
            { label: "Last verified", value: "Aug 12", note: "account evidence" },
            { label: "Sessions", value: "2", note: "not ended by verification" },
            { label: "Recovery", value: "Available", note: "provider-owned" },
        ],
        sections: [
            { title: "Sign-in method", rows: [
                { label: "Account", value: "jack@gaugewright.com", note: "primary email" },
                { label: "Provider", value: "Google", note: "external handoff" },
                { label: "Return", value: "This GaugeDesk", note: "current account session" },
            ] },
            { title: "Unaffected", rows: [
                { label: "Provider credentials", value: "Unchanged", note: "Model Providers" },
                { label: "Trusted Device keys", value: "Unchanged", note: "Trusted Devices" },
                { label: "Project admission", value: "Unchanged", note: "each project Home remains authoritative" },
            ] },
        ],
        commands: [{ label: "continue with Google" }],
    };
    if (detail.family === "account" && action === "edit profile") return {
        description: `Edit the person-scoped display details used across GaugeDesk.${supplied}`,
        notice: "Display details are presentation metadata. The account root, primary identity, memberships, project grants, and authored history do not change.",
        metrics: [
            { label: "Account", value: "Active", note: "Jack Scully" },
            { label: "Primary email", value: "Verified", note: "Google-owned" },
            { label: "Memberships", value: "2", note: "unchanged" },
            { label: "Sessions", value: "2", note: "unchanged" },
        ],
        sections: [{ title: "Profile", fields: [
            { label: "Display name", value: "Jack Scully" },
            { label: "Primary email", value: "jack@gaugewright.com", readOnly: true },
            { label: "Account root", value: "root:7a91…c2", readOnly: true },
        ] }],
        commands: [{ label: "save profile" }],
    };
    if (detail.family === "account" && action === "open") return {
        description: `Your membership and reachable work in ${detail.title}.${supplied}`,
        notice: "Membership determines organization role and routing. Each project grants access independently.",
        metrics: [
            { label: "Role", value: "Owner", note: "tenant authority" },
            { label: "Projects", value: "2 reachable", note: "explicit project access" },
            { label: "Seat", value: "Assigned", note: "billing is separate" },
            { label: "Sessions", value: "1", note: "current GaugeDesk" },
        ],
        sections: [
            { title: "Membership", rows: [
                { label: "Organization", value: detail.title, note: "selected tenant" },
                { label: "Role", value: "Owner", note: "fixed tenant role" },
                { label: "Joined", value: "Direct", note: "not identity-provider managed" },
            ] },
            { title: "Reachable projects", rows: [
                { label: "GaugeDesk", value: "Available", note: "project owner" },
                { label: "GaugeWright operations", value: "Available", note: "project owner" },
            ] },
        ],
        commands: [{ label: "switch to organization" }, { label: "leave organization", danger: true }],
    };
    if (detail.family === "model" && (action.includes("plan") || detail.title.toLowerCase().includes("plan"))) return {
        description: `Managed model funding, included usage, and execution-class limits for ${detail.title}.${supplied}`,
        notice: "A model plan funds eligible calls. It does not admit a provider to organization policy, project work, a private Home, or a public deployment credential.",
        metrics: [
            { label: "Plan", value: scope.kind === "organization" ? "Organization managed" : "Individual" , note: "active" },
            { label: "Used", value: scope.kind === "organization" ? "42,180" : "18,420", note: "included tokens" },
            { label: "Allowance", value: scope.kind === "organization" ? "250,000" : "100,000", note: "per month" },
            { label: "Renews", value: "Sep 1", note: "billing period" },
        ],
        sections: [
            { title: "Plan", fields: [
                { label: "Funding scope", value: scope.kind === "organization" ? scope.label : "Jack Scully", readOnly: true },
                { label: "Plan", value: scope.kind === "organization" ? "Organization managed" : "Individual" },
                { label: "Usage alert", value: "80%" },
                { label: "Overage", value: "Stop at allowance" },
            ] },
            { title: "Execution boundary", rows: [
                { label: "Local interactive", value: "Eligible", note: "provider and project policy still resolve" },
                { label: "Private Home", value: "Separate credential admission", note: "never inherited" },
                { label: "Public deployment", value: "Separate funding required", note: "no personal fallback" },
            ] },
        ],
        commands: [{ label: "save usage controls" }, { label: "request plan change" }],
    };
    if (detail.family === "billing" && (action === "upgrade to plus" || action === "add cloud home")) return {
        description: `Add GaugeDesk Plus and its managed Cloud Home to ${scope.label}.${supplied}`,
        notice: "The upgrade creates future hosted-service eligibility. It does not move local projects, change memberships, admit anyone to work, or silently make the Cloud Home authoritative for an existing project.",
        sections: [
            { title: "Service selection", fields: [
                { label: "Service", value: "GaugeDesk Plus", readOnly: true },
                { label: "Billing scope", value: scope.kind === "personal" ? "Personal tenant" : scope.label, readOnly: true },
                { label: "Region", value: "us-east" },
                { label: "Effective", value: "Immediately after payment succeeds" },
            ] },
            { title: "Included", rows: [
                { label: "Managed Project Host", value: "One Cloud Home", note: "durable project store and bounded workflow execution" },
                { label: "Cloud backup", value: "Basic encrypted backup", note: "recovery access configured separately" },
                { label: "Isolated workspace compute", value: "Not included", note: "separately metered and explicitly enabled" },
            ] },
            { title: "After activation", rows: [
                { label: "New projects", value: "May choose the Cloud Home", note: "only after the Home is ready" },
                { label: "Existing projects", value: "Stay where they are", note: "moving one requires an explicit Home handoff" },
                { label: "People and roles", value: "Unchanged", note: "billing is not access authority" },
                { label: "Model funding", value: "Separate", note: "Plus does not silently authorize provider spend" },
            ] },
        ],
        commands: [{ label: "review Plus checkout" }],
    };
    if (detail.family === "billing" && action === "change plan") return {
        description: `Compare the paid service plans available to ${scope.label}.${supplied}`,
        notice: "A plan change affects future service and billing. It never changes tenant role, seat assignment, project admission, or model-provider policy.",
        sections: [
            { title: "Plan selection", fields: [
                { label: "Plan", value: scope.kind === "personal" ? "GaugeDesk Plus" : "Managed organization" },
                { label: "Effective", value: "Next billing period" },
            ] },
            { title: "Included service", rows: [
                { label: "Managed Project Host", value: scope.cloudHome === "managed" ? "1 active" : "1 proposed", note: "lifecycle is managed separately" },
                { label: "Encrypted backup", value: scope.cloudHome === "managed" ? "30 days" : "Included after activation", note: "recovery holders remain unchanged" },
                { label: "Managed inference", value: "Separate plan controls", note: "Model Providers" },
            ] },
        ],
        commands: [{ label: "review plan change" }],
    };
    if (detail.family === "billing" && action === "change seats") return {
        description: `Change paid seat capacity for ${scope.label}.${supplied}`,
        notice: "Purchasing a seat does not assign it and cannot grant organization or project access. People remains the membership authority.",
        metrics: [
            { label: "Purchased", value: "5", note: "current capacity" },
            { label: "Assigned", value: "3", note: "People" },
            { label: "Available", value: "2", note: "unassigned" },
            { label: "Estimate", value: "$60 / month", note: "seat portion" },
        ],
        sections: [
            { title: "Seat capacity", fields: [
                { label: "Purchased seats", value: "5" },
                { label: "Effective", value: "Immediately for increases" },
            ] },
            { title: "Assignment boundary", rows: [
                { label: "Jack Scully", value: "Assigned", note: "owner" },
                { label: "Maya Singh", value: "Assigned", note: "administrator" },
                { label: "Eli Ortiz", value: "Assigned", note: "member" },
            ] },
        ],
        commands: [{ label: "review seat change" }],
    };
    if (detail.family === "billing" && action === "update") return {
        description: `Replace the default payment method for ${scope.label}.${supplied}`,
        notice: "Card details are collected by the payment processor and never projected into GaugeDesk. GaugeDesk retains only the masked method and processor reference.",
        metrics: [
            { label: "Current", value: "Visa · 4242", note: "expires 08/29" },
            { label: "Status", value: "Valid", note: "processor confirmed" },
            { label: "Default", value: "Yes", note: "tenant services" },
            { label: "Past due", value: "$0", note: "account current" },
        ],
        sections: [
            { title: "Payment method", rows: [
                { label: "Current method", value: "Visa ending 4242", note: "processor reference pm_…4242" },
                { label: "Replacement", value: "Entered in secure processor form", note: "never enters agent or panel data" },
            ] },
        ],
        commands: [{ label: "continue to secure card form" }],
    };
    if (detail.family === "billing" && action === "edit") return {
        description: `Edit invoice delivery details for ${scope.label}.${supplied}`,
        notice: "The billing contact receives invoices and payment notices. It gains no tenant membership, project access, or payment authority.",
        metrics: [
            { label: "Delivery", value: "Email", note: "processor notices" },
            { label: "Status", value: "Verified", note: "last delivery succeeded" },
            { label: "Past due", value: "$0", note: "account current" },
            { label: "Authority", value: "None", note: "contact only" },
        ],
        sections: [{ title: "Billing contact", fields: [
            { label: "Email", value: scope.kind === "personal" ? "jack@gaugewright.com" : "billing@gaugewright.com" },
            { label: "Legal name", value: scope.label },
        ] }],
        commands: [{ label: "save billing contact" }],
    };
    if (detail.family === "billing" && action === "view usage") return {
        description: `Current managed-model usage for ${scope.label}.${supplied}`,
        notice: "Usage is billing evidence only. It neither proves a run was authorized nor changes any project, credential, or deployment permission.",
        metrics: [
            { label: "Used", value: "42,180", note: "included tokens" },
            { label: "Allowance", value: "250,000", note: "current period" },
            { label: "Forecast", value: "67,000", note: "at current rate" },
            { label: "Renews", value: "Sep 1", note: "billing period" },
        ],
        sections: [
            { title: "Usage by project", rows: [
                { label: "GaugeDesk", value: "31,240 tokens", note: "74%" },
                { label: "GaugeWright operations", value: "10,940 tokens", note: "26%" },
            ] },
            { title: "Usage by model", rows: [
                { label: "GPT-5.6", value: "28,900 tokens", note: "69%" },
                { label: "GPT-5.4", value: "13,280 tokens", note: "31%" },
            ] },
        ],
        commands: [{ label: "download usage CSV" }, { label: "change usage alert" }],
    };
    switch (detail.family) {
        case "project-governance": {
            const governedProject = PROJECTS_BY_SCOPE[scope.id].find((candidate) => candidate.id === detail.kind || candidate.name === detail.title) ?? project;
            const facts = PROJECT_GOVERNANCE_BY_ID[governedProject.id] ?? {
                people: 1, explicitGrants: 0, agents: 0, targets: 0, state: "healthy", activity: "just now",
            };
            return {
                description: `Tenant-wide governance posture for ${governedProject.name}, resolved from its authoritative Home.${supplied}`,
                notice: "This page lets an organization owner or administrator discover and inspect the project. Changes still resolve to the project’s authoritative Home; Administration does not become a second project authority.",
                metrics: [
                    { label: "Home", value: facts.state === "healthy" ? "Reachable" : "Needs attention", note: governedProject.detail, warn: facts.state === "attention" },
                    { label: "People", value: `${facts.people}`, note: `${facts.explicitGrants} explicit member grant${facts.explicitGrants === 1 ? "" : "s"}` },
                    { label: "Agents", value: `${facts.agents}`, note: "admitted placements" },
                    { label: "Work targets", value: `${facts.targets}`, note: "project-owned data boundaries" },
                ],
                sections: [
                    { title: "Identity & custody", rows: [
                        { label: "Project ID", value: `proj_${governedProject.id}`, note: "permanent identity" },
                        { label: "Authoritative Home", value: governedProject.detail, note: "sole owner of project settings and work" },
                        { label: "Organization", value: scope.label, note: "tenant governance scope" },
                        { label: "Last activity", value: facts.activity, note: "operational evidence" },
                    ] },
                    { title: "Access posture", rows: [
                        { label: "Project owner", value: "1 person", note: "can work and manage access" },
                        { label: "Other people", value: `${Math.max(0, facts.people - 1)}`, note: "explicit revocable project access" },
                        { label: "Reachable people", value: `${facts.people}`, note: "resolved by the project Home" },
                        { label: "Paid seats", value: "No authority", note: "billing never grants project access" },
                    ] },
                    { title: "Work & Agents", rows: [
                        { label: "Work targets", value: `${facts.targets}`, note: "exact locators and admitted acts" },
                        { label: "Agent placements", value: `${facts.agents}`, note: "pinned project installations" },
                        { label: "Protected context", value: governedProject.id === "gaugedesk" || governedProject.id === "client-launch" ? "2 resources" : "1 resource", note: "owner-granted bases only" },
                    ] },
                    { title: "Authority invariants", rows: [
                        { label: "Project settings", value: "Owned by the authoritative Home", note: "Administration routes commands there" },
                        { label: "Organization policy", value: "Restrict-only", note: "the project cannot widen the tenant floor" },
                        { label: "Move project", value: "Deliberate Home handoff", note: "never a mutable region or Project Host field" },
                    ] },
                ],
                commands: [{ label: "open project settings", destination: {
                    appId: "project", tab: PROJECT_TABS[0]!.id, projectId: governedProject.id,
                } }],
            };
        }
        case "project-access": return {
            description: `The effective access record for ${detail.title} in ${projectName}.${supplied}`,
            notice: "Project admission is binary in the current backend. Tenant role, target acts, resource consent, and review can narrow it; the grant cannot widen any of them.",
            metrics: [
                { label: "Project", value: projectName, note: "one trust boundary" },
                { label: "Admission", value: detail.action.includes("grant") ? "Not granted" : "Active", note: "future access only" },
                { label: "Role source", value: "Tenant directory", note: "not a project role" },
                { label: "Exports", value: "Separately gated", note: "viewer and stakeholder rules apply" },
            ],
            sections: [
                { title: "Access basis", rows: [
                    { label: "Person / authority", value: detail.title, note: detail.meta ?? "active organization member" },
                    { label: "Project", value: projectName, note: `proj_${project.id}` },
                    { label: "Source", value: detail.kind ?? "explicit member → project grant", note: "revocable without rewriting prior work" },
                ] },
                { title: "What this does not grant", rows: [
                    { label: "Work targets", value: "No new acts", note: "read, propose, apply, publish, and release remain separate" },
                    { label: "Agent context", value: "No resource access", note: "placements require their own granted bases" },
                    { label: "Output release", value: "No consent", note: "stakeholder review still applies" },
                ] },
            ],
            commands: detail.action.includes("grant") ? [{ label: "grant project access" }] : [{ label: "revoke project access", danger: true }],
        };
        case "project-target": return {
            description: `Configure the exact body of work and admitted acts represented by ${detail.title}.${supplied}`,
            notice: "A target locator, visible diff, or checked-out file grants nothing by itself. Every chat pins an exact basis and path scope.",
            metrics: [
                { label: "Kind", value: detail.kind ?? "work target", note: "authority preserved" },
                { label: "Status", value: "Available", note: "resolved by the Home" },
                { label: "Path scope", value: detail.title.includes("gaugedesk") ? "/web/**" : "/**", note: "no neighboring paths" },
                { label: "Basis", value: detail.title.includes("gaugedesk") ? "main@8f21d9b" : "managed cut 184", note: "immutable chat basis" },
            ],
            sections: [
                { title: "Target", fields: [
                    { label: "Display name", value: detail.title },
                    { label: "Protected locator", value: detail.title.includes("gaugedesk") ? "github:gaugewright/gaugedesk-src" : `managed:${project.id}`, readOnly: true },
                    { label: "Path scope", value: detail.title.includes("gaugedesk") ? "/web/**" : "/**" },
                    { label: "Adapter", value: detail.title.includes("gaugedesk") ? "Git / external VCS" : "WhippleScript managed", readOnly: true },
                ] },
                { title: "Admitted acts", rows: [
                    { label: "Read", value: "Allowed", note: "materialize the exact basis" },
                    { label: "Propose", value: "Allowed", note: "candidate overlay only" },
                    { label: "Apply", value: detail.title.includes("gaugedesk") ? "Denied" : "Allowed", note: "requires unchanged current basis" },
                    { label: "Publish / release", value: detail.title.includes("gaugedesk") ? "Publish allowed · release denied" : "Denied", note: "neither is implied by propose" },
                ] },
            ],
            commands: [{ label: detail.action.includes("attach") ? "attach target" : "save target grants" }, { label: "detach target", danger: true }],
        };
        case "project-resource": return {
            description: `Inspect the protected context basis and placement access for ${detail.title}.${supplied}`,
            notice: "Visibility is not payload access. Multi-party context resolves only through a currently granted resource-access basis approved by its owner or stakeholders.",
            metrics: [
                { label: "Owner", value: detail.title.includes("Northstar") ? "Northstar Labs" : scope.label, note: "resource authority" },
                { label: "State", value: detail.action.includes("review") ? "Requested" : "Granted", note: "future use only" },
                { label: "Placements", value: "2 of 3", note: "exact consumers" },
                { label: "Purpose", value: "Project analysis", note: "cannot widen on retry" },
            ],
            sections: [
                { title: "Resource basis", rows: [
                    { label: "Resource", value: detail.title, note: detail.kind ?? "project context" },
                    { label: "Purpose", value: "Project analysis", note: "bound to this access request" },
                    { label: "Approver", value: detail.title.includes("Northstar") ? "Northstar Labs" : scope.label, note: "current owner" },
                ] },
                { title: "Placement access", rows: [
                    { label: "Product designer", value: "Granted", note: "may resolve during an admitted run" },
                    { label: "General assistant", value: detail.title.includes("Northstar") ? "Not granted" : "Granted", note: "no ambient project-wide read" },
                    { label: "Financial analyst", value: "Pending placement", note: "cannot consume any basis" },
                ] },
            ],
            commands: detail.action.includes("review") ? [{ label: "approve request" }, { label: "deny request", danger: true }] : [{ label: "save placement access" }, { label: "revoke basis", danger: true }],
        };
        case "project-placement": return {
            description: `Manage the pinned Agent installation ${detail.title} inside ${projectName}.${supplied}`,
            notice: "A placement limits an Agent; it never admits a person. Target eligibility also does not grant the target's read or mutation acts.",
            metrics: [
                { label: "Admission", value: detail.title.includes("Financial") ? "Pending" : "Active", note: "owner acceptance" },
                { label: "Agent kind", value: detail.title.includes("Documentation") ? "Panel" : "Work", note: "immutable lineage" },
                { label: "Pinned version", value: detail.title.includes("General") ? "v1" : detail.title.includes("Financial") ? "v2" : detail.title.includes("Documentation") ? "v3" : "v4", note: "read-only method" },
                { label: "Update", value: detail.title.includes("Product designer") ? "v5 available" : "Current", note: "never silent" },
            ],
            sections: [
                { title: "Binding", fields: [
                    { label: "Agent", value: detail.title, readOnly: true },
                    { label: "Project", value: projectName, readOnly: true },
                    { label: "Eligible target", value: detail.title.includes("Documentation") ? "None — Panel agent" : `${projectName} files` },
                    { label: "Pinned version", value: detail.title.includes("General") ? "v1" : detail.title.includes("Financial") ? "v2" : detail.title.includes("Documentation") ? "v3" : "v4" },
                    { label: "Project configuration", value: "Use GaugeWright terminology and current project conventions.", wide: true },
                ] },
                { title: "Current authority", rows: [
                    { label: "Context", value: "Company style guide", note: "one granted resource basis" },
                    { label: "Target acts", value: detail.title.includes("Documentation") ? "None" : "read · propose", note: "checked again at run admission" },
                    { label: "Public deployment", value: detail.title.includes("Documentation") ? "1 binding" : "Not applicable", note: "separate release and funding authority" },
                ] },
            ],
            commands: detail.title.includes("Financial")
                ? [{ label: "accept Agent" }, { label: "reject placement", danger: true }]
                : [{ label: "save placement" }, ...(detail.description?.includes("available") ? [{ label: "upgrade to current" }] : []), { label: "remove placement", danger: true }],
        };
        case "project-model": return {
            description: `Manage the project-scoped provider, funding, and execution-class decision represented by ${detail.title}.${supplied}`,
            notice: "Credential plaintext is accepted once into the owning seal path and is never projected back into GaugeDesk, agent context, diffs, or audit rows.",
            metrics: [
                { label: "Resolution", value: detail.meta ?? "Project override", note: "nearest scope wins" },
                { label: "Provider", value: detail.title, note: "exact endpoint policy" },
                { label: "Private Home", value: "Allowed", note: "separate re-seal" },
                { label: "Public", value: "Denied", note: "deployment funding is separate" },
            ],
            sections: [
                { title: "Funding source", fields: [
                    { label: "Provider", value: detail.title },
                    { label: "Funding", value: detail.title.includes("Anthropic") ? "Project API credential" : "Organization managed inference" },
                    { label: "Credential reference", value: detail.title.includes("Anthropic") ? "credential:anthropic:v3" : "managed:gaugewright", readOnly: true },
                    { label: "Execution classes", value: "local-interactive · private-home" },
                ] },
                { title: "Policy composition", rows: [
                    { label: "Account default", value: "Overridden for this provider", note: "remains unchanged" },
                    { label: "Organization policy", value: "Satisfied", note: "project cannot widen it" },
                    { label: "Deployment funding", value: "Not configured", note: "no fallback from private credentials" },
                ] },
            ],
            commands: [{ label: "save funding source" }, { label: "rotate credential" }, { label: "remove project override", danger: true }],
        };
        case "sales-setup": {
            const agent = agentProductFor(detail.title);
            const pricingRows: readonly DetailRow[] = agent.name === "Research Analyst" ? [
                { label: "Implementation", value: "$2,000 fixed", note: "once in advance" },
                { label: "Managed operation", value: "$400 fixed", note: "monthly in advance" },
                { label: "Assigned audience", value: "$30 × assigned seats", note: "monthly in advance" },
                { label: "Model and compute", value: "Actual usage cost + 15%", note: "billed monthly after use" },
            ] : agent.name === "Policy Desk" ? [
                { label: "Assigned audience", value: "$30 × assigned seats", note: "monthly in advance" },
                { label: "Model and compute", value: "Actual usage cost + 15%", note: "billed monthly after use" },
            ] : agent.name === "Release Steward" ? [
                { label: "Agent access and managed operation", value: "$6,200 fixed", note: "monthly in advance" },
            ] : [
                { label: "Agent access and review engagement", value: "$4,800 fixed", note: "once on acceptance" },
            ];
            const activeEngagements: readonly DetailRow[] = agent.name === "Research Analyst" ? [
                { label: "AGR-1054", value: "Cosmos Design · $760/month + usage", note: "active · delivery action needed" },
            ] : agent.name === "Policy Desk" ? [
                { label: "AGR-1051", value: "Northstar Labs · $360/month + usage", note: "active · 12 assigned seats" },
            ] : agent.name === "Release Steward" ? [
                { label: "AGR-1048", value: "Hearth & Wire · $6,200/month", note: "active · current period through Sep 17" },
            ] : [];
            const openProposals: readonly DetailRow[] = agent.name === "Research Analyst" ? [
                { label: "Draft", value: "Cosmos Design · revised deployment terms", note: "not sent" },
            ] : agent.name === "Policy Desk" ? [
                { label: "Sent", value: "Northstar Labs · expanded audience", note: "expires Sep 5" },
            ] : [];
            const closedEngagements: readonly DetailRow[] = agent.name === "Architecture Advisor" ? [
                { label: "AGR-1009", value: "Brightworks Studio · $4,800", note: "completed Aug 7, 2026" },
            ] : [];
            const contracted = agent.name === "Research Analyst" ? "$760/month + usage"
                : agent.name === "Policy Desk" ? "$360/month + usage"
                    : agent.name === "Release Steward" ? "$6,200/month" : "$4,800 completed";
            if (action === "view product") return {
                description: `${agent.kind} · ${agent.agentVersion} · ${agent.salesRevision}`,
                metrics: [
                    { label: "Active", value: `${activeEngagements.length}`, note: "accepted engagements" },
                    { label: "Open proposals", value: `${openProposals.length}`, note: "draft or sent" },
                    { label: "Closed", value: `${closedEngagements.length}`, note: "retained history" },
                    { label: activeEngagements.length ? "Contracted" : "Completed sales", value: contracted, note: activeEngagements.length ? "before metered usage" : "lifetime in this fixture" },
                ],
                sections: [
                    { title: "Product", rows: [
                        { label: "Source", value: `${agent.name} · ${agent.agentVersion}`, note: `${agent.kind} in Library` },
                        { label: "Commercial details", value: agent.salesRevision, note: agent.summary },
                        { label: "Price", value: agent.pricing },
                        { label: "Delivery", value: agent.delivery, note: agent.versionPolicy },
                        { label: "Readiness", value: agent.readiness },
                    ] },
                    { title: "Active engagements", intro: activeEngagements.length ? undefined : "There are no active customer commitments for this product.", rows: activeEngagements },
                    { title: "Open proposals", intro: openProposals.length ? undefined : "There are no draft or sent proposals for this product.", rows: openProposals },
                    { title: "Closed engagements", intro: closedEngagements.length ? undefined : "No completed or ended engagements are recorded for this product.", rows: closedEngagements },
                    { title: "Services included", rows: agent.obligations.map((obligation) => ({ label: "Service", value: obligation })) },
                ],
                commands: [
                    { label: "edit product", destination: { appId: "vend", tab: "Products", target: { action: "edit product", title: agent.name, description: agent.summary, kind: agent.kind, meta: agent.agreements } } },
                    { label: "new proposal", destination: { appId: "vend", tab: "Engagements", target: { action: "new proposal", title: "New proposal for Northstar Labs", description: `Started from ${agent.name}.`, kind: agent.name } } },
                    { label: "open engagements", destination: { appId: "vend", tab: "Engagements" } },
                ],
            };
            return {
                description: `${agent.kind} · ${agent.agreements}`,
                sections: [
                    { title: "Product details", fields: [
                        { label: "Product title", value: agent.summary, wide: true },
                        { label: "Description", value: detail.description ?? agent.summary, wide: true },
                    ] },
                    { title: "Price", rows: pricingRows },
                    { title: "Delivery", rows: [
                        { label: "Customer receives", value: agent.delivery },
                        { label: "Updates", value: agent.versionPolicy },
                    ] },
                    { title: "Services included", rows: agent.obligations.map((obligation) => ({ label: "Service", value: obligation })) },
                    { title: "Engagements", rows: [{ label: "Current", value: agent.agreements }] },
                ],
                commands: [
                    { label: "save changes" },
                    { label: "new proposal", destination: { appId: "vend", tab: "Engagements", target: { action: "new proposal", title: "New proposal for Northstar Labs", description: `Started from ${agent.name}.`, kind: agent.name } } },
                ],
            };
        }
        case "client": {
            const clientName = Object.keys(CLIENT_CONTACTS).find((name) => detail.meta === name || detail.title.includes(name)) ?? "Northstar Labs";
            const contacts = clientContacts(clientName);
            const closed = clientName === "Brightworks Studio";
            const hearth = clientName === "Hearth & Wire";
            const cosmos = clientName === "Cosmos Design";
            if (action === "manage recipients") return {
                description: `Reusable names and email addresses for ${clientName} engagements.`,
                notice: "Saved recipients are suggestions for engagements. They do not create GaugeDesk identity or project access.",
                sections: [
                    { title: "Saved recipients", intro: `${contacts.filter((contact) => !contact.archived).length} available`, rows: contacts.filter((contact) => !contact.archived).map((contact) => ({
                        label: "saved", value: contact.name, note: contact.email, actions: [{ label: "remove" }],
                    })) },
                    { title: "Add recipient", fields: [
                        { label: "Name", value: "" },
                        { label: "Email", value: "" },
                    ] },
                ],
                commands: [{ label: "save recipients" }],
            };
            const product = hearth ? "Release Steward" : cosmos ? "Research Analyst" : closed ? "Architecture Advisor" : "Policy Desk";
            const agreement = hearth ? "AGR-1048" : cosmos ? "AGR-1054" : closed ? "AGR-1009" : "AGR-1051";
            const terms = hearth ? "$6,200/month" : cosmos ? "$2,000 + recurring" : closed ? "$8,000 once" : "$360/month + usage";
            const engagementState = closed ? "Closed" : cosmos ? "Setup required" : "Active";
            const billing = hearth ? "$6,200 billed · $0 outstanding" : cosmos ? "$2,000 billed · $2,000 outstanding" : closed ? "$8,000 billed · $0 outstanding" : "$360 billed · usage pending";
            const invoiceRecipient = clientContacts(clientName, "billing")[0];
            return {
                description: `${closed ? "Closed" : "Active"} commercial relationship · ${agreement}.`,
                metrics: [
                    { label: "Engagement", value: engagementState, note: `${product} · ${agreement}` },
                    { label: "Billing", value: cosmos ? "$2,000 due" : "Current", note: billing },
                ],
                sections: [
                    { title: "Engagements", rows: [
                        { label: engagementState, value: `${product} · ${agreement}`, note: terms, actions: [{ label: "view", destination: {
                            appId: "vend", tab: "Engagements", target: { action: "open engagement", title: `${product} · ${clientName}`, kind: "agreement", meta: engagementState.toLowerCase() },
                        } }] },
                    ] },
                    { title: "Billing", rows: [
                        { label: "Customer", value: `${clientName} · Stripe`, note: "used across this client’s engagements" },
                        { label: "Balance", value: billing, note: "Stripe-confirmed billing records" },
                        { label: "Invoices", value: invoiceRecipient?.name ?? "Not assigned", note: invoiceRecipient?.email ?? "set on each engagement" },
                    ] },
                    { title: "Saved recipients", intro: "Suggestions for future engagement assignments.", rows: contacts.filter((contact) => !contact.archived).map((contact) => ({
                        label: "saved", value: contact.name, note: contact.email,
                    })) },
                ],
                commands: closed ? [{ label: "reopen relationship" }] : [
                    { label: "new proposal", destination: { appId: "vend", tab: "Engagements", target: { action: "new proposal", title: `New proposal for ${clientName}`, description: `Started from the ${clientName} client record.` } } },
                    { label: "manage recipients", destination: { appId: "vend", tab: "Clients", target: { action: "manage recipients", title: `${clientName} recipients`, kind: "recipient", meta: clientName } } },
                    { label: "close relationship", danger: true },
                ],
            };
        }
        case "offer":
        case "agreement": return {
            description: "Engagement details are rendered by the explicit engagement surface.",
            sections: [],
            commands: [],
        };
        case "transaction": {
            const isRefund = detail.kind === "refund" || detail.description?.toLowerCase().includes("refund");
            const amount = detail.title.includes("$4,800") ? "$4,800" : detail.title.includes("$800") ? "$800" : "$6,200";
            const fee = amount === "$6,200" ? "$310" : amount === "$4,800" ? "$240" : "$0";
            const providerNet = amount === "$6,200" ? "$5,890" : amount === "$4,800" ? "$4,560" : "−$800";
            const client = detail.title.split(" · ")[0]!;
            if (action === "refund" || action === "issue refund") return {
                description: `Return all or part of the ${amount} payment to ${client}.`,
                notice: "The refund is submitted on the provider’s connected account. The GaugeWright platform fee is returned by default so the provider is not charged for money it gives back.",
                metrics: [
                    { label: "Paid", value: amount, note: "maximum refundable" },
                    { label: "Refunded", value: "$0", note: "before this refund" },
                    { label: "Platform fee", value: fee, note: "returned proportionally" },
                    { label: "Client", value: client, note: "original payer" },
                ],
                sections: [
                    { title: "Refund", fields: [
                        { label: "Amount", value: amount },
                        { label: "Reason", value: "Requested by customer" },
                        { label: "Return platform fee", value: "Yes · proportional to refund", readOnly: true },
                        { label: "Customer notification", value: "Send receipt" },
                    ] },
                    { title: "Original payment", rows: [
                        { label: "Payment", value: amount === "$4,800" ? "pi_6K2…9931" : "pi_3Q7…1842", note: "direct charge on acct_…6P4C" },
                        { label: "Settlement", value: providerNet, note: "provider net before this refund" },
                        { label: "Refund source", value: "Connected account balance", note: "a shortfall can delay payouts" },
                    ] },
                ],
                commands: [{ label: "submit refund", danger: true }],
            };
            return {
                description: `Payment details for ${client}.`,
                metrics: [
                    { label: isRefund ? "Refund" : "Gross", value: amount, note: "USD" },
                    { label: "Status", value: isRefund ? "Refunded" : "Settled", note: "processor confirmed" },
                    { label: "Provider net", value: providerNet, note: isRefund ? "durable adjustment" : "after platform fee" },
                    { label: "Client", value: client, note: "commercial account" },
                ],
                sections: [
                    { title: isRefund ? "Refund" : "Transaction", rows: [
                        { label: "Processor reference", value: isRefund ? "re_7F2…8110" : amount === "$4,800" ? "pi_6K2…9931" : "pi_3Q7…1842", note: "Stripe" },
                        { label: "Client", value: client, note: detail.description },
                        { label: isRefund ? "Refunded" : "Settled", value: isRefund ? "Aug 14 · 09:18 UTC" : amount === "$4,800" ? "Aug 16 · 11:06 UTC" : "Aug 18 · 14:32 UTC", note: "immutable evidence" },
                        { label: "Refunded total", value: isRefund ? amount : "$0", note: "future refunds append another record" },
                    ] },
                    { title: "Processor settlement", rows: [
                        { label: "Platform fee", value: fee, note: isRefund ? "reversed with original record" : "5%" },
                        { label: "Provider net", value: providerNet, note: "settlement projection" },
                        { label: "Charge owner", value: "GaugeWright · acct_…6P4C", note: "direct charge on the provider account" },
                        { label: "Metered cost", value: "Withheld", note: "no matched deployment evidence" },
                    ] },
                ],
                commands: isRefund ? [{ label: "download refund receipt" }] : [{ label: "download receipt" }, { label: "issue refund", danger: true }],
            };
        }
        case "invoice": {
            const isCollection = action === "view all";
            const isVend = detail.appId === "vend";
            const isOverdue = detail.description?.toLowerCase().includes("overdue") ?? false;
            const isEstimate = action === "view estimate" || detail.title.includes("September");
            const isAugust = detail.title.includes("August");
            const amount = isVend ? "$2,000" : scope.kind === "personal"
                ? isEstimate ? "$64.00" : isAugust ? "$58.00" : "$55.00"
                : isEstimate ? "$184.20" : isAugust ? "$171.80" : "$168.40";
            const account = isVend ? "Cosmos Design" : scope.label;
            if (isCollection) return {
                description: `Invoice history and the current processor estimate for ${scope.label}.${supplied}`,
                notice: "These invoices cover GaugeWright services for this organization. Client invoices issued through Commercial Operations remain a separate ledger.",
                metrics: [
                    { label: "Current estimate", value: scope.kind === "personal" ? "$64.00" : "$184.20", note: "closes Sep 1" },
                    { label: "Last invoice", value: scope.kind === "personal" ? "$58.00" : "$171.80", note: "paid Aug 1" },
                    { label: "Payment", value: "Visa · 4242", note: "default" },
                    { label: "Past due", value: "$0", note: "account current" },
                ],
                sections: [{ title: "Invoices", rows: [
                    { label: "September 1", value: "Estimate", note: scope.kind === "personal" ? "$64.00" : "$184.20" },
                    { label: "August 1", value: "Paid", note: scope.kind === "personal" ? "$58.00 · PDF available" : "$171.80 · PDF available" },
                    { label: "July 1", value: "Paid", note: scope.kind === "personal" ? "$55.00 · PDF available" : "$168.40 · PDF available" },
                ] }],
                commands: [{ label: "download statement" }],
            };
            return {
                description: `${isEstimate ? "Current estimate" : "Invoice details"} for ${account}.`,
                notice: isVend ? undefined : "This is a GaugeWright service invoice. Client invoices are in Commercial Operations.",
                metrics: [
                    { label: "Amount", value: amount, note: "USD" },
                    { label: "Status", value: isOverdue ? "Overdue" : isVend ? "Open" : isEstimate ? "Estimate" : "Paid", note: isOverdue ? "8 days" : isVend ? "issued Aug 20" : isEstimate ? "closes Sep 1" : isAugust ? "Aug 1" : "Jul 1", warn: isOverdue },
                    { label: "Due", value: isOverdue ? "Aug 13" : isVend ? "Sep 4" : isEstimate ? "Sep 1" : isAugust ? "Aug 1" : "Jul 1", note: isVend ? "net 15" : "automatic payment" },
                    { label: "Account", value: account, note: isVend ? "client" : "tenant" },
                ],
                sections: [
                    { title: "Invoice", fields: [
                        { label: isVend ? "Client" : "Tenant", value: account, readOnly: true },
                        { label: "Billing email", value: isVend ? "billing@cosmos.example" : scope.kind === "personal" ? "jack@gaugewright.com" : "billing@gaugewright.com" },
                        { label: "Invoice number", value: isVend ? "INV-2026-1054" : isEstimate ? "EST-2026-09" : isAugust ? "GW-2026-08" : "GW-2026-07", readOnly: true },
                        { label: "Period / due date", value: isVend ? "Issued Aug 20 · due Sep 4" : isEstimate ? "Aug 1–31 · closes Sep 1" : isAugust ? "July service · paid Aug 1" : "June service · paid Jul 1" },
                    ] },
                    { title: "Line items & payment", rows: isVend ? [
                        { label: "Research Analyst · implementation", value: "$2,000", note: "AGR-1054" },
                        { label: "Payment", value: "No settled payment", note: "processor checked 2 minutes ago" },
                    ] : [
                        { label: "Managed Project Host", value: scope.kind === "personal" ? "$40.00" : "$120.00", note: "tenant service" },
                        { label: "Backup", value: scope.kind === "personal" ? "$8.00" : "$24.00", note: "encrypted retention" },
                        { label: "Managed inference", value: isEstimate ? scope.kind === "personal" ? "$16.00" : "$40.20" : "Included", note: "current service period" },
                        { label: "Payment", value: isEstimate ? "Not yet charged" : "Visa · 4242 settled", note: "processor evidence" },
                    ] },
                ],
                commands: isEstimate ? [{ label: "download estimate" }]
                    : isVend || isOverdue ? [{ label: "copy invoice link" }, { label: "void invoice", danger: true }]
                        : [{ label: "download PDF" }, { label: "email receipt" }],
            };
        }
        case "stripe-connect": {
            const toPayments = (nextAction: string, title: string, description: string): DetailCommand["destination"] => ({
                appId: "vend", tab: "Payments", target: { action: nextAction, title, description, kind: "Stripe Connect" },
            });
            if (action.includes("requirement") || action.startsWith("resolve")) return {
                description: "Provide the one item Stripe still needs to keep the connected account current.",
                notice: "Payments and payouts are active today. If this is not completed by September 3, Stripe can restrict payouts until it is verified.",
                metrics: [
                    { label: "Due", value: "Sep 3", note: "12 days remaining", warn: true },
                    { label: "Impact", value: "Payouts", note: "only after the deadline" },
                    { label: "Collected by", value: "Stripe", note: "not stored by GaugeWright" },
                    { label: "Status", value: "Currently due", note: "account requirement", warn: true },
                ],
                sections: [
                    { title: "Requested information", rows: [
                        { label: "Representative address", value: "Home address", note: "required for identity verification" },
                        { label: "Person", value: "Jack · account representative", note: "owner of the connected account" },
                        { label: "Current restriction", value: "None", note: "charges and payouts remain enabled" },
                    ] },
                    { title: "Secure handoff", rows: [
                        { label: "Authentication", value: "Stripe account authentication", note: "the account owner completes this step" },
                        { label: "Return", value: "Payments", note: "status updates from Stripe after verification" },
                    ] },
                ],
                commands: [{ label: "continue to Stripe" }],
            };
            if (action.includes("processing setup")) return {
                description: "How customer payments move through the connected account.",
                metrics: [
                    { label: "Charge type", value: "Direct", note: "provider account owns the payment" },
                    { label: "Merchant", value: scope.label, note: "shown to the customer" },
                    { label: "Platform fee", value: "5%", note: "application fee" },
                    { label: "Currency", value: "USD", note: "settlement default" },
                ],
                sections: [
                    { title: "Payment ownership", rows: [
                        { label: "Charges", value: "Created on acct_…6P4C", note: "the provider is merchant of record" },
                        { label: "Stripe processing fees", value: "Connected account", note: "deducted from its balance" },
                        { label: "Disputes and losses", value: "Connected account balance", note: "evidence is submitted from Payments" },
                        { label: "Platform revenue", value: "5% application fee", note: "recorded separately by Stripe" },
                    ] },
                    { title: "Refund behavior", rows: [
                        { label: "Customer refund", value: "Connected account balance", note: "full or partial" },
                        { label: "Platform fee", value: "Returned proportionally by default", note: "explicit on every refund command" },
                        { label: "Access and delivery", value: "Never changed by payment alone", note: "commercial commands remain explicit" },
                    ] },
                ],
                commands: [{ label: "manage Stripe account", destination: toPayments("manage Stripe account", "Stripe account", "Connected account identity, capabilities, and requirements") }],
            };
            if (action.includes("public details")) return {
                description: "Control the business details customers see on card statements and payment receipts.",
                notice: "Stripe validates the statement descriptor and may derive its card prefix from the business profile.",
                metrics: [
                    { label: "Descriptor", value: "GAUGEWRIGHT", note: "card statements" },
                    { label: "Support", value: "Current", note: "email and website" },
                    { label: "Branding", value: "Configured", note: "provider identity" },
                    { label: "Country", value: "US", note: "connected account" },
                ],
                sections: [
                    { title: "Customer-facing business", fields: [
                        { label: "Statement descriptor", value: "GAUGEWRIGHT" },
                        { label: "Business website", value: "https://gaugewright.com" },
                        { label: "Support email", value: "support@gaugewright.com" },
                        { label: "Support phone", value: "+1 555 014 0184" },
                    ] },
                    { title: "Receipts and checkout", rows: [
                        { label: "Business name", value: scope.label, note: "provider branding" },
                        { label: "Receipt contact", value: "support@gaugewright.com", note: "customer support" },
                    ] },
                ],
                commands: [{ label: "save public details" }],
            };
            if (action.includes("dispute") || detail.kind === "dispute") return {
                description: "Respond to a disputed customer payment before the evidence deadline.",
                notice: "The disputed amount and Stripe dispute fee are held from the connected account balance while Stripe reviews the case.",
                metrics: [
                    { label: "Amount", value: "$760", note: "Cosmos Design" },
                    { label: "Reason", value: "Not recognized", note: "cardholder claim" },
                    { label: "Evidence due", value: "Aug 29", note: "7 days", warn: true },
                    { label: "Status", value: "Needs response", note: "no evidence submitted", warn: true },
                ],
                sections: [
                    { title: "Payment", rows: [
                        { label: "Payment", value: "pi_8R1…4402", note: "direct charge on acct_…6P4C" },
                        { label: "Client", value: "Cosmos Design", note: "AGR-1054 · Research Analyst" },
                        { label: "Paid", value: "Aug 20 · Visa ending 4242", note: "recurring charge" },
                    ] },
                    { title: "Evidence", fields: [
                        { label: "Service description", value: "Research Analyst managed service · August" },
                        { label: "Customer communication", value: "Attach email or agreement acknowledgement" },
                        { label: "Delivery evidence", value: "AGR-1054 · current delivery record" },
                        { label: "Additional evidence", value: "Optional" },
                    ] },
                ],
                commands: [{ label: "continue to Stripe to submit evidence" }, { label: "accept dispute", danger: true }],
            };
            if (action.includes("tax") || action.includes("document")) return {
                description: "Keep the connected account’s tax profile and processor documents accessible.",
                metrics: [
                    { label: "Tax profile", value: "Current", note: "US business" },
                    { label: "Delivery", value: "Electronic", note: "consent on file" },
                    { label: "2025 tax form", value: "No form", note: "none issued by Stripe" },
                    { label: "Statements", value: "Monthly", note: "August available Sep 1" },
                ],
                sections: [
                    { title: "Documents", rows: [
                        { label: "2025 tax form", value: "No form issued", note: "status reported by Stripe" },
                        { label: "July 2026 statement", value: "Available", note: "payments, refunds, fees, and payouts" },
                        { label: "June 2026 statement", value: "Available", note: "payments, refunds, fees, and payouts" },
                    ] },
                    { title: "Tax profile", rows: [
                        { label: "Legal name", value: scope.label, note: "verified" },
                        { label: "Tax ID", value: "••-•••4821", note: "held by Stripe" },
                        { label: "Electronic delivery", value: "On", note: "consent recorded by Stripe" },
                    ] },
                ],
                commands: [{ label: "continue to Stripe for tax profile" }, { label: "download July statement" }],
            };
            if (action.includes("add funds")) return {
                description: "Add money to the connected account balance to cover refunds, disputes, or a future shortfall.",
                metrics: [
                    { label: "Available", value: "$2,340", note: "connected balance" },
                    { label: "Negative", value: "$0", note: "nothing owed" },
                    { label: "Pending debits", value: "$760", note: "open dispute" },
                    { label: "Currency", value: "USD", note: "bank transfer" },
                ],
                sections: [
                    { title: "Transfer", fields: [
                        { label: "Amount", value: "$1,000" },
                        { label: "From", value: "Operating account · 6789" },
                    ] },
                    { title: "Before you transfer", rows: [
                        { label: "Use", value: "Balance protection", note: "does not count as customer revenue" },
                        { label: "Availability", value: "Usually 1–2 business days", note: "Stripe confirms the date" },
                    ] },
                ],
                commands: [{ label: "continue to Stripe" }],
            };
            if (action.includes("balance") || action.includes("payout") || action.includes("bank")) return {
                description: "See what is available, what is still settling, and where Stripe sends it.",
                metrics: [
                    { label: "Available", value: "$2,340", note: "can be paid out" },
                    { label: "Pending", value: "$8,420", note: "still settling" },
                    { label: "Next payout", value: "Aug 24", note: "$8,420 expected" },
                    { label: "Negative", value: "$0", note: "account current" },
                ],
                sections: [
                    { title: "Payout settings", rows: [
                        { label: "Destination", value: "Operating account · 6789", note: "verified bank account" },
                        { label: "Schedule", value: "Automatic · weekly", note: "every Monday" },
                        { label: "Minimum", value: "$100", note: "smaller balances roll forward" },
                    ] },
                    { title: "Recent payouts", rows: [
                        { label: "Aug 17", value: "$5,890 · paid", note: "po_3V8…8103" },
                        { label: "Aug 10", value: "$4,560 · paid", note: "po_2D4…1942" },
                        { label: "Aug 3", value: "$1,780 · paid", note: "po_9K1…5227" },
                    ] },
                ],
                commands: [
                    { label: "change bank account" },
                    { label: "change payout schedule" },
                    { label: "add funds", destination: toPayments("add funds", "Add funds", "Cover refunds, disputes, or a negative balance") },
                ],
            };
            if (action.includes("support")) return {
                description: "Get help for the connected Stripe account without losing the organization context.",
                sections: [
                    { title: "Stripe account support", rows: [
                        { label: "Account", value: `${scope.label} · acct_…6P4C`, note: "included with the support handoff" },
                        { label: "Payments and refunds", value: "Stripe support", note: "processor records and payment failures" },
                        { label: "Disputes and reserves", value: "Stripe support", note: "evidence, holds, and account reviews" },
                        { label: "Payouts and verification", value: "Stripe support", note: "bank, identity, and payout timing" },
                        { label: "GaugeWright products", value: "GaugeWright support", note: "products, engagements, deployment, and client access" },
                    ] },
                ],
                commands: [{ label: "continue to Stripe support" }],
            };
            return {
                description: "Account identity, capabilities, requirements, and customer-facing payment details.",
                metrics: [
                    { label: "Account", value: "Verified", note: "acct_…6P4C" },
                    { label: "Payments", value: "Active", note: "card_payments" },
                    { label: "Payouts", value: "Active", note: "bank verified" },
                    { label: "Requirements", value: "1 due", note: "Sep 3 · no restriction", warn: true },
                ],
                sections: [
                    { title: "Connected account", rows: [
                        { label: "Business", value: scope.label, note: "United States · USD" },
                        { label: "Account", value: "acct_…6P4C", note: "platform account mapping" },
                        { label: "Onboarding", value: "Details submitted", note: "Stripe-hosted collection" },
                        { label: "Authentication", value: "Stripe account authentication", note: "required for sensitive changes" },
                    ] },
                    { title: "Capabilities", rows: [
                        { label: "Card payments", value: "Active", note: "direct charges" },
                        { label: "Payouts", value: "Active", note: "external account verified" },
                        { label: "Requirement collection", value: "Stripe", note: "future requirements appear in Payments" },
                        { label: "Statement descriptor", value: "GAUGEWRIGHT", note: "current" },
                    ] },
                ],
                commands: [
                    { label: "resolve requirement", destination: toPayments("resolve requirement", "Representative address", "Required by Sep 3 to prevent a payout restriction") },
                    { label: "edit public details", destination: toPayments("edit public details", "Public business details", "Statement descriptor, website, and support contact") },
                    { label: "manage payouts", destination: toPayments("manage payouts", "Balance & payouts", "Available balance, bank account, and schedule") },
                    { label: "open Stripe support", destination: toPayments("open Stripe support", "Stripe support", "Help for this connected account") },
                ],
            };
        }
        case "organization": return {
            description: `Organization identity, ownership, and verified-domain detail for ${detail.title}.${supplied}`,
            metrics: [
                { label: "Members", value: "3 active", note: "one owner" },
                { label: "Domains", value: "1 pending", note: "DNS proof" },
                { label: "Projects", value: "2", note: "independently homed" },
                { label: "Owner", value: "Jack Scully", note: "break-glass" },
            ],
            sections: [
                { title: "Organization", fields: [
                    { label: "Display name", value: scope.label },
                    { label: "Organization ID", value: "organization:9f4a…72c1", readOnly: true },
                ] },
                { title: "Ownership & domain", rows: [
                    { label: "Owner", value: "Jack Scully", note: "jack@gaugewright.com" },
                    { label: "gaugewright.com", value: "Pending DNS proof", note: "auto-join remains unavailable" },
                ] },
            ],
            commands: [{ label: "save organization" }, { label: "transfer ownership" }, { label: "delete organization", danger: true }],
        };
        case "member": return {
            description: `Membership, fixed tenant role, explicit project grants, and live sessions for ${detail.title}.${supplied}`,
            notice: "Role and project admission are separate. A paid seat is neither, and deprovisioning blocks future access without rewriting history.",
            metrics: [
                { label: "Status", value: detail.meta === "pending" ? "Pending" : "Active", note: "admitted membership" },
                { label: "Tenant role", value: detail.kind && ["owner", "admin", "member", "viewer"].includes(detail.kind) ? detail.kind : detail.meta ?? "member", note: "fixed role set" },
                { label: "Project grants", value: "2", note: "explicit records" },
                { label: "Sessions", value: "1 active", note: "reported client" },
            ],
            sections: [
                { title: "Membership", fields: [
                    { label: "Person", value: detail.title },
                    { label: "Email / authority", value: detail.description ?? "member@gaugewright.com" },
                    { label: "Tenant role", value: detail.kind && ["owner", "admin", "member", "viewer"].includes(detail.kind) ? detail.kind : detail.meta ?? "member" },
                ] },
                { title: "Project grants", rows: [
                    { label: "GaugeDesk", value: "Active", note: "explicit member → project grant" },
                    { label: "GaugeWright operations", value: "Active", note: "explicit member → project grant" },
                ] },
                { title: "Sessions", rows: [
                    { label: "GaugeDesk desktop 0.4.6", value: "Admitted", note: "Linux · idle 2 minutes" },
                ] },
            ],
            commands: [{ label: "save membership" }, { label: "revoke selected project grant", danger: true }, { label: "deactivate member", danger: true }],
        };
        case "identity": return {
            description: `Identity-provider, verified-domain, and provisioning configuration for ${detail.title}.${supplied}`,
            notice: "Test results and sync counts are operational evidence. Membership and enforcement become truth only when their owning commands are admitted.",
            metrics: [
                { label: "SSO", value: "Not configured", note: "OIDC or SAML" },
                { label: "SCIM", value: "Not configured", note: "token absent" },
                { label: "Domains", value: "0 verified", note: "JIT disabled" },
                { label: "Enforcement", value: "Off", note: "owner remains break-glass" },
            ],
            sections: [
                { title: "Connection", fields: [
                    { label: "Protocol", value: "OIDC" },
                    { label: "Metadata / issuer URL", value: "https://idp.example/.well-known/openid-configuration", wide: true },
                    { label: "Subject claim", value: "sub" },
                    { label: "Roles claim", value: "groups" },
                ] },
                { title: "Provisioning", rows: [
                    { label: "JIT", value: "Off", note: "requires a verified email domain" },
                    { label: "SCIM", value: "Disconnected", note: "no token issued" },
                    { label: "Group mappings", value: "0", note: "tenant roles only" },
                ] },
            ],
            commands: [{ label: "test connection" }, { label: "save identity connection" }, { label: "enforce SSO" }],
        };
        case "policy": throw new Error("Organization Policy changes are reviewed inline.");
        case "project-host": return {
            description: `Reachability, project Homes, execution profiles, storage, and lifecycle controls for ${detail.title}.${supplied}`,
            notice: "This Project Host may carry authoritative project Homes. Trusted Devices remain separate; selecting either one grants no project access.",
            metrics: [
                { label: "Reachability", value: detail.title.includes("Office") ? "Unreachable" : "Available", note: detail.title.includes("Office") ? "19 hours stale" : "refreshed just now", warn: detail.title.includes("Office") },
                { label: "Management", value: detail.kind ?? "Managed", note: "Project Host kind" },
                { label: "Projects", value: "2", note: "authoritative Homes" },
                { label: "Region", value: detail.title.includes("desktop") ? "Local" : "us-east", note: "physical custody" },
            ],
            sections: [
                { title: "Project Host", fields: [
                    { label: "Name", value: detail.title },
                    { label: "Project Host ID", value: `host:${detail.title.toLowerCase().replaceAll(" ", "-")}`, readOnly: true },
                    { label: "Region", value: detail.title.includes("desktop") ? "local" : "us-east", readOnly: true },
                    { label: "Retention", value: "30 days" },
                ] },
                { title: "Execution profiles", rows: [
                    { label: "Background work", value: "Available", note: "queued work within an active chat" },
                    { label: "Isolated workspace", value: "Metered", note: "default-deny egress · no privileged Docker" },
                ] },
                { title: "Project Homes", rows: [
                    { label: projectName, value: "Authoritative", note: "move only through handoff" },
                    { label: "GaugeWright operations", value: "Authoritative", note: "separate project scope" },
                ] },
            ],
            commands: detail.title.includes("Office") ? [{ label: "retry reachability" }, { label: "disconnect Project Host", danger: true }] : [{ label: "save Project Host settings" }, { label: "suspend Project Host", danger: true }],
        };
        case "backup": return {
            description: `Recovery points, retention, holders, and restore controls for ${detail.title}.${supplied}`,
            notice: "Backups are sealed. Recovery holders retain keys on their Trusted Devices; restore creates a new admitted operation and never rewrites the source evidence.",
            metrics: [
                { label: "Status", value: "Healthy", note: "encrypted" },
                { label: "Last point", value: "7 hours ago", note: "09:10 UTC" },
                { label: "Retention", value: "30 days", note: "daily" },
                { label: "Holders", value: scope.kind === "organization" ? "2" : "1", note: "Trusted Device-held keys" },
            ],
            sections: [
                { title: "Schedule & retention", fields: [
                    { label: "Schedule", value: "Daily · 02:00 UTC" },
                    { label: "Retention", value: "30 days" },
                    { label: "Destination", value: scope.kind === "signed-out-local" ? "Local drive" : "GaugeWright managed backup" },
                    { label: "Encryption", value: "Tenant recovery key", readOnly: true },
                ] },
                { title: "Recovery points", rows: [
                    { label: "Aug 21 · 09:10", value: "Healthy", note: "restorable to a new Project Host" },
                    { label: "Aug 20 · 09:08", value: "Healthy", note: "integrity verified" },
                    { label: "Aug 19 · 09:12", value: "Healthy", note: "integrity verified" },
                ] },
                { title: "Recovery holders", rows: [
                    { label: "Jack · GaugeDesk desktop", value: "Active", note: "key remains on Trusted Device" },
                    { label: "Maya · recovery Trusted Device", value: scope.kind === "organization" ? "Active" : "Not configured", note: "removal affects future restore" },
                ] },
            ],
            commands: [{ label: "save schedule" }, { label: "create recovery point" }, { label: "restore from selected point" }, { label: "turn off backups", danger: true }],
        };
        case "deployment": return {
            description: `Technical runtime, release, audience, funding, and collection controls for ${detail.title}.${supplied}`,
            notice: "This deployment belongs to the project and its Panel placement. Client terms and entitlement remain with the linked engagement, when there is one.",
            metrics: [
                { label: "Status", value: "Active", note: "new sessions admitted" },
                { label: "Audience", value: detail.title.includes("website") ? "Anonymous" : "Authenticated", note: "release ceiling" },
                { label: "Spend", value: "$8.42 / $25", note: "aggregate guard" },
                { label: "Sessions", value: "18", note: "current release" },
            ],
            sections: [
                { title: "Runtime", fields: [
                    { label: "Deployment", value: detail.title },
                    { label: "Allowed origin", value: "https://www.example.com" },
                    { label: "Active release", value: "release:sha256:91ab…c3", readOnly: true },
                    { label: "Audience", value: detail.title.includes("website") ? "Anonymous allowed" : "OIDC required" },
                ] },
                { title: "Funding & guards", rows: [
                    { label: "Credential", value: "deployment:openai:prod", note: "exact hosted reference" },
                    { label: "Per-turn spend", value: "$0.50", note: "future admission" },
                    { label: "Per-session spend", value: "$3.00", note: "future admission" },
                    { label: "Concurrency", value: "25 sessions", note: "hard guard" },
                ] },
                { title: "Collection", rows: [
                    { label: "Waiting", value: "3 session envelopes", note: "sealed until admitted" },
                    { label: "Recipient", value: `${projectName} quarantine`, note: "exact project binding" },
                ] },
            ],
            commands: [{ label: "save runtime controls" }, { label: "activate selected release" }, { label: "drain collections" }, { label: "pause deployment", danger: true }],
        };
        case "software": return {
            description: `Client compatibility policy and current admission posture for ${detail.title}.${supplied}`,
            notice: "Reported builds are compatibility evidence, not Trusted Device attestation. Unknown or below-floor clients fail closed outside an explicit grace window.",
            metrics: [
                { label: "Channel", value: "Stable", note: "allowed" },
                { label: "Minimum version", value: "Not set", note: "warning", warn: true },
                { label: "Protocol", value: "4", note: "minimum" },
                { label: "Compatible clients", value: "2", note: "current sessions" },
            ],
            sections: [
                { title: "Admission policy", fields: [
                    { label: "Allowed channel", value: "Stable" },
                    { label: "Minimum GaugeDesk version", value: "0.4.6" },
                    { label: "Minimum protocol", value: "4" },
                    { label: "Grace deadline", value: "Not set" },
                ] },
                { title: "Effect", rows: [
                    { label: "Compatible", value: "Organization data admitted", note: "other gates still apply" },
                    { label: "Below floor", value: "Recovery-only", note: "updater and logout remain reachable" },
                    { label: "Missing report", value: "Denied", note: "unless within explicit grace" },
                ] },
            ],
            commands: [{ label: "submit software policy" }, { label: "discard draft" }],
        };
        case "client-session": return {
            description: `Authenticated actor, reported build, software admission, and revocation controls for ${detail.title}.${supplied}`,
            notice: "This is a live session, not a Trusted Device record. Revocation ends future requests and does not erase the actor's admitted history.",
            metrics: [
                { label: "Admission", value: detail.kind ?? "Admitted", note: "current request posture" },
                { label: "Actor", value: detail.title.split(" · ")[0]!, note: "directory authority" },
                { label: "Build", value: detail.title.includes("0.4.3") ? "0.4.3" : "0.4.6", note: "reported" },
                { label: "Idle", value: "2 minutes", note: "operational" },
            ],
            sections: [
                { title: "Session evidence", rows: [
                    { label: "Client", value: detail.title, note: detail.description },
                    { label: "Protocol", value: "4", note: "meets current floor" },
                    { label: "Release channel", value: "Stable", note: "allowed" },
                    { label: "Last request", value: "2 minutes ago", note: "tenant-local evidence" },
                ] },
                { title: "Authority", rows: [
                    { label: "Tenant role", value: "Member", note: "resolved from directory" },
                    { label: "Project access", value: "Explicit grants only", note: "session itself grants nothing" },
                ] },
            ],
            commands: [{ label: "revoke session", danger: true }],
        };
        case "billing": return {
            description: `Subscription, payment, invoice, seat, and usage detail for ${detail.title}.${supplied}`,
            notice: "Billing gates future paid service only. A seat, payment, invoice, or managed-plan state is never project or data authority.",
            metrics: [
                { label: "Status", value: detail.meta ?? "Active", note: "billing projection" },
                { label: "Current period", value: "$184.20", note: "estimate" },
                { label: "Payment", value: "Visa · 4242", note: "default" },
                { label: "Next invoice", value: "Sep 1", note: "processor estimate" },
            ],
            sections: [
                { title: "Billing record", fields: [
                    { label: "Item", value: detail.title },
                    { label: "Billing contact", value: scope.kind === "personal" ? "jack@gaugewright.com" : "billing@gaugewright.com" },
                    { label: "Payment method", value: "Visa ending 4242" },
                ] },
                { title: "Current period", rows: [
                    { label: "Managed Project Host", value: "$120.00", note: "active service" },
                    { label: "Backup", value: "$24.00", note: "30-day retention" },
                    { label: "Managed inference", value: "$40.20", note: "42k tokens" },
                    { label: "Seats", value: scope.kind === "personal" ? "Not applicable" : "3 of 5", note: "payment is not assignment" },
                ] },
                { title: "Invoice history", rows: [
                    { label: "September 1", value: "Estimate", note: "$184.20" },
                    { label: "August 1", value: "Paid", note: "$171.80 · receipt available" },
                    { label: "July 1", value: "Paid", note: "$168.40 · receipt available" },
                ] },
            ],
            commands: [{ label: "save billing details" }],
        };
        case "account": return {
            description: `Person-scoped identity, membership, sessions, and recovery detail for ${detail.title}.${supplied}`,
            notice: "Account identity and tenant membership route you to project Homes. Neither one grants access to project work without Home admission.",
            metrics: [
                { label: "Account", value: "Active", note: "Jack Scully" },
                { label: "Memberships", value: "2 active", note: "1 invitation" },
                { label: "Sessions", value: "2", note: "one current" },
                { label: "Recovery", value: "Available", note: "root-held Trusted Devices" },
            ],
            sections: [
                { title: "Account", fields: [
                    { label: "Display name", value: "Jack Scully" },
                    { label: "Primary email", value: "jack@gaugewright.com", readOnly: true },
                    { label: "Account root", value: "root:7a91…c2", readOnly: true },
                ] },
                { title: "Membership / session detail", rows: [
                    { label: detail.title, value: detail.meta ?? "Active", note: detail.description },
                    { label: "Current GaugeDesk", value: "Admitted", note: "Linux · Aug 21" },
                    { label: "Other session", value: "Chrome on macOS", note: "last active Aug 19" },
                ] },
            ],
            commands: [{ label: "save account details" }, { label: "end other sessions" }, { label: "leave organization", danger: true }],
        };
        case "model": return {
            description: `Provider connection, model catalog, credential scope, and usage controls for ${detail.title}.${supplied}`,
            notice: "Provider sign-in is separate from GaugeWright sign-in. A credential's allowed execution classes are explicit and public deployment is never inherited.",
            metrics: [
                { label: "Connection", value: detail.meta ?? "Connected", note: "credential reference" },
                { label: "Models", value: detail.title.includes("Local") ? "2" : "6", note: "enabled catalog" },
                { label: "Execution", value: "Local interactive", note: "current grant" },
                { label: "Usage", value: "42k tokens", note: "current period" },
            ],
            sections: [
                { title: "Provider", fields: [
                    { label: "Name", value: detail.title },
                    { label: "Endpoint", value: detail.title.includes("Local") ? "http://localhost:11434/v1" : "Fixed provider host" },
                    { label: "Authentication", value: detail.title.includes("Codex") ? "Provider account" : "Sealed API credential" },
                    { label: "Execution classes", value: "local-interactive" },
                ] },
                { title: "Model catalog", rows: [
                    { label: "Primary", value: detail.title.includes("Local") ? "qwen3-coder" : "GPT-5.6", note: "enabled" },
                    { label: "Secondary", value: detail.title.includes("Local") ? "deepseek-r1:14b" : "GPT-5.4", note: "enabled" },
                    { label: "Public deployment", value: "Denied", note: "requires distinct deployment funding" },
                ] },
            ],
            commands: [{ label: "save provider" }, { label: "test connection" }, { label: "reauthenticate provider" }, { label: "remove provider", danger: true }],
        };
        case "trusted-device": return {
            description: `Identity, activity, project routing, and lifecycle controls for ${detail.title}.${supplied}`,
            notice: "This Trusted Device acts as you, but remains a client. It can discover project routes and request access; it never becomes a Project Host or carries a project Home.",
            metrics: [
                { label: "Standing", value: detail.meta ?? "Active", note: "Trusted Device registry" },
                { label: "Last seen", value: "8 minutes ago", note: "operational" },
                { label: "Identity", value: "Delegated", note: "acts as Jack Scully" },
                { label: "Project data", value: "On each Home", note: "not stored by linking" },
            ],
            sections: [
                { title: "Trusted Device", fields: [
                    { label: "Name", value: detail.title },
                    { label: "Type", value: detail.kind ?? (detail.title.includes("iPhone") ? "phone" : detail.title.includes("iPad") ? "tablet" : "computer"), readOnly: true },
                    { label: "Trusted Device ID", value: `device:${detail.title.toLowerCase().replaceAll(" ", "-")}`, readOnly: true },
                    { label: "Trusted", value: "Aug 12", readOnly: true },
                ] },
                { title: "Access & activity", rows: [
                    { label: "Account identity", value: "Jack Scully", note: "delegated by the account root" },
                    { label: "Project routes", value: detail.meta === "revoked" ? "None" : "2 opaque routes", note: "each Home still decides access" },
                    { label: "Project Homes", value: "None on this Trusted Device", note: "client-only connection" },
                    { label: "Last activity", value: detail.meta === "revoked" ? "Jul 18" : "8 minutes ago", note: "account session evidence" },
                ] },
                { title: "What lifecycle actions do", rows: [
                    { label: "Rename", value: "Changes this roster label", note: "no authority change" },
                    { label: "Revoke", value: "Ends future account requests", note: "history remains; local files are not remotely erased" },
                ] },
            ],
            commands: detail.meta === "revoked" ? [] : [{ label: "rename Trusted Device" }, { label: "revoke trust", danger: true }],
        };
        case "application": return {
            description: `Local GaugeDesk behavior and attention preferences for ${detail.title}.${supplied}`,
            notice: "These settings affect this application only. They do not alter tenant policy, project authority, Agent methods, or server admission.",
            metrics: [
                { label: "Scope", value: "This application", note: "local preference" },
                { label: "Sync", value: "Off", note: "not account policy" },
                { label: "Attention", value: "Task bar", note: "questions and conflicts" },
                { label: "Automatic keep", value: "2 paths", note: "local UI rule" },
            ],
            sections: [
                { title: "Preference", fields: [
                    { label: "Setting", value: detail.title },
                    { label: "Current value", value: detail.meta ?? "Enabled" },
                ] },
                { title: "Scope boundary", rows: [
                    { label: "Tenant policy", value: "Unaffected", note: "server remains authoritative" },
                    { label: "Project settings", value: "Unaffected", note: "no authority crossing" },
                    { label: "Other Trusted Devices", value: "Unaffected", note: "unless later made an account preference" },
                ] },
            ],
            commands: [{ label: "save application preference" }, { label: "restore local default" }],
        };
        case "sign-in": return {
            description: `Start or inspect the account handoff for ${detail.title}.${supplied}`,
            notice: "Signing in links this GaugeDesk to an account for identity, memberships, and route discovery. It does not move local projects or grant access to a Home.",
            metrics: [
                { label: "GaugeDesk", value: "Signed out", note: "local work available" },
                { label: "Account", value: "Not linked", note: "no Desk account session" },
                { label: "Local projects", value: "2", note: "remain on this computer" },
                { label: "Provider login", value: "Separate", note: "provider connections unchanged" },
            ],
            sections: [
                { title: "Sign-in handoff", fields: [
                    { label: "Sign-in", value: "Email, passkey, social sign-in, or organization SSO" },
                    { label: "Surface", value: "desk.gaugewright.com", readOnly: true },
                ] },
                { title: "After sign-in", rows: [
                    { label: "Identity", value: "Account root delegated", note: "this Trusted Device is added only through explicit pairing" },
                    { label: "First sign-in", value: "Free Personal tenant created", note: "one owner membership; not presented as an organization" },
                    { label: "Memberships", value: "Discovered", note: "membership is not project access" },
                    { label: "Project routes", value: "Opaque endpoints", note: "each Home still admits" },
                    { label: "Hosted Home", value: "None", note: "connect a computer or explicitly add Cloud Home" },
                    { label: "Local work", value: "Unchanged", note: "no silent handoff" },
                ] },
            ],
            commands: [{ label: "continue to sign in" }, { label: "cancel sign-in" }],
        };
    }
}

function NewOrganizationView(props: { onCancel: () => void }): JSX.Element {
    const [name, setName] = createSignal("");
    const [created, setCreated] = createSignal(false);
    return <><PageHeader eyebrow="Organization" title={created() ? name().trim() : "New organization"} description={created() ? "Organization created." : "Create the organization first. Add paid services only when they are needed."} />
        <DashboardGrid surface>
        <Show when={created()} fallback={<section class="admin-section gaugeapp-form-card"><h4>Organization</h4>
            <div class="gaugeapp-field-grid gaugeapp-field-grid-single"><label>Organization name<input value={name()} onInput={(event) => setName(event.currentTarget.value)} placeholder="Acme Studio" /></label></div>
            <p class="gaugeapp-field-note">You become the owner. GaugeWright creates a permanent organization ID and an owner membership. It does not create a Cloud Home, buy seats, enable Commercial Operations, or activate Enterprise controls.</p>
            <div class="bar"><button class="tree-action" type="button" onClick={props.onCancel}>cancel</button><button type="button" disabled={!name().trim()} onClick={() => setCreated(true)}>create base organization</button></div>
        </section>}><>
            <Notice tone="neutral"><strong>{name().trim()} is ready.</strong> No paid services or projects were added.</Notice>
            <section class="admin-section"><SectionHeading title="Organization" />
                <Definition label="Organization ID" value="organization:new:7c31…9a02" note="permanent" />
                <Definition label="Owner" value="Jack Scully" note="organization owner" />
                <div class="bar"><button type="button" onClick={props.onCancel}>enter organization</button></div>
            </section>
        </></Show>
        </DashboardGrid>
    </>;
}

function ProjectView(props: {
    scope: ScopeFixture;
    project: ProjectFixture;
    tab: string;
    onNavigate: (app: GaugeAppId, tab: string, target?: InteractionTarget) => void;
}): JSX.Element {
    if (props.tab === "Project Work") return <ProjectWorkView scope={props.scope} project={props.project} />;
    if (props.tab === "Project Placements") return <ProjectPlacementsView scope={props.scope} project={props.project} />;
    if (props.tab === "Project Models") return <ProjectModelAccessView scope={props.scope} project={props.project} />;
    if (props.project.isPersonal) return <ProjectWorkView scope={props.scope} project={props.project} />;
    return <ProjectPermissionsView scope={props.scope} project={props.project} onNavigate={props.onNavigate} />;
}

function ProjectPermissionsView(props: {
    scope: ScopeFixture;
    project: ProjectFixture;
    onNavigate: (app: GaugeAppId, tab: string, target?: InteractionTarget) => void;
}): JSX.Element {
    return <ShareableProjectPermissionsView scope={props.scope} project={props.project} onNavigate={props.onNavigate} />;
}

function ShareableProjectPermissionsView(props: {
    scope: ScopeFixture;
    project: ProjectFixture;
    onNavigate: (app: GaugeAppId, tab: string, target?: InteractionTarget) => void;
}): JSX.Element {
    const report = useContext(ActionFeedbackContext);
    const [action, setAction] = createSignal<"member" | "person" | "handoff" | null>(null);
    const [member, setMember] = createSignal("Nora Chen · member");
    const [recipient, setRecipient] = createSignal("");
    const [personAccess, setPersonAccess] = createSignal<"work" | "view">("work");
    const [pendingInvite, setPendingInvite] = createSignal<string | null>(null);
    const [handoffTarget, setHandoffTarget] = createSignal("");
    const organization = () => props.scope.kind === "organization";
    const signedOut = () => props.scope.kind === "signed-out-local";
    const personal = () => props.scope.kind === "personal";
    const openPersonInvite = () => {
        if (signedOut()) {
            props.onNavigate("settings", "Sign In");
            return;
        }
        setAction("person");
    };
    // Backend gap: desktop invitations still need recipient lookup and
    // relay-safe acceptance. Project access intentionally stays person-based.
    return <>
        <PageHeader eyebrow={`${props.project.name} / Project`} title={organization() ? "People & access" : "People & sharing"}
            description={organization()
                ? "Choose which organization members and invited collaborators can open this project."
                : "Invite people to this project and choose whether they can work or view."}
            actions={organization()
                ? <button type="button" onClick={() => setAction("member")}>grant member access</button>
                : <button type="button" onClick={openPersonInvite}>{signedOut() ? "sign in to invite" : "invite person"}</button>} />
        <DashboardGrid surface>
        <Show when={organization()} fallback={<>
            <section class="admin-section"><SectionHeading title="People" meta={signedOut() ? "local owner" : "personal project"} />
                <ProjectAccessRow name="Jack Scully" email={props.scope.kind === "signed-out-local" ? "local authority" : "jack@gaugewright.com"}
                    role="Owner" access="Can work and manage sharing" source="Project owner" />
                <Show when={personal() && props.scope.id === "personal-plus"} fallback={<Definition label="Collaborators" value="No one else yet" note={signedOut() ? "sign in before inviting another person" : "invite someone when this work becomes shared"} />}>
                    <ProjectAccessRow name="Maya Singh" email="maya@example.com" role="Collaborator"
                        access="Can work" source="Accepted project invitation" action="remove" danger />
                </Show>
            </section>
            <section class="admin-section"><SectionHeading title="Pending invitations" meta={pendingInvite() ? "1 waiting" : "none"} />
                <Show when={pendingInvite()} fallback={<Definition label="Invitations" value="None pending" note="An invitation grants nothing until the intended account accepts it." />}>
                    {(email) => <Resource kind="waiting for acceptance" title={email()} detail={`Invited to ${props.project.name} · project remains on ${props.project.detail}`} tone="warn"
                        action="copy invite" secondaryAction="cancel" onAction={() => report("Prototype: project invitation link copied.")}
                        onSecondaryAction={() => setPendingInvite(null)} />}
                </Show>
            </section>
        </>}>
            <section class="admin-section"><SectionHeading title="People with access" meta="4 people" />
                <ProjectAccessRow name="Jack Scully" email="jack@gaugewright.com" role="Owner" access="Can work and manage access" source="Project owner" />
                <ProjectAccessRow name="Maya Singh" email="maya@gaugewright.com" role="Collaborator" access="Can work" source="Explicit project access" action="revoke access" danger />
                <ProjectAccessRow name="Eli Torres" email="eli@gaugewright.com" role="Collaborator" access="Can work" source="Explicit project access" action="revoke access" danger />
                <ProjectAccessRow name="Ada Brooks" email="ada@brightworks.studio" role="External collaborator" access="Can view" source="Explicit project access" action="revoke access" danger />
            </section>
            <section class="admin-section"><SectionHeading title="External collaborators" meta="1 invitation pending" action="invite external collaborator" onAction={openPersonInvite} />
                <Resource kind="expires in 5 days" title="client-owner@northstar.example" detail={`Invited to ${props.project.name} · not admitted until the intended account accepts`} tone="warn" action="copy invite" secondaryAction="cancel" />
            </section>
        </Show>
        <Show when={action() === "member" && organization()}><section class="admin-section gaugeapp-form-card"><SectionHeading title="Grant an organization member" />
            <div class="gaugeapp-field-grid gaugeapp-field-grid-single"><label>Member<select value={member()} onChange={(event) => setMember(event.currentTarget.value)}><option>Nora Chen · member</option><option>Sam Patel · viewer</option></select></label></div>
            <p class="gaugeapp-field-note">This creates one revocable member→project grant. It does not change the member’s tenant role or any target, Agent, or export permission.</p>
            <div class="bar"><button class="tree-action" type="button" onClick={() => setAction(null)}>cancel</button><button type="button" onClick={() => { report(`Prototype: ${member()} would receive access to ${props.project.name}.`); setAction(null); }}>grant project access</button></div>
        </section></Show>
        <Show when={action() === "person"}><section class="admin-section gaugeapp-form-card"><SectionHeading title={organization() ? "Invite an external collaborator" : "Invite a person"} />
            <div class="gaugeapp-field-grid"><label>Email or GaugeWright account<input value={recipient()} onInput={(event) => setRecipient(event.currentTarget.value)} placeholder="person@example.com" /></label>
                <label>Project access<select value={personAccess()} onChange={(event) => setPersonAccess(event.currentTarget.value as "work" | "view")}><option value="work">Can work</option><option value="view">Can view</option></select></label></div>
            <p class="gaugeapp-field-note">The invitation is for this person and this project only. Acceptance lets their account reach the project on {props.project.detail}; it does not move the Home or add a Trusted Device to your account.</p>
            <div class="bar"><button class="tree-action" type="button" onClick={() => setAction(null)}>cancel</button><button type="button" disabled={!recipient().trim()} onClick={() => {
                const invited = recipient().trim();
                setPendingInvite(invited);
                report(`Prototype: ${invited} would be invited to ${props.project.name} with ${personAccess() === "work" ? "work" : "view"} access.`);
                setRecipient(""); setAction(null);
            }}>create project invitation</button></div>
        </section></Show>
        <section class="admin-section"><SectionHeading title="Project Home" meta={props.project.detail} action="hand off project" onAction={() => setAction("handoff")} />
            <Definition label="Current Home" value={props.project.detail} note="Inviting a person leaves the project and its data here." />
            <Definition label="Availability" value={props.scope.cloudHome === "managed" ? "Always reachable" : "Available while this Home is online"} note={props.scope.cloudHome === "managed" ? "managed Project Host" : "local or self-managed Project Host"} />
        </section>
        <Show when={action() === "handoff"}><section class="admin-section gaugeapp-form-card"><SectionHeading title="Hand off this project" />
            <Notice tone="warn"><strong>This is not a collaborator invitation.</strong> After the destination Project Host accepts, it carries the project’s authoritative Home and the current Project Host becomes a participant.</Notice>
            <div class="gaugeapp-field-grid gaugeapp-field-grid-single"><label>Person or destination Project Host<input value={handoffTarget()} onInput={(event) => setHandoffTarget(event.currentTarget.value)} placeholder="person or Project Host name" /></label></div>
            <div class="bar"><button class="tree-action" type="button" onClick={() => setAction(null)}>cancel</button><button type="button" disabled={!handoffTarget().trim()} onClick={() => { report(`Prototype: a Home handoff invitation would be created for ${handoffTarget().trim()}.`); setHandoffTarget(""); setAction(null); }}>create handoff invitation</button></div>
        </section></Show>
        </DashboardGrid>
    </>;
}

function ProjectWorkView(props: { scope: ScopeFixture; project: ProjectFixture }): JSX.Element {
    const interact = useContext(InteractionContext);
    return <>
        <PageHeader eyebrow={`${props.project.name} / Project`} title="Work & data"
            description={props.project.isPersonal ? "The files and context available to your private Personal project." : "Attach work and context, then choose the actions available to this project’s Agents."}
            actions={<button type="button" onClick={() => interact({ action: "attach work", title: "Attach work", description: "Choose a GaugeDesk-managed target, external repository, or scoped folder." })}>attach work</button>} />
        <DashboardGrid surface>
        <Show when={props.project.isPersonal} fallback={<>
            <Notice tone="neutral">Separate audiences belong in separate projects. Path scope, resource ownership, and exact actions narrow access within this project.</Notice>
            <section class="admin-section"><SectionHeading title="Work targets" meta="2 attached" action="attach work" />
                <TargetAccessRow kind="managed" title={`${props.project.name} files`} scope="/**" acts={["read", "propose", "apply"]} detail="GaugeDesk-managed history · available" action="manage acts" />
                <TargetAccessRow kind="external VCS" title={`${props.project.id}-src`} scope="/**" acts={["read", "propose", "publish"]} detail="External repository · main@8f21d9b" action="manage acts" />
            </section>
            <section class="admin-section"><SectionHeading title="Context resources" meta="granted to Agents" action="attach context" />
                <Resource kind="project owned" title="Company style guide" detail="internal · us · product-development · 3 active Agents" tone="ready" action="manage Agent access" secondaryAction="detach" />
                <Resource kind="client owned" title="Client research archive" detail="PII · us · product-development · Product designer granted" tone="ready" action="manage Agent access" secondaryAction="revoke access" />
                <Resource kind="request" title="Client operating plan" detail="regulated · purpose product-development · waiting for owner" tone="warn" action="review request" secondaryAction="cancel" />
            </section>
            <section class="admin-section"><SectionHeading title="Data policy" meta="applied on each governed turn" action="edit data policy" />
                <Definition label="Run purpose" value="product-development" note="purpose-labeled resources must match before the Agent starts" />
                <Definition label="Missing classification" value="regulated" note="unknown or omitted labels fail closed" />
            </section>
        </>}><>
            <Notice tone="neutral"><strong>Personal is only available to you.</strong> Create a regular project when work needs another participant.</Notice>
            <section class="admin-section"><SectionHeading title="Work targets" meta="1 attached" action="attach work" />
                <TargetAccessRow kind="managed" title="Personal files" scope="/**" acts={["read", "propose", "apply"]} detail={`${props.project.detail} · available`} action="manage acts" />
            </section>
            <section class="admin-section"><SectionHeading title="Context resources" meta="1 attached" action="attach context" />
                <Resource kind="personal" title="My reference notes" detail="Available to the General assistant" tone="ready" action="manage Agent access" secondaryAction="detach" />
            </section>
        </></Show>
        </DashboardGrid>
    </>;
}

function ProjectPlacementsView(props: { scope: ScopeFixture; project: ProjectFixture }): JSX.Element {
    const interact = useContext(InteractionContext);
    return <>
        <PageHeader eyebrow={`${props.project.name} / Project`} title="Agents & placements"
            description="A placement installs one pinned Agent version into this project and limits the work, context, and actions it may use."
            actions={<button type="button" onClick={() => interact({ action: "add Agent", title: "Add Agent", description: `Choose an admitted Agent and configure a placement for ${props.project.name}.` })}>add Agent</button>} />
        <DashboardGrid surface>
        <Notice tone="neutral"><strong>A placement is not a person permission.</strong> Adding an Agent never admits a person to the project; granting a person project access never widens an Agent’s targets, resources, or runtime authority.</Notice>
        <section class="admin-section"><SectionHeading title="Work Agents" meta="active placements appear in new chat" action="add Agent" />
            <PlacementAccessRow kind="built in" title="General assistant" state="active" version="v1 · current" authority="2 targets · 1 context grant" action="configure" />
            <PlacementAccessRow kind="work Agent" title="Product designer" state="active" version="v4 · v5 available" authority="1 target · 2 context grants" action="manage" secondaryAction="upgrade" />
            <PlacementAccessRow kind="work Agent" title="Financial analyst" state="pending" version="v2 · pinned" authority="no access until accepted" action="review & accept" secondaryAction="reject" warn />
        </section>
        <section class="admin-section"><SectionHeading title="Panel agents & deployments" meta="public runtimes owned by this project" action="new deployment" />
            <PlacementAccessRow kind="panel Agent" title="Documentation assistant" state="active" version="v3 · current"
                authority="preview · Website assistant deployment active" action="manage placement" secondaryAction="open deployment" />
        </section>
        </DashboardGrid>
    </>;
}

type ProjectModelProviderId = "openai" | "anthropic" | "xai" | "openrouter" | "openai-generic";
interface ProjectModelRouteFixture {
    readonly id: ProjectModelProviderId | "openai-codex" | "xai-grok" | "managed";
    readonly label: string;
    readonly models: string;
    readonly inheritedSource: string;
    readonly inheritedClasses: string;
    readonly editable: boolean;
}
interface ProjectModelOverrideFixture {
    readonly mode: "inherit" | "project";
    readonly version?: number;
    readonly endpoint?: string;
    readonly models?: string;
    readonly privateHome?: boolean;
}

/** Current implementation gaps made visible by this prototype:
 * - credentials are keyed by provider, so an account or project cannot retain
 *   two selectable OpenAI accounts (or two generic endpoints) at one scope;
 * - the project credential read route returns only provider + linked, omitting
 *   credential ref/version, auth kind, endpoint, and execution classes;
 * - a project no-catalog override has no project-owned declared-model catalog
 *   even though a generic endpoint can differ from the account endpoint and an
 *   OpenRouter credential may expose different routes.
 * The UI below uses only inherit/project-owned routing today and treats the
 * generic model list as the deliberately required follow-on backend gap. */
function ProjectModelAccessView(props: { scope: ScopeFixture; project: ProjectFixture }): JSX.Element {
    const report = useContext(ActionFeedbackContext);
    const interact = useContext(InteractionContext);
    const routes: readonly ProjectModelRouteFixture[] = [
        { id: "openai-codex", label: "OpenAI Codex", models: "GPT-5.6 · GPT-5.4", inheritedSource: "Jack Scully’s Codex account", inheritedClasses: "local · private Home", editable: false },
        { id: "openai", label: "OpenAI API", models: "GPT-5.4 · GPT-5.4 mini", inheritedSource: "Jack Scully’s API key", inheritedClasses: "local · private Home", editable: true },
        { id: "anthropic", label: "Anthropic", models: "Claude Opus 4.1 · Claude Sonnet 4.1", inheritedSource: "Jack Scully’s API key", inheritedClasses: "local", editable: true },
        { id: "xai-grok", label: "xAI Grok subscription", models: "Grok 4.6 · Grok 4.5", inheritedSource: "Jack Scully’s Grok subscription", inheritedClasses: "local · private Home", editable: false },
        { id: "xai", label: "xAI API", models: "Grok 4.6 · Grok 4.5", inheritedSource: "Jack Scully’s xAI API key", inheritedClasses: "local", editable: true },
        { id: "openrouter", label: "OpenRouter", models: "anthropic/claude-sonnet-4.1 · google/gemini-2.5-pro", inheritedSource: "Jack Scully’s API key", inheritedClasses: "local · private Home", editable: true },
        { id: "openai-generic", label: "Studio endpoint", models: "qwen3-coder · deepseek-r1:14b", inheritedSource: "http://localhost:11434/v1", inheritedClasses: "local", editable: true },
        { id: "managed", label: "Managed inference", models: "GPT-5.4 mini", inheritedSource: props.scope.kind === "organization" ? `${props.scope.label} model plan` : "Personal model plan", inheritedClasses: "local · private Home", editable: false },
    ];
    const [editing, setEditing] = createSignal(false);
    const [provider, setProvider] = createSignal<ProjectModelProviderId>("openai");
    const [mode, setMode] = createSignal<"inherit" | "project">("project");
    const [endpoint, setEndpoint] = createSignal("");
    const [declaredModels, setDeclaredModels] = createSignal("qwen3-coder\ndeepseek-r1:14b");
    const [privateHome, setPrivateHome] = createSignal(false);
    const [overrides, setOverrides] = createSignal<Readonly<Partial<Record<ProjectModelProviderId, ProjectModelOverrideFixture>>>>({
        anthropic: { mode: "project", version: 3, privateHome: true },
    });
    const needsDeclaredModels = (id: ProjectModelProviderId) => id === "openai-generic" || id === "openrouter";
    const defaultModels = (id: ProjectModelProviderId) => id === "openrouter"
        ? "anthropic/claude-sonnet-4.1\ngoogle/gemini-2.5-pro"
        : id === "openai-generic" ? "qwen3-coder\ndeepseek-r1:14b" : "";
    const editableRoute = (id: ProjectModelProviderId) => routes.find((route) => route.id === id)!;
    const beginEdit = (id: ProjectModelProviderId) => {
        const current = overrides()[id];
        setProvider(id);
        setMode(current?.mode ?? "inherit");
        setPrivateHome(Boolean(current?.privateHome));
        setEndpoint(current?.endpoint ?? (id === "openai-generic" ? "http://localhost:11434/v1" : ""));
        setDeclaredModels(current?.models ?? defaultModels(id));
        setEditing(true);
    };
    const changeProvider = (id: ProjectModelProviderId) => {
        const current = overrides()[id];
        setProvider(id);
        setMode(current?.mode ?? "inherit");
        setPrivateHome(Boolean(current?.privateHome));
        setEndpoint(current?.endpoint ?? (id === "openai-generic" ? "http://localhost:11434/v1" : ""));
        setDeclaredModels(current?.models ?? defaultModels(id));
    };
    const save = () => {
        const id = provider();
        if (mode() === "inherit") {
            setOverrides((current) => ({ ...current, [id]: { mode: "inherit" } }));
            report(`${editableRoute(id).label} now inherits your account connection in ${props.project.name}.`);
        } else {
            const previousVersion = overrides()[id]?.version ?? 0;
            setOverrides((current) => ({ ...current, [id]: {
                mode: "project", version: previousVersion + 1, privateHome: privateHome(),
                endpoint: id === "openai-generic" ? endpoint().trim() : undefined,
                models: needsDeclaredModels(id) ? declaredModels().trim() : undefined,
            } }));
            report(`${editableRoute(id).label} now uses a project-owned credential in ${props.project.name}.`);
        }
        setEditing(false);
    };
    return <>
        <PageHeader eyebrow={`${props.project.name} / Project`} title="Model access"
            description="Choose the account or project connection each provider uses here."
            actions={<button type="button" onClick={() => beginEdit("openai")}>set project connection</button>} />
        <DashboardGrid surface>
        <Show when={editing()}><section class="admin-section gaugeapp-form-card gaugeapp-project-model-editor"><SectionHeading title="Project connection" />
            <div class="gaugeapp-field-grid">
                <label>Provider<select value={provider()} onChange={(event) => changeProvider(event.currentTarget.value as ProjectModelProviderId)}>
                    <option value="openai">OpenAI API</option><option value="anthropic">Anthropic</option><option value="xai">xAI API</option>
                    <option value="openrouter">OpenRouter</option><option value="openai-generic">OpenAI-compatible endpoint</option>
                </select></label>
                <label>Use<select value={mode()} onChange={(event) => setMode(event.currentTarget.value as "inherit" | "project")}>
                    <option value="inherit">My account connection</option><option value="project">A project-owned credential</option>
                </select></label>
                <Show when={mode() === "project"}><>
                    <label classList={{ "gaugeapp-field-span": provider() !== "openai-generic" }}>API key<input type="password" autocomplete="off" placeholder="Stored sealed to this project" /></label>
                    <Show when={provider() === "openai-generic"}><label>Endpoint URL<input type="url" value={endpoint()} onInput={(event) => setEndpoint(event.currentTarget.value)} /></label></Show>
                    <Show when={needsDeclaredModels(provider())}><label class="gaugeapp-field-span">Model IDs<textarea value={declaredModels()} onInput={(event) => setDeclaredModels(event.currentTarget.value)} /></label></Show>
                    <label class="gaugeapp-model-class-choice"><input type="checkbox" checked /> Local interactive</label>
                    <label class="gaugeapp-model-class-choice"><input type="checkbox" checked={privateHome()} disabled={props.scope.cloudHome === "none"} onChange={(event) => setPrivateHome(event.currentTarget.checked)} /> Private Home</label>
                </></Show>
            </div>
            <div class="bar"><button class="tree-action" type="button" onClick={() => setEditing(false)}>cancel</button><button type="button" onClick={save}>save connection</button></div>
        </section></Show>
        <section class="admin-section gaugeapp-project-model-section"><SectionHeading title="Connections for this project" meta="a model may appear once per provider" />
            <div class="gaugeapp-project-model-list">
                <For each={routes}>{(route) => {
                    const override = () => route.id === "managed" || route.id === "openai-codex" || route.id === "xai-grok" ? undefined : overrides()[route.id];
                    const isProject = () => override()?.mode === "project";
                    const models = () => isProject() && override()?.models ? override()!.models!.split(/\s+/).filter(Boolean).join(" · ") : route.models;
                    const source = () => isProject()
                        ? `${override()?.endpoint ?? "Project API key"} · v${override()?.version ?? 1}`
                        : route.inheritedSource;
                    const scope = () => route.id === "managed" ? "plan" : isProject() ? "project" : route.id === "openai-codex" || route.id === "xai-grok" ? "account only" : "account";
                    const classes = () => isProject() ? `local${override()?.privateHome ? " · private Home" : ""}` : route.inheritedClasses;
                    return <div class="gaugeapp-project-model-route">
                        <span class="gaugeapp-model-provider"><strong>{route.label}</strong><small>{models()}</small></span>
                        <span><small>Connection</small><strong>{source()}</strong></span>
                        <span><small>Runs in</small>{classes()}</span>
                        <span class="badge">{scope()}</span>
                        <Show when={route.editable} fallback={<Show when={route.id === "managed"}><button class="tree-action" type="button" onClick={() => interact({ action: "open billing", title: "Model plan" })}>plan</button></Show>}>
                            <button class="tree-action" type="button" onClick={() => beginEdit(route.id as ProjectModelProviderId)}>{isProject() ? "change" : "override"}</button>
                        </Show>
                    </div>;
                }}</For>
            </div>
            <p class="gaugeapp-field-note">Public Panel deployments select their own connection. Managed inference follows the account or organization plan and is not a project credential.</p>
        </section>
        </DashboardGrid>
    </>;
}

function VendView(props: { scope: ScopeFixture; tab: string }): JSX.Element {
    const page = () => ({
        Products: { title: "Products", description: "Define the Agents you sell, their default price, delivery, and included services." },
        Clients: { title: "Clients", description: "Commercial relationships with the people and companies you serve." },
        Engagements: { title: "Engagements", description: "Proposals, accepted agreements, Agent deployment, billing, and closure in one lifecycle." },
        Payments: { title: "Payments", description: "Engagement billing and the connected Stripe financial account." },
    } as const)[props.tab as "Products" | "Clients" | "Engagements" | "Payments"];
    return <><PageHeader eyebrow="Commercial Operations" title={page().title} description={page().description} />
        <DashboardGrid>
            <Show when={props.tab === "Products"}><VendProducts /></Show>
            <Show when={props.tab === "Clients"}><VendClients /></Show>
            <Show when={props.tab === "Engagements"}><VendEngagements /></Show>
            <Show when={props.tab === "Payments"}><VendPayments scope={props.scope} /></Show>
        </DashboardGrid>
    </>;
}

function VendProducts(): JSX.Element {
    const interact = useContext(InteractionContext);
    return <>
        <section class="admin-section gaugeapp-catalog-section"><SectionHeading title="Products" meta="4 products" action="new product"
            onAction={() => interact({ action: "new product", title: "New product" })} />
            <div class="gaugeapp-catalog-grid">
                <For each={AGENT_PRODUCTS}>{(agent) => <AgentProductCard agent={agent} />}</For>
            </div>
        </section>
    </>;
}

function VendClients(): JSX.Element {
    const [creating, setCreating] = createSignal(false);
    const report = useContext(ActionFeedbackContext);
    return <>
        <Show when={creating()}><section class="admin-section gaugeapp-form-card"><SectionHeading title="New client" />
            <div class="gaugeapp-field-grid gaugeapp-field-grid-single"><label>Client name<input placeholder="Acme Studio" /></label></div>
            <p class="gaugeapp-field-note">Proposal and invoice recipients are assigned on each engagement. You can save names and email addresses for reuse later.</p>
            <div class="bar"><button class="tree-action" type="button" onClick={() => setCreating(false)}>cancel</button><button type="button" onClick={() => { setCreating(false); report("Client created."); }}>create client</button></div>
        </section></Show>
        <section class="admin-section gaugeapp-ledger-section"><SectionHeading title="Clients" meta="3 active · 1 closed" action={creating() ? undefined : "new client"} onAction={() => setCreating(true)} />
            <Resource client kind="active" title="Northstar Labs" detail="Policy Desk active · $360 billed" tone="ready" action="view client" actionLabel="view" />
            <Resource client kind="active" title="Hearth & Wire" detail="Release Steward active · $6,200 billed" tone="ready" action="view client" actionLabel="view" />
            <Resource client kind="active" title="Cosmos Design" detail="Research Analyst setup · $2,000 due" tone="warn" action="view client" actionLabel="view" />
            <Resource client kind="closed" title="Brightworks Studio" detail="closed Jun 4 · $8,000 billed · history preserved" tone="neutral" action="view history" actionLabel="view" />
        </section>
    </>;
}

function VendEngagements(): JSX.Element {
    const interact = useContext(InteractionContext);
    const [filter, setFilter] = createSignal<"open" | "attention" | "closed">("open");
    return <>
        <section class="admin-section gaugeapp-ledger-section"><SectionHeading title="Engagements" meta="5 open · 1 needs attention · 2 closed" action="new proposal"
            onAction={() => interact({ action: "new proposal", title: "New proposal for Northstar Labs", description: "Choose a product and set the terms." })} />
            <div class="gaugeapp-engagement-filters" role="group" aria-label="Engagement filter">
                <button type="button" classList={{ active: filter() === "open" }} onClick={() => setFilter("open")}>Open <span>5</span></button>
                <button type="button" classList={{ active: filter() === "attention" }} onClick={() => setFilter("attention")}>Needs attention <span>1</span></button>
                <button type="button" classList={{ active: filter() === "closed" }} onClick={() => setFilter("closed")}>Closed <span>2</span></button>
            </div>
            <Show when={filter() === "open" || filter() === "attention"}>
                <ManagedEngagementRow kind="agreement" reference="AGR-1054" agent="Research Analyst" client="Cosmos Design" stage="Setup required"
                    commercial="$2,000 setup · $760/month + usage" fulfillment="No deployment linked · client access inactive" nextAction="open engagement" attention />
            </Show>
            <Show when={filter() === "open"}>
                <ManagedEngagementRow kind="offer" agent="Research Analyst" client="Cosmos Design" stage="Draft"
                    commercial="$2,000 setup · $760/month + usage · 12-month term" fulfillment="Created after proposal acceptance" nextAction="edit proposal" />
                <ManagedEngagementRow kind="offer" agent="Policy Desk" client="Northstar Labs" stage="Awaiting client"
                    commercial="$360/month + usage · expires Sep 5" fulfillment="Created after proposal acceptance" nextAction="view proposal" />
                <ManagedEngagementRow kind="agreement" reference="AGR-1051" agent="Policy Desk" client="Northstar Labs" stage="Active"
                    commercial="$360/month + usage · through Aug 11, 2027" fulfillment="Panel active · v4 · 12 users" nextAction="open engagement" />
                <ManagedEngagementRow kind="agreement" reference="AGR-1048" agent="Release Steward" client="Hearth & Wire" stage="Active"
                    commercial="$6,200/month · through Aug 17, 2027" fulfillment="Customer placement active · v2" nextAction="open engagement" />
            </Show>
            <Show when={filter() === "closed"}>
                <ManagedEngagementRow kind="agreement" reference="AGR-1009" agent="Architecture Advisor" client="Brightworks Studio" stage="Closed"
                    commercial="$4,800 · paid" fulfillment="Placement closed · client access closed" nextAction="view record" closed />
                <ManagedEngagementRow kind="offer" agent="Architecture Advisor" client="Brightworks Studio" stage="Withdrawn"
                    commercial="$8,000 once · withdrawn Jun 4" fulfillment="No deployment or client access created" nextAction="view record" closed />
            </Show>
        </section>
    </>;
}

/** Stripe Connect implementation inventory carried by this prototype:
 * - Configure a fully embedded connected account with direct charges and an
 *   explicit fee/loss contract; persist its tenant mapping server-side.
 * - Authorize short-lived, capability-scoped Account Sessions for Stripe's
 *   onboarding, account, notification, payment, payout, and document surfaces.
 * - Keep stable provider-client Customer mappings and derive every charge or
 *   invoice from accepted engagement terms and a GaugeDesk billing instruction.
 * - Reconcile signed, idempotent Connect events and balance transactions before
 *   claiming net revenue, available funds, fees, disputes, refunds, or payouts.
 * - Stripe owns regulated account data and processor actions; GaugeDesk owns
 *   products, clients, engagements, billing schedules, delivery, and linkage.
 * These are backend gaps, not claims that the fixture already performs them. */
function VendPayments(props: { scope: ScopeFixture }): JSX.Element {
    const [draft, setDraft] = createSignal<"invoice" | "checkout" | null>(null);
    const report = useContext(ActionFeedbackContext);
    const interact = useContext(InteractionContext);
    const connected = () => props.scope.id !== "brightworks";
    return <>
        <Show when={connected()} fallback={<>
            <section class="admin-section gaugeapp-payment-setup-card">
                <div class="gaugeapp-payment-status"><span class="gaugeapp-owner-chip">Stripe</span><span><strong>Set up payments</strong><small>Required before you can send an invoice or checkout link.</small></span></div>
                <div class="gaugeapp-payment-setup-facts">
                    <span><small>Commercial Operations</small><strong>Active</strong><em>Keep preparing products and engagements</em></span>
                    <span><small>Payment collection</small><strong>Not set up</strong><em>Checkout and invoices are off</em></span>
                    <span><small>Stripe will ask for</small><strong>Business and payout details</strong><em>Entered securely with Stripe</em></span>
                </div>
                <div class="bar"><button type="button" onClick={() => interact({ action: "set up payments", title: "Stripe financial account", description: "Secure onboarding for client payments and payouts", kind: "Stripe Connect" })}>set up payments</button></div>
            </section>
            <section class="admin-section"><SectionHeading title="What you can do now" />
                <div class="gaugeapp-prepayment-list"><span><strong>Products</strong><small>Define Agent products and prices</small></span><span><strong>Clients</strong><small>Keep each commercial relationship together</small></span><span><strong>Engagements</strong><small>Prepare terms before acceptance</small></span></div>
            </section>
        </>}>
            <section class="admin-section gaugeapp-payment-account-card">
                <div class="gaugeapp-payment-status"><span class="gaugeapp-owner-chip">Stripe</span><span><strong>Payments are ready</strong><small>{props.scope.label} is the merchant of record.</small></span></div>
                <div class="gaugeapp-payment-account-facts">
                    <span><small>Charges</small><strong>Ready</strong></span><span><small>Payouts</small><strong>Ready</strong></span><span><small>Next payout</small><strong>$8,420 · Aug 31</strong></span>
                </div>
                <button type="button" onClick={() => interact({ action: "manage Stripe account", title: "Stripe financial account", description: "Account details and payment capabilities", kind: "Stripe Connect" })}>manage account</button>
            </section>
            <div class="gaugeapp-metrics gaugeapp-connect-metrics">
                <Metric label="Collected" value="$12,000" note="this month · Stripe confirmed" />
                <Metric label="Outstanding" value="$2,000" note="one engagement invoice" />
                <Metric label="Refunded" value="$800" note="this month · Stripe confirmed" />
                <Metric label="Platform fees" value="$540" note="application fees recorded" />
            </div>
            <div class="gaugeapp-connect-alert" role="status">
                <span><strong>Stripe needs one item</strong><small>Representative address · due Sep 3 · payments and payouts are active</small></span>
                <button class="tree-action" type="button" onClick={() => interact({ action: "resolve requirement", title: "Representative address", description: "Required by Sep 3 to prevent a payout restriction", kind: "Stripe requirement" })}>open in Stripe</button>
            </div>
        </Show>
        <Show when={draft() === "invoice"}><section class="admin-section gaugeapp-form-card"><SectionHeading title="Issue invoice" />
            <div class="gaugeapp-field-grid"><label>Agreement<select><option>AGR-1054 · Research Analyst</option><option>AGR-1048 · Release Steward</option><option>AGR-1051 · Policy Desk</option></select></label><label>Billing period<select><option>Initial charges</option><option>August recurring charges</option><option>August metered charges</option></select></label><label>Billing email<input type="email" placeholder="billing@client.com" /></label><label>Days until due<input type="number" min="1" max="90" value="30" /></label></div>
            <p class="gaugeapp-field-note">GaugeDesk supplies the accepted charges and billing contact. Stripe creates and hosts the invoice on the provider account.</p>
            <div class="bar"><button class="tree-action" type="button" onClick={() => setDraft(null)}>cancel</button><button type="button" onClick={() => { setDraft(null); report("Prototype: an invoice would be issued from the selected agreement and billing period."); }}>issue invoice</button></div>
        </section></Show>
        <Show when={draft() === "checkout"}><section class="admin-section gaugeapp-form-card"><SectionHeading title="Create checkout link" />
            <div class="gaugeapp-field-grid"><label>Engagement<select><option>AGR-1054 · Cosmos Design</option><option>AGR-1048 · Hearth & Wire</option><option>AGR-1051 · Northstar Labs</option></select></label><label>Charge<select><option>Implementation · $2,000</option><option>August recurring charge · $760</option><option>Usage charge · calculated at issue</option></select></label><label>Send to<select><option>Morgan Ellis · proposal</option><option>Devon Lee · billing</option></select></label><label>Link expires<select><option>30 days</option><option>14 days</option><option>7 days</option></select></label></div>
            <p class="gaugeapp-field-note">GaugeDesk supplies the engagement and accepted charge. Stripe hosts checkout and collects the payment for {props.scope.label}.</p>
            <div class="bar"><button class="tree-action" type="button" onClick={() => setDraft(null)}>cancel</button><button type="button" onClick={() => { setDraft(null); report("Checkout link created for the selected engagement charge."); }}>create checkout link</button></div>
        </section></Show>
        <Show when={connected()}><>
            <section class="admin-section gaugeapp-payment-ledger gaugeapp-ledger-section"><div class="gaugeapp-billing-heading"><SectionHeading title="Client billing" meta="GaugeDesk · 4 recent records" /><span><button class="tree-action" type="button" onClick={() => setDraft("checkout")}>create checkout link</button><button type="button" onClick={() => setDraft("invoice")}>issue invoice</button></span></div>
                <Resource titleFirst kind="paid" title="Hearth & Wire · $6,200" detail="AGR-1048 · August recurring charge · Stripe payment succeeded Aug 18" tone="ready" action="details" actionLabel="view" secondaryAction="manage payment" secondaryActionLabel="manage" />
                <Resource titleFirst kind="paid" title="Northstar Labs · $4,800" detail="AGR-1004 · Stripe payment succeeded Aug 16" tone="ready" action="details" actionLabel="view" secondaryAction="manage payment" secondaryActionLabel="manage" />
                <Resource titleFirst kind="open" title="Cosmos Design · $2,000" detail="AGR-1054 · hosted invoice due Sep 4" tone="neutral" action="open invoice" actionLabel="view" />
                <Resource titleFirst kind="refund" title="Cosmos Design · $800" detail="Stripe refund succeeded Aug 14 · original engagement record retained" tone="neutral" action="details" actionLabel="view" />
            </section>
            <section class="admin-section"><SectionHeading title="Usage reconciliation" meta="one blocked" />
                <Resource titleFirst kind="matched" title="Policy Desk · AGR-1051" detail="42,180 model tokens matched to panel:policy-desk · usage charge may be prepared" tone="ready" action="open engagement" actionLabel="view"
                    onAction={() => interact({ action: "view agreement", title: "Policy Desk · Northstar Labs", kind: "agreement" })} />
                <Resource titleFirst kind="blocked" title="Research Analyst · AGR-1054" detail="No deployment reference · usage-priced charges are withheld" tone="warn" action="resolve in engagement" actionLabel="resolve"
                    onAction={() => interact({ action: "view agreement", title: "Research Analyst · Cosmos Design", kind: "agreement" })} />
            </section>
            <section class="admin-section gaugeapp-connect-account"><SectionHeading title="Financial account" meta="Stripe · acct_…6P4C" />
                <ConnectSettingRow title="Account & requirements" note="Verified · one requirement due" status="Stripe" action="manage Stripe account" />
                <ConnectSettingRow title="Payments, refunds & disputes" note="Direct charges and processor history" status="Stripe" action="manage payments" />
                <ConnectSettingRow title="Balance & payouts" note="$2,340 available · automatic weekly" status="Stripe" action="manage payouts" />
                <ConnectSettingRow title="Statements & tax documents" note="Processor-issued documents" status="Stripe" action="view documents" />
                <ConnectSettingRow title="Support" note="Verification, reserves, disputes, and payout timing" status="Stripe" action="open Stripe support" />
            </section>
            <p class="gaugeapp-payment-boundary-note">Engagements and billing instructions are managed here. Account verification, payment methods, refunds, disputes, balances, and payouts are managed by Stripe.</p>
        </></Show>
    </>;
}

function AdministrationView(props: { scope: ScopeFixture; tab: string }): JSX.Element {
    const destination = () => administrationDestination(props.scope, props.tab);
    const description = () => props.tab === "Services" ? "Manage the organization plan, capacity, and optional services." : destination().description;
    const title = () => ({
        "Project Hosts": "Project Hosts",
        Backups: "Backups & recovery",
        Software: "Software policy",
        Clients: "Sessions",
    } as Readonly<Record<string, string>>)[props.tab] ?? (props.tab === "Services" ? "Plans & services" : destination().label);
    return <><PageHeader eyebrow={props.scope.kind === "signed-out-local" ? "This computer" : props.scope.kind === "personal" ? "Your Account" : `${props.scope.label} / Administration`} title={title()} description={description()} />
        <DashboardGrid surface>
            <Show when={props.tab === "Organization"}><OrganizationPanel scope={props.scope} /></Show>
            <Show when={props.tab === "Services"}><CapabilitiesPanel scope={props.scope} /></Show>
            <Show when={props.tab === "Projects"}><ProjectsPanel scope={props.scope} /></Show>
            <Show when={props.tab === "People & Access"}><PeopleAccessPanel scope={props.scope} /></Show>
            <Show when={props.tab === "Identity"}><IdentityPanel scope={props.scope} /></Show>
            <Show when={props.tab === "Model Providers"}><ModelAccessPanel scope={props.scope} owner="organization" /></Show>
            <Show when={props.tab === "Policy"}><PolicyPanel scope={props.scope} /></Show>
            <Show when={props.tab === "Project Hosts"}><ProjectHostsPanel scope={props.scope} /></Show>
            <Show when={props.tab === "Backups"}><BackupsPanel scope={props.scope} /></Show>
            <Show when={props.tab === "Software"}><SoftwarePanel /></Show>
            <Show when={props.tab === "Clients"}><ClientsPanel /></Show>
            <Show when={props.tab === "Billing"}><BillingPanel scope={props.scope} /></Show>
        </DashboardGrid>
    </>;
}

interface OrganizationSubscriptionFixture {
    readonly plan: OrganizationPlanId;
    readonly name: string;
    readonly status: "active" | "trial" | "past due";
    readonly cadence: string;
    readonly renewal: string;
    readonly estimate: string;
    readonly purchasedSeats: number;
    readonly assignedSeats: number;
    readonly payment: string;
}

/** Fixture prices exercise the management flow; they are not product terms. */
function organizationSubscription(scope: ScopeFixture, state: PrototypeOrganizationState = {}): OrganizationSubscriptionFixture {
    const base: OrganizationSubscriptionFixture = {
        plan: "base", name: "Base organization", status: "active", cadence: "No recurring charge",
        renewal: "No renewal", estimate: "$0", purchasedSeats: 0, assignedSeats: 0, payment: "No payment method",
    };
    const managed: OrganizationSubscriptionFixture = scope.id === "northstar" ? {
        plan: "managed", name: "Managed organization", status: "active", cadence: "Annual agreement · invoiced monthly",
        renewal: "Aug 31, 2027", estimate: "$620 / month + usage", purchasedSeats: 25, assignedSeats: 18, payment: "Invoice · net 30",
    } : {
        plan: "managed", name: "Managed organization", status: "active",
        cadence: scope.id === "gaugewright" ? "Annual agreement · invoiced monthly" : "Monthly",
        renewal: scope.id === "gaugewright" ? "Aug 31, 2027" : "Sep 1, 2026",
        estimate: "$220 / month + usage",
        purchasedSeats: 5, assignedSeats: scope.id === "acorn" ? 0 : scope.id === "brightworks" ? 4 : 3,
        payment: scope.id === "gaugewright" ? "Invoice · net 30" : "Visa · 4242",
    };
    const fixture = (state.plan ?? (scope.id === "acorn" ? "base" : "managed")) === "base" ? base : managed;
    const purchasedSeats = state.purchasedSeats ?? fixture.purchasedSeats;
    return {
        ...fixture,
        purchasedSeats,
        estimate: fixture.plan === "managed" && state.purchasedSeats !== undefined
            ? `$${120 + (purchasedSeats * 20)} / month + usage`
            : fixture.estimate,
    };
}

function CapabilitiesPanel(props: { scope: ScopeFixture }): JSX.Element {
    const interact = useContext(InteractionContext);
    const prototype = useContext(PrototypeOrganizationContext);
    const state = () => prototype.get(props.scope.id);
    const subscription = () => organizationSubscription(props.scope, state());
    const providerActive = () => (state().providerCommerce ?? props.scope.providerCommerce) === "active";
    const enterpriseActive = () => (state().enterpriseControls ?? props.scope.enterpriseControls) === "active";
    const managePlan = () => interact({
        action: "change plan", title: subscription().name,
        description: `${subscription().cadence} · ${subscription().estimate} current estimate`,
        kind: "organization-plan", meta: subscription().status,
    });
    const manageSeats = () => interact({
        action: "manage seats", title: "Seat capacity",
        description: `${subscription().assignedSeats} assigned of ${subscription().purchasedSeats} purchased`,
        kind: "organization-seats", meta: `${subscription().purchasedSeats} seats`,
    });
    return <>
        <section class="admin-section"><SectionHeading title="Current plan" meta={subscription().status} />
            <Show when={state().scheduledPlan}>{(plan) => <Notice tone="neutral"><strong>Plan change scheduled.</strong> {plan() === "base" ? `Managed organization ends ${subscription().renewal}.` : "Managed organization activates after payment succeeds."}</Notice>}</Show>
            <article class="gaugeapp-plan-summary" data-plan={subscription().plan}>
                <div class="gaugeapp-plan-summary-head"><div><span>{subscription().plan === "base" ? "Organization foundation" : "Organization subscription"}</span>
                    <h3>{subscription().name}</h3><p>{subscription().plan === "base" ? "People, projects, policy, and self-managed operations." : "Managed capacity for the organization’s GaugeDesk work."}</p></div>
                    <button type="button" onClick={managePlan}>change plan</button></div>
                <dl class="gaugeapp-plan-facts">
                    <div><dt>Billing</dt><dd>{subscription().cadence}</dd></div>
                    <div><dt>{subscription().renewal === "No renewal" ? "Renewal" : "Renews"}</dt><dd>{subscription().renewal}</dd></div>
                    <div><dt>Current estimate</dt><dd>{subscription().estimate}</dd></div>
                </dl>
                <Show when={subscription().plan === "managed"} fallback={<PlanEntitlementRow label="Seat package" value="Not required" note="Membership and project access remain role-governed" />}>
                    <PlanEntitlementRow label="Seat capacity" value={`${subscription().assignedSeats} assigned of ${subscription().purchasedSeats} purchased`}
                        note={state().scheduledSeats !== undefined && state().scheduledSeats !== null
                            ? `${state().scheduledSeats} seats scheduled for the next period · assignment stays in People`
                            : `${subscription().purchasedSeats - subscription().assignedSeats} available · assignment stays in People`} action="manage seats" onAction={manageSeats} />
                </Show>
            </article>
        </section>
        <section class="admin-section"><SectionHeading title="Included capacity" />
            <PlanEntitlementRow label="Managed Home" value={subscription().plan === "managed" ? `${props.scope.label} Cloud Project Host` : "Not included"}
                note={subscription().plan === "managed" ? (props.scope.cloudHome === "managed" ? "Active · manage operational state under Project Hosts" : "Provisioning · existing projects stay where they are") : "Self-managed Project Hosts remain available"}
                action={subscription().plan === "managed" ? "open Project Hosts" : undefined}
                onAction={subscription().plan === "managed" ? () => interact({ action: "open project hosts", title: "Project Hosts" }) : undefined} />
            <PlanEntitlementRow label="Encrypted backup" value={subscription().plan === "managed" ? "Daily · 30 days" : "Not included"}
                note={subscription().plan === "managed" ? "Recovery holders remain independently managed" : "Available with managed service"}
                action={subscription().plan === "managed" ? "open Backups" : undefined}
                onAction={subscription().plan === "managed" ? () => interact({ action: "open backups", title: "Backups" }) : undefined} />
            <PlanEntitlementRow label="Managed model allowance" value={subscription().plan === "managed" ? "250,000 tokens / month" : "Not included"}
                note="Provider and project model policy remain separate" action={subscription().plan === "managed" ? "open Model Providers" : undefined}
                onAction={subscription().plan === "managed" ? () => interact({ action: "open model providers", title: "Organization model plan" }) : undefined} />
        </section>
        <section class="admin-section"><SectionHeading title="Organization services" meta="independent from the base plan" />
            <OrganizationServiceRow title="Commercial Operations" active={providerActive()}
                summary="Products, clients, engagements, and payment processing"
                terms={state().scheduledServiceRemoval === "commercial" ? `Removal scheduled · ${subscription().renewal}` : providerActive() ? "Transaction-priced · processor active" : "Available to add"}
                onAction={() => interact({ action: providerActive() ? "manage service" : "begin provider onboarding", title: "Commercial Operations",
                    description: "Business identity, commercial terms, and Stripe processing", kind: "provider-commercial", meta: providerActive() ? "active" : "not added" })} />
            <OrganizationServiceRow title="Enterprise controls" active={enterpriseActive()}
                summary="Corporate sign-in, provisioning, sessions, and software policy"
                terms={state().scheduledServiceRemoval === "enterprise" ? `Removal scheduled · ${subscription().renewal}` : enterpriseActive() ? "Annual agreement · identity setup available" : "Available to add"}
                onAction={() => interact({ action: enterpriseActive() ? "manage service" : "begin enterprise onboarding", title: "Enterprise controls",
                    description: "Commercial order, identity, provisioning, and owner recovery", kind: "enterprise-controls", meta: enterpriseActive() ? "active" : "not added" })} />
        </section>
        <section class="admin-section gaugeapp-plan-billing-link"><span><strong>Billing records</strong><small>{subscription().payment} · invoices, credits, and usage charges</small></span>
            <button type="button" class="tree-action" onClick={() => interact({ action: "open billing", title: "Billing" })}>view</button></section>
    </>;
}

function PlanEntitlementRow(props: { label: string; value: string; note: string; action?: string; onAction?: () => void }): JSX.Element {
    return <div class="gaugeapp-plan-entitlement"><span><strong>{props.label}</strong><small>{props.note}</small></span><span>{props.value}</span>
        <Show when={props.action}><button type="button" class="tree-action" onClick={props.onAction}>{contextualActionLabel(props.action!)}</button></Show></div>;
}

function OrganizationServiceRow(props: { title: string; active: boolean; summary: string; terms: string; onAction: () => void }): JSX.Element {
    return <article class="gaugeapp-service-row" data-state={props.active ? "active" : "available"}>
        <span><strong>{props.title}</strong><small>{props.summary}</small></span>
        <span><strong>{props.active ? "Active" : "Not added"}</strong><small>{props.terms}</small></span>
        <button type="button" class={props.active ? "tree-action" : undefined} onClick={props.onAction}>{props.active ? "manage" : "add service"}</button>
    </article>;
}

function ProjectsPanel(props: { scope: ScopeFixture }): JSX.Element {
    const [creating, setCreating] = createSignal(false);
    const report = useContext(ActionFeedbackContext);
    const projects = () => PROJECTS_BY_SCOPE[props.scope.id];
    return <>
        <Show when={creating()}><section class="admin-section gaugeapp-form-card">
            <SectionHeading title="New organization project" />
            <div class="gaugeapp-field-grid">
                <label>Project name<input placeholder="Project name" /></label>
                <label>Authoritative Home<select><option>{projects()[0]?.detail ?? `${props.scope.label} Project Host`}</option><option>Choose another admitted Project Host</option></select></label>
            </div>
            <p class="gaugeapp-field-note">The selected Home becomes the sole authority for project membership, work, Agents, and context. Organization policy may restrict the eligible Project Hosts.</p>
            <div class="bar"><button class="tree-action" type="button" onClick={() => setCreating(false)}>cancel</button><button type="button" onClick={() => {
                setCreating(false);
                report("Prototype: the project would be created on the selected authoritative Home with only the creator admitted.");
            }}>create project</button></div>
        </section></Show>
        <section class="admin-section"><SectionHeading title="Governed projects" meta={`${projects().length} projects`} action={creating() ? undefined : "new project"} onAction={() => setCreating(true)} />
            <For each={projects()}>{(project) => <ProjectGovernanceRow project={project} facts={PROJECT_GOVERNANCE_BY_ID[project.id]!} />}</For>
        </section>
    </>;
}

function OrganizationPanel(props: { scope: ScopeFixture }): JSX.Element {
    const [displayName, setDisplayName] = createSignal(props.scope.label);
    const [addingDomain, setAddingDomain] = createSignal(false);
    const [transferringOwnership, setTransferringOwnership] = createSignal(false);
    const [newOwner, setNewOwner] = createSignal("Maya Singh");
    const [reviewingDeletion, setReviewingDeletion] = createSignal(false);
    const [message, setMessage] = createSignal("");
    const domain = () => scopeDomain(props.scope);
    return <>
        <section class="admin-section"><SectionHeading title="Profile" action="save changes" onAction={() => setMessage(`Display name would be saved as ${displayName()}.`)} />
            <div class="gaugeapp-field-grid gaugeapp-field-grid-single"><label>Display name<input value={displayName()} onInput={(event) => setDisplayName(event.currentTarget.value)} /></label></div>
            <Definition label="Organization ID" value={`organization:${props.scope.id}:9f4a…72c1`} note="Permanent" />
        </section>
        <section class="admin-section"><SectionHeading title="Ownership" meta="Jack Scully"
            action={transferringOwnership() ? undefined : "transfer ownership"} onAction={() => setTransferringOwnership(true)} />
            <Definition label="Current owner" value="Jack Scully" note="jack@gaugewright.com" />
        </section>
        <Show when={transferringOwnership()}><section class="admin-section gaugeapp-form-card gaugeapp-ownership-card">
            <SectionHeading title="Transfer ownership" />
            <div class="gaugeapp-field-grid gaugeapp-field-grid-single"><label>New owner<select value={newOwner()}
                onChange={(event) => setNewOwner(event.currentTarget.value)}><option>Maya Singh</option><option>Eli Ortiz</option></select></label></div>
            <p class="gaugeapp-field-note">The new owner receives full organization authority. Jack Scully becomes an administrator; projects, billing, and recorded history stay with the organization.</p>
            <div class="bar"><button class="tree-action" type="button" onClick={() => setTransferringOwnership(false)}>cancel</button>
                <button type="button" onClick={() => { setTransferringOwnership(false); setMessage(`Prototype: ownership would transfer to ${newOwner()}, and Jack Scully would become an administrator.`); }}>transfer ownership</button></div>
        </section></Show>
        <Show when={props.scope.enterpriseControls === "active"}><Show when={addingDomain()}><section class="admin-section gaugeapp-form-card"><SectionHeading title="Add domain" />
            <div class="gaugeapp-field-grid gaugeapp-field-grid-single"><label>Domain<input placeholder="example.com" /></label></div>
            <p class="gaugeapp-field-note">You’ll get a DNS record to add before the domain is verified.</p>
            <div class="bar"><button class="tree-action" type="button" onClick={() => setAddingDomain(false)}>cancel</button><button type="button" onClick={() => { setAddingDomain(false); setMessage("A DNS TXT record would be generated for the new domain."); }}>get DNS record</button></div>
        </section></Show>
        <section class="admin-section"><SectionHeading title="Domains" action={addingDomain() ? undefined : "add domain"} onAction={() => setAddingDomain(true)} />
            <Resource kind="pending" title={domain()} detail="Waiting for DNS verification · available to SSO and JIT after proof" tone="warn" action="view DNS record"
                onAction={() => setMessage(`Add the TXT record shown for ${domain()}, then GaugeDesk will verify it automatically.`)} />
        </section></Show>
        <section class="admin-section gaugeapp-danger-zone"><SectionHeading title="Delete organization" />
            <p class="gaugeapp-section-intro">Deleting removes the organization from the switcher and invalidates outstanding invitations. Existing audit history is retained.</p>
            <button type="button" class="tree-action" onClick={() => setReviewingDeletion(!reviewingDeletion())}>delete organization</button>
            <Show when={reviewingDeletion()}><div class="gaugeapp-danger-review" role="status">
                <strong>{props.scope.id === "acorn" ? "Deletion is available after final confirmation." : "Deletion is currently blocked."}</strong>
                <p>{props.scope.id === "acorn" ? "Acorn Workshop has one owner, no managed Project Host, and no optional organization services. The final step would require entering the organization name and confirming permanent loss of its tenant routes." : "Other active members must leave or be deactivated, managed services must be retired, and provider or enterprise standing must be closed before the final confirmation."}</p>
                <button type="button" class="tree-action gaugeapp-danger-secondary" onClick={() => setReviewingDeletion(false)}>close</button>
            </div></Show>
        </section>
        <Show when={message()}><p class="status" role="status">{message()}</p></Show>
    </>;
}

function PeopleAccessPanel(props: { scope: ScopeFixture }): JSX.Element {
    const [inviting, setInviting] = createSignal(false);
    const [invitees, setInvitees] = createSignal("");
    const report = useContext(ActionFeedbackContext);
    return <>
        <Show when={inviting()}><section class="admin-section gaugeapp-form-card"><SectionHeading title="Invite people" meta="one email per line" />
            <div class="gaugeapp-field-grid"><label class="gaugeapp-field-span">Email addresses<textarea value={invitees()} onInput={(event) => setInvitees(event.currentTarget.value)} placeholder={'maya@example.com\neli@example.com'} /></label><label>Initial role<select><option>member</option><option>admin</option></select></label></div>
            <p class="gaugeapp-field-note">Invitations create no project grants. Those are assigned separately after membership is admitted.</p>
            <div class="bar"><button class="tree-action" type="button" onClick={() => setInviting(false)}>cancel</button><button type="button" disabled={!invitees().trim()} onClick={() => { report(`Prototype: invitations would be sent to ${invitees().trim().split(/\s+/).length} people.`); setInviting(false); setInvitees(""); }}>send invitations</button></div>
        </section></Show>
        <section class="admin-section"><SectionHeading title="People" meta={props.scope.id === "acorn" ? "1 active" : props.scope.id === "northstar" ? "24 active · 2 invitations" : "3 active · 1 invitation"} action={inviting() ? undefined : "invite people"} onAction={() => setInviting(true)} />
            <MemberRow name="Jack Scully" email="jack@gaugewright.com" role="owner" detail="direct · active" />
            <Show when={props.scope.id !== "acorn"}><>
                <MemberRow name="Maya Singh" email={`maya@${scopeDomain(props.scope)}`} role="admin" detail={props.scope.enterpriseControls === "active" ? "direct · active" : "direct · active"} action="view grants" secondaryAction="deactivate" />
                <MemberRow name="Eli Ortiz" email={`eli@${scopeDomain(props.scope)}`} role="member" detail={props.scope.id === "northstar" ? "SCIM · active" : "direct · active"} action="view grants" secondaryAction="deactivate" />
                <MemberRow name="Rowan Kim" email={`rowan@${scopeDomain(props.scope)}`} role="member" detail="invited Aug 20" pending action="resend" secondaryAction="revoke" />
            </></Show>
        </section>
        <section class="admin-section"><SectionHeading title="Project grants" meta={props.scope.id === "acorn" ? "none" : "2 explicit grants"} action="manage grants" />
            <Show when={props.scope.id === "acorn"} fallback={<>
                <Definition label={PROJECTS_BY_SCOPE[props.scope.id][0]?.name ?? "Project"} value="2 people" note="Maya Singh · Can work; Eli Ortiz · Can view" />
                <Definition label={PROJECTS_BY_SCOPE[props.scope.id][1]?.name ?? "Operations"} value="2 people" note="Jack Scully · Owner; Maya Singh · Can work" />
            </>}><Definition label="Acorn design" value="Owner only" note="organization membership would not admit a new member automatically" /></Show>
        </section>
        <Notice tone="neutral">{props.scope.enterpriseControls === "active" ? "People managed by your identity provider are configured in Enterprise Identity." : "Direct invitations and fixed roles are included. Identity-provider-managed membership requires Enterprise controls."}</Notice>
    </>;
}

function IdentityPanel(props: { scope: ScopeFixture }): JSX.Element {
    const [settingUp, setSettingUp] = createSignal(false);
    const [message, setMessage] = createSignal("");
    const revealProvisioning = () => {
        setSettingUp(false);
        queueMicrotask(() => document.getElementById("enterprise-identity-provisioning")?.scrollIntoView({ behavior: "smooth", block: "start" }));
    };
    return <Show when={settingUp()} fallback={<>
        <Notice tone="warn">No corporate identity provider is connected. Verify a company domain before enabling just-in-time membership, and test the connection before enforcing SSO.</Notice>
        <section class="admin-section"><SectionHeading title="Single sign-on" meta="owner or administrator" action="set up SSO" onAction={() => setSettingUp(true)} />
            <Definition label="Connection" value="No identity provider" note="Microsoft Entra ID, Okta, Google Workspace, Ping, or another standards-compliant IdP" />
            <Definition label="Protocols" value="OIDC · SAML 2.0" note="one admitted connection per organization" />
            <Definition label="Enforcement" value="Off" note="the last owner remains a break-glass sign-in" />
        </section>
        <Show when={message()}><p class="status" role="status">{message()}</p></Show>
        <ProvisioningPanel scope={props.scope} anchorId="enterprise-identity-provisioning" />
    </>}>
        <SsoSetupFlow scope={props.scope} onCancel={() => setSettingUp(false)} onComplete={(result) => { setMessage(result); setSettingUp(false); }}
            onProvisioning={revealProvisioning} />
    </Show>;
}

function SsoSetupFlow(props: {
    scope: ScopeFixture;
    onCancel: () => void;
    onComplete: (message: string) => void;
    onProvisioning: () => void;
}): JSX.Element {
    const steps = ["Connect", "Test", "Provision", "Enforce"] as const;
    const [step, setStep] = createSignal(0);
    const [protocol, setProtocol] = createSignal<"oidc" | "saml">("oidc");
    const [provider, setProvider] = createSignal("Microsoft Entra ID");
    const [issuer, setIssuer] = createSignal("");
    const [audience, setAudience] = createSignal("");
    const [metadataUrl, setMetadataUrl] = createSignal("");
    const [subjectClaim, setSubjectClaim] = createSignal("sub");
    const [rolesClaim, setRolesClaim] = createSignal("groups");
    const [provisioning, setProvisioning] = createSignal<"jit" | "scim">("jit");
    const [enforce, setEnforce] = createSignal(false);
    const [ownerRecovery, setOwnerRecovery] = createSignal(false);
    const [testState, setTestState] = createSignal<"not-run" | "passed" | "blocked">("not-run");
    const [status, setStatus] = createSignal("");
    const domain = () => scopeDomain(props.scope);
    const testConnection = () => {
        if (protocol() === "saml") {
            setTestState("blocked");
            setStatus("SAML SP metadata is publishable, but the current backend does not yet provide the complete ACS sign-in and live test journey. The connection cannot be enforced from this prototype.");
            return;
        }
        if (!issuer().trim() || !audience().trim()) {
            setTestState("blocked");
            setStatus("Enter the OIDC issuer and client ID before testing.");
            return;
        }
        setTestState("passed");
        setStatus("Prototype result: issuer discovery and signing-key reachability passed. A real deployment must still complete a signed-in browser round trip before enforcement.");
    };
    return <>
        <button type="button" class="gaugeapp-back-link" onClick={props.onCancel}>← Enterprise Identity</button>
        <PageHeader eyebrow="Enterprise Identity / guided setup" title="Set up corporate sign-in"
            description="Exchange metadata with your identity provider, test the actual trust path, choose provisioning, and only then decide whether to require SSO." />
        <ol class="gaugeapp-setup-steps" aria-label="SSO setup progress">
            <For each={steps}>{(label, index) => <li classList={{ active: step() === index(), done: step() > index() }}>
                <button type="button" onClick={() => setStep(index())}><span>{index() + 1}</span>{label}</button>
            </li>}</For>
        </ol>
        <Show when={step() === 0}><>
            <section class="admin-section"><SectionHeading title="Identity provider" />
                <div class="gaugeapp-protocol-choices">
                    <button type="button" classList={{ active: protocol() === "oidc" }} onClick={() => { setProtocol("oidc"); setTestState("not-run"); setStatus(""); }}><strong>OIDC</strong><small>Recommended for Entra, Okta, Google Workspace, and modern providers</small></button>
                    <button type="button" classList={{ active: protocol() === "saml" }} onClick={() => { setProtocol("saml"); setTestState("not-run"); setStatus(""); }}><strong>SAML 2.0</strong><small>Metadata exchange for established enterprise identity systems</small></button>
                </div>
                <div class="gaugeapp-field-grid gaugeapp-field-grid-single"><label>Provider<select value={provider()} onChange={(event) => setProvider(event.currentTarget.value)}><option>Microsoft Entra ID</option><option>Okta</option><option>Google Workspace</option><option>Ping Identity</option><option>Other standards-compliant IdP</option></select></label></div>
            </section>
            <section class="admin-section"><SectionHeading title="Give these values to your IdP" meta="service-provider metadata" />
                <Show when={protocol() === "oidc"} fallback={<>
                    <IntegrationValue label="SP metadata URL" value="https://desk.gw.localhost:7523/saml/metadata" onCopy={() => setStatus("SAML metadata URL copied for the prototype.")} />
                    <IntegrationValue label="ACS URL" value="https://desk.gw.localhost:7523/auth/saml/acs" onCopy={() => setStatus("SAML ACS URL copied for the prototype.")} />
                    <IntegrationValue label="SP entity ID" value="https://desk.gw.localhost:7523/saml/metadata" onCopy={() => setStatus("SAML entity ID copied for the prototype.")} />
                </>}>
                    <IntegrationValue label="Redirect URI" value="https://desk.gw.localhost:7523/auth/callback" onCopy={() => setStatus("OIDC redirect URI copied for the prototype.")} />
                    <IntegrationValue label="Login URL" value="https://desk.gw.localhost:7523/auth/login" onCopy={() => setStatus("OIDC login URL copied for the prototype.")} />
                </Show>
            </section>
            <section class="admin-section"><SectionHeading title={`Connect ${provider()}`} />
                <Show when={protocol() === "oidc"} fallback={<div class="gaugeapp-field-grid gaugeapp-field-grid-single">
                    <label>IdP metadata URL<input value={metadataUrl()} onInput={(event) => setMetadataUrl(event.currentTarget.value)} placeholder="https://idp.example.com/app/metadata" /></label>
                    <p class="gaugeapp-field-note">The accepted design parses the IdP metadata URL for endpoints and certificates. The current backend record accepts SAML metadata, but the production ACS journey remains unfinished.</p>
                </div>}><div class="gaugeapp-field-grid">
                    <label>Issuer URL<input value={issuer()} onInput={(event) => setIssuer(event.currentTarget.value)} placeholder="https://login.example.com/tenant/v2.0" /></label>
                    <label>Client ID / audience<input value={audience()} onInput={(event) => setAudience(event.currentTarget.value)} placeholder="application client ID" /></label>
                </div></Show>
            </section>
        </></Show>
        <Show when={step() === 1}><>
            <section class="admin-section"><SectionHeading title="Claim mapping" meta="unmapped attributes fail closed" />
                <div class="gaugeapp-field-grid">
                    <label>Stable subject claim<input value={subjectClaim()} onInput={(event) => setSubjectClaim(event.currentTarget.value)} /></label>
                    <label>Roles or groups claim<input value={rolesClaim()} onInput={(event) => setRolesClaim(event.currentTarget.value)} placeholder="optional" /></label>
                </div>
                <p class="gaugeapp-field-note">Tenant roles still come from GaugeDesk membership records. Token claims can feed verified attributes, but cannot invent a custom role or widen organization policy.</p>
            </section>
            <section class="admin-section"><SectionHeading title="Connection test" />
                <Notice tone={protocol() === "saml" ? "warn" : "neutral"}>{protocol() === "oidc"
                    ? "The implemented test checks OIDC discovery and JWKS reachability. A browser sign-in remains the decisive end-to-end test."
                    : "SAML metadata is available for IdP registration, but the current backend explicitly lacks the complete SP-initiated ACS and live-test path."}</Notice>
                <button type="button" class="gaugeapp-primary-action" onClick={testConnection}>{protocol() === "oidc" ? "test issuer and signing keys" : "check SAML readiness"}</button>
                <Show when={status()}><p class="status" role="status">{status()}</p></Show>
            </section>
        </></Show>
        <Show when={step() === 2}><>
            <section class="admin-section"><SectionHeading title="Provisioning mode" />
                <div class="gaugeapp-protocol-choices">
                    <button type="button" classList={{ active: provisioning() === "jit" }} onClick={() => setProvisioning("jit")}><strong>Just in time</strong><small>Verified-domain users enter as members on first successful SSO login</small></button>
                    <button type="button" classList={{ active: provisioning() === "scim" }} onClick={() => setProvisioning("scim")}><strong>SCIM directory</strong><small>Provision, suspend, restore, deprovision, and map groups to roles</small></button>
                </div>
            </section>
            <section class="admin-section"><SectionHeading title="Prerequisites" />
                <Resource kind="domain" title={domain()} detail="DNS verification pending · JIT cannot admit anyone from this domain yet." tone="warn" />
                <Definition label="SCIM base URL" value="https://desk.gw.localhost:7523/scim/v2" note="credential is issued once from Provisioning after review" />
                <Definition label="Default JIT role" value="member" note="fixed role; group mapping or an administrator may elevate later" />
            </section>
            <button type="button" class="tree-action" onClick={props.onProvisioning}>open provisioning configuration</button>
        </></Show>
        <Show when={step() === 3}><>
            <Notice tone={protocol() === "saml" || testState() !== "passed" ? "warn" : "neutral"}>{protocol() === "saml"
                ? "SAML can be prepared but cannot be honestly marked live until the backend ACS and end-to-end test gap is closed."
                : testState() === "passed" ? "The OIDC reachability test passed. Review the connection and preserve owner recovery before enforcement." : "Test the OIDC connection before requesting enforcement."}</Notice>
            <section class="admin-section"><SectionHeading title="Go-live controls" />
                <label class="gaugeapp-check-row"><input type="checkbox" checked={enforce()} disabled={protocol() === "saml" || testState() !== "passed"} onChange={(event) => setEnforce(event.currentTarget.checked)} /><span><strong>Require SSO for organization members</strong><small>Enforcement affects future sign-ins; the last owner remains the break-glass path.</small></span></label>
                <label class="gaugeapp-check-row"><input type="checkbox" checked={ownerRecovery()} onChange={(event) => setOwnerRecovery(event.currentTarget.checked)} /><span><strong>I verified owner recovery</strong><small>Required before an enforcement proposal can be reviewed.</small></span></label>
            </section>
            <section class="admin-section"><SectionHeading title="Connection summary" />
                <Definition label="Provider" value={provider()} note={protocol().toUpperCase()} />
                <Definition label="Connection" value={protocol() === "oidc" ? issuer() || "Issuer not entered" : metadataUrl() || "Metadata URL not entered"} note={testState() === "passed" ? "reachability tested" : "not live"} />
                <Definition label="Provisioning" value={provisioning() === "jit" ? "JIT membership" : "SCIM directory"} note={provisioning() === "jit" ? "blocked until domain verification" : "credential issued separately"} />
                <Definition label="SSO enforcement" value={enforce() ? "Requested" : "Optional"} note="last owner preserved" />
            </section>
            <div class="bar"><button class="tree-action" type="button" onClick={props.onCancel}>cancel setup</button><button type="button"
                disabled={protocol() === "oidc" ? testState() !== "passed" || (enforce() && !ownerRecovery()) : !metadataUrl().trim()}
                onClick={() => props.onComplete(protocol() === "saml"
                    ? "Prototype: the SAML connection draft would be prepared, but activation remains blocked on the documented ACS backend gap."
                    : `Prototype: the ${provider()} OIDC connection would enter review${enforce() ? " with SSO enforcement" : " as optional sign-in"}.`)}>{protocol() === "saml" ? "save SAML draft" : "review OIDC connection"}</button></div>
        </></Show>
        <div class="gaugeapp-setup-navigation">
            <button type="button" class="tree-action" disabled={step() === 0} onClick={() => setStep((current) => Math.max(0, current - 1))}>back</button>
            <span>Step {step() + 1} of {steps.length}</span>
            <button type="button" disabled={step() === steps.length - 1} onClick={() => setStep((current) => Math.min(steps.length - 1, current + 1))}>next</button>
        </div>
    </>;
}

function ProvisioningPanel(props: { scope: ScopeFixture; anchorId?: string }): JSX.Element {
    const [issuing, setIssuing] = createSignal(false);
    const [addingMapping, setAddingMapping] = createSignal(false);
    const [group, setGroup] = createSignal("");
    const [role, setRole] = createSignal("member");
    const [message, setMessage] = createSignal("");
    const interact = useContext(InteractionContext);
    const domain = () => scopeDomain(props.scope);
    return <>
        <Show when={props.anchorId}><span id={props.anchorId} class="gaugeapp-section-anchor" aria-hidden="true" /></Show>
        <Notice tone="neutral">SCIM owns the lifecycle of directory-managed members. A credential is revealed only once after its reviewed rotation command is admitted; it never enters this page, the agent, or a configuration diff.</Notice>
        <section class="admin-section"><SectionHeading title="Just-in-time membership" meta="zero-config path" />
            <Resource kind="domain" title={domain()} detail="Waiting for DNS verification. Until admitted, successful SSO identities cannot auto-join." tone="warn" action="manage verified domains" />
            <Definition label="Default role" value="member" note="JIT never creates an administrator or owner" />
            <Definition label="Unverified domains" value="Denied" note="invite or SCIM provisioning required" />
        </section>
        <Show when={issuing()}><section class="admin-section gaugeapp-form-card">
            <SectionHeading title="Issue SCIM credential" />
            <IntegrationValue label="SCIM base URL" value="https://desk.gw.localhost:7523/scim/v2" onCopy={() => setMessage("SCIM base URL copied for the prototype.")} />
            <p class="gaugeapp-field-note">After review, the new bearer credential is shown once. Rotating it immediately invalidates the prior credential, so update the IdP before ending the session.</p>
            <div class="bar"><button class="tree-action" type="button" onClick={() => setIssuing(false)}>cancel</button><button type="button" onClick={() => { setIssuing(false); setMessage("Prototype: SCIM credential issuance would enter review; the one-time credential would appear only after admission."); }}>issue credential</button></div>
        </section></Show>
        <section class="admin-section"><SectionHeading title="SCIM directory" meta="RFC 7644" action={issuing() ? undefined : "issue credential"} onAction={() => setIssuing(true)} />
            <Definition label="Endpoint" value="https://desk.gw.localhost:7523/scim/v2" note="Users endpoint supports create, update, suspend, restore, and delete" />
            <Definition label="Credential" value="Not issued" note="stored only as a one-way digest after activation" />
            <Definition label="Directory activity" value="No calls observed" note="sync counts are operational evidence" />
        </section>
        <Show when={addingMapping()}><section class="admin-section gaugeapp-form-card">
            <SectionHeading title="Add group mapping" />
            <div class="gaugeapp-field-grid">
                <label>IdP group<input value={group()} onInput={(event) => setGroup(event.currentTarget.value)} placeholder="Engineering" /></label>
                <label>Tenant role<select value={role()} onChange={(event) => setRole(event.currentTarget.value)}><option>member</option><option>viewer</option><option>billing</option><option>admin</option></select></label>
            </div>
            <p class="gaugeapp-field-note">Roles are fixed. Group mapping changes organization membership attributes; project access remains an independent grant.</p>
            <div class="bar"><button class="tree-action" type="button" onClick={() => setAddingMapping(false)}>cancel</button><button type="button" disabled={!group().trim()} onClick={() => {
                setAddingMapping(false);
                setMessage(`Prototype: ${group()} would map to ${role()} after review.`);
                setGroup(""); setRole("member");
            }}>review mapping</button></div>
        </section></Show>
        <section class="admin-section"><SectionHeading title="Group mappings" meta="2 admitted" action={addingMapping() ? undefined : "add mapping"} onAction={() => setAddingMapping(true)} />
            <Definition label="IT Administrators" value="admin" note="tenant-wide administrative capability" />
            <Definition label="Engineering" value="member" note="project access assigned separately" />
            <Definition label="Unmapped groups" value="member" note="fail-safe default" />
        </section>
        <section class="admin-section"><SectionHeading title="Offboarding behavior" />
            <Definition label="Suspend or delete in IdP" value="Future organization access revoked" note="prior authored work and audit evidence remain" />
            <Definition label="Project admission" value="Becomes unreachable" note="no grant record is silently rewritten" />
            <Definition label="Active sessions" value="Rejected after membership fold" note="session roster is operational evidence" />
            <button type="button" class="tree-action" onClick={() => interact({ action: "open people and access", title: "People" })}>open People</button>
        </section>
        <Show when={message()}><p class="status" role="status">{message()}</p></Show>
    </>;
}

function IntegrationValue(props: { label: string; value: string; onCopy: () => void }): JSX.Element {
    return <div class="gaugeapp-integration-value"><span><small>{props.label}</small><code>{props.value}</code></span><button class="tree-action" type="button" onClick={() => {
        void navigator.clipboard?.writeText(props.value);
        props.onCopy();
    }}>copy</button></div>;
}

type PolicyExportAccess = "owners-admins" | "project-members" | "project-policy";
type PolicyRunAccess = "owners-admins" | "project-members" | "project-policy";
type PolicyRegionMatch = "pii" | "pii-regulated" | "all-labeled" | "floor";
type PolicyAgentAdmission = "approval" | "immediate";
type PolicyAgentUpdates = "manual" | "publisher-auto";

interface OrganizationPolicyDraft {
    readonly exportAccess: PolicyExportAccess;
    readonly runAccess: PolicyRunAccess;
    readonly regionMatch: PolicyRegionMatch;
    readonly allowRunOwnerHost: boolean;
    readonly allowCounterpartyHost: boolean;
    readonly allowNeutralHost: boolean;
    readonly agentAdmission: PolicyAgentAdmission;
    readonly agentUpdates: PolicyAgentUpdates;
    readonly sessionLifetime: "4" | "8" | "12" | "24";
    readonly idleTimeout: "15" | "30" | "60" | "120";
    readonly auditMinimum: "365" | "1095" | "2555";
}

function organizationPolicyFixture(scope: ScopeFixture): OrganizationPolicyDraft {
    const governed = scope.id === "gaugewright" || scope.id === "northstar";
    return {
        exportAccess: governed ? "owners-admins" : "project-members",
        runAccess: "project-members",
        regionMatch: governed ? "pii" : "floor",
        allowRunOwnerHost: true,
        allowCounterpartyHost: scope.id !== "northstar",
        allowNeutralHost: true,
        agentAdmission: governed ? "approval" : "immediate",
        agentUpdates: "manual",
        sessionLifetime: scope.id === "northstar" ? "8" : "12",
        idleTimeout: "30",
        auditMinimum: scope.id === "northstar" ? "2555" : "365",
    };
}

function organizationPolicyValueLabel(key: keyof OrganizationPolicyDraft, value: OrganizationPolicyDraft[keyof OrganizationPolicyDraft]): string {
    const text = String(value);
    if (key === "exportAccess" || key === "runAccess") return ({
        "owners-admins": "Owners and administrators",
        "project-members": "Project members with authority",
        "project-policy": "No organization restriction",
    } as Record<string, string>)[text] ?? text;
    if (key === "regionMatch") return ({
        pii: "PII resources",
        "pii-regulated": "PII and regulated resources",
        "all-labeled": "Every resource",
        floor: "No organization restriction",
    } as Record<string, string>)[text] ?? text;
    if (key === "allowRunOwnerHost" || key === "allowCounterpartyHost" || key === "allowNeutralHost") return value ? "Allowed" : "Blocked";
    if (key === "agentAdmission") return text === "approval" ? "Require project-owner approval" : "Activate immediately";
    if (key === "agentUpdates") return text === "manual" ? "Review every upgrade" : "Allow publisher-requested auto-upgrades";
    if (key === "sessionLifetime") return `${text} hours`;
    if (key === "idleTimeout") return text === "120" ? "2 hours" : `${text} minutes`;
    if (key === "auditMinimum") return ({ "365": "At least 1 year", "1095": "At least 3 years", "2555": "At least 7 years" } as Record<string, string>)[text] ?? text;
    return text;
}

function PolicyControlRow(props: { title: string; note: string; children: JSX.Element }): JSX.Element {
    return <div class="gaugeapp-policy-control-row"><span><strong>{props.title}</strong><small>{props.note}</small></span><span>{props.children}</span></div>;
}

function PolicyToggleRow(props: { title: string; note: string; checked: boolean; disabled?: boolean; onChange: (checked: boolean) => void }): JSX.Element {
    return <label class="gaugeapp-policy-toggle-row"><span><strong>{props.title}</strong><small>{props.note}</small></span>
        <input type="checkbox" checked={props.checked} disabled={props.disabled} onChange={(event) => props.onChange(event.currentTarget.checked)} />
    </label>;
}

function PolicyPanel(props: { scope: ScopeFixture }): JSX.Element {
    const report = useContext(ActionFeedbackContext);
    const initial = organizationPolicyFixture(props.scope);
    const [fixtureScope, setFixtureScope] = createSignal(props.scope.id);
    const [saved, setSaved] = createSignal<OrganizationPolicyDraft>(initial);
    const [draft, setDraft] = createSignal<OrganizationPolicyDraft>(initial);
    createEffect(() => {
        if (props.scope.id === fixtureScope()) return;
        const next = organizationPolicyFixture(props.scope);
        setFixtureScope(props.scope.id);
        setSaved(next);
        setDraft(next);
    });
    const change = <K extends keyof OrganizationPolicyDraft>(key: K, value: OrganizationPolicyDraft[K]) => {
        setDraft((current) => ({ ...current, [key]: value }));
    };
    const dirty = createMemo(() => JSON.stringify(draft()) !== JSON.stringify(saved()));
    const changedFields = createMemo(() => {
        const current = draft();
        const admitted = saved();
        const names: Record<keyof OrganizationPolicyDraft, string> = {
            exportAccess: "export access", runAccess: "Agent run access", regionMatch: "resource-region matching",
            allowRunOwnerHost: "run-owner hosts", allowCounterpartyHost: "counterparty hosts", allowNeutralHost: "neutral hosts",
            agentAdmission: "new Agent admission", agentUpdates: "Agent updates", sessionLifetime: "session lifetime",
            idleTimeout: "idle timeout", auditMinimum: "audit guarantee",
        };
        return (Object.keys(names) as (keyof OrganizationPolicyDraft)[])
            .filter((key) => current[key] !== admitted[key])
            .map((key) => ({
                key,
                label: names[key],
                before: organizationPolicyValueLabel(key, admitted[key]),
                after: organizationPolicyValueLabel(key, current[key]),
            }));
    });
    const allowedHostCount = createMemo(() => [draft().allowRunOwnerHost, draft().allowCounterpartyHost, draft().allowNeutralHost].filter(Boolean).length);
    const discard = () => {
        setDraft(saved());
        report("Policy changes were discarded.");
    };
    const accept = () => {
        setSaved(draft());
        report("Policy revision accepted for this prototype.");
    };
    return <>
        <Notice tone="neutral">These settings add organization-wide restrictions after project access and resource consent. Changes are reviewed and applied as one policy revision.</Notice>

        <section class="admin-section gaugeapp-policy-section"><SectionHeading title="Resource access & export" />
            <PolicyControlRow title="Who may export" note="An organization denial is added after project access and resource consent; selecting a role here never grants export.">
                <select aria-label="Who may export" value={draft().exportAccess} onChange={(event) => change("exportAccess", event.currentTarget.value as PolicyExportAccess)}>
                    <option value="owners-admins">Owners and administrators</option>
                    <option value="project-members">Project members with authority</option>
                    <option value="project-policy">No added organization restriction</option>
                </select>
            </PolicyControlRow>
            <PolicyControlRow title="Who may start Agent runs" note="Project and Agent placement authority are still required. This setting can only remove eligible roles.">
                <select aria-label="Who may start Agent runs" value={draft().runAccess} onChange={(event) => change("runAccess", event.currentTarget.value as PolicyRunAccess)}>
                    <option value="owners-admins">Owners and administrators</option>
                    <option value="project-members">Project members with authority</option>
                    <option value="project-policy">No added organization restriction</option>
                </select>
            </PolicyControlRow>
            <PolicyControlRow title="Require matching regions" note="The resource and acting member must have the same region. Unlabeled resources count as regulated; a required but missing region fails closed.">
                <select aria-label="Require matching regions" value={draft().regionMatch} onChange={(event) => change("regionMatch", event.currentTarget.value as PolicyRegionMatch)}>
                    <option value="pii">For PII resources</option>
                    <option value="pii-regulated">For PII and regulated resources</option>
                    <option value="all-labeled">For every resource</option>
                    <option value="floor">No added organization restriction</option>
                </select>
            </PolicyControlRow>
        </section>

        <section class="admin-section gaugeapp-policy-section"><SectionHeading title="Shared execution boundaries" meta="engagements and federated runs" />
            <p class="gaugeapp-section-intro">Choose where shared work involving this organization’s data may execute. At least one host type must remain allowed.</p>
            <div class="gaugeapp-policy-toggle-grid">
                <PolicyToggleRow title="Run owner’s host" note="The party starting the run operates the host." checked={draft().allowRunOwnerHost}
                    disabled={draft().allowRunOwnerHost && allowedHostCount() === 1} onChange={(value) => change("allowRunOwnerHost", value)} />
                <PolicyToggleRow title="Counterparty host" note="The other engagement party operates the host." checked={draft().allowCounterpartyHost}
                    disabled={draft().allowCounterpartyHost && allowedHostCount() === 1} onChange={(value) => change("allowCounterpartyHost", value)} />
                <PolicyToggleRow title="Neutral host" note="A third-party provider operates the host." checked={draft().allowNeutralHost}
                    disabled={draft().allowNeutralHost && allowedHostCount() === 1} onChange={(value) => change("allowNeutralHost", value)} />
            </div>
        </section>

        <section class="admin-section gaugeapp-policy-section"><SectionHeading title="Agent change admission" meta="organization defaults" />
            <PolicyControlRow title="New Agent placements" note="Approval creates a pending placement; the project owner must accept it before the Agent can be used.">
                <select aria-label="New Agent placements" value={draft().agentAdmission} onChange={(event) => change("agentAdmission", event.currentTarget.value as PolicyAgentAdmission)}>
                    <option value="approval">Require project-owner approval</option>
                    <option value="immediate">Activate immediately</option>
                </select>
            </PolicyControlRow>
            <PolicyControlRow title="Published Agent versions" note="Automatic upgrade only occurs when both the Agent publisher requests it and this organization allows it. Otherwise each placement stays pinned.">
                <select aria-label="Published Agent versions" value={draft().agentUpdates} onChange={(event) => change("agentUpdates", event.currentTarget.value as PolicyAgentUpdates)}>
                    <option value="manual">Review every upgrade</option>
                    <option value="publisher-auto">Allow publisher-requested auto-upgrades</option>
                </select>
            </PolicyControlRow>
        </section>

        <section class="admin-section gaugeapp-policy-section"><SectionHeading title="Sessions & audit history" />
            <Show when={props.scope.enterpriseControls === "active"}><>
                <PolicyControlRow title="Maximum session lifetime" note="The enterprise data routes require reauthentication after this total session age.">
                    <select aria-label="Maximum session lifetime" value={draft().sessionLifetime} onChange={(event) => change("sessionLifetime", event.currentTarget.value as OrganizationPolicyDraft["sessionLifetime"])}>
                        <option value="4">4 hours</option><option value="8">8 hours</option><option value="12">12 hours</option><option value="24">24 hours</option>
                    </select>
                </PolicyControlRow>
                <PolicyControlRow title="Idle timeout" note="Activity refreshes the idle clock; an expired token stays refused until the member reauthenticates.">
                    <select aria-label="Idle timeout" value={draft().idleTimeout} onChange={(event) => change("idleTimeout", event.currentTarget.value as OrganizationPolicyDraft["idleTimeout"])}>
                        <option value="15">15 minutes</option><option value="30">30 minutes</option><option value="60">60 minutes</option><option value="120">2 hours</option>
                    </select>
                </PolicyControlRow>
            </></Show>
            <PolicyControlRow title="Minimum audit-history guarantee" note="GaugeDesk keeps the append-only event history indefinitely. This is a buyer guarantee, not a deletion schedule.">
                <select aria-label="Minimum audit-history guarantee" value={draft().auditMinimum} onChange={(event) => change("auditMinimum", event.currentTarget.value as OrganizationPolicyDraft["auditMinimum"])}>
                    <option value="365">At least 1 year</option><option value="1095">At least 3 years</option><option value="2555">At least 7 years</option>
                </select>
            </PolicyControlRow>
        </section>

        <section class="admin-section gaugeapp-form-card gaugeapp-policy-review" aria-label="Policy change summary">
            <SectionHeading title="Policy changes" meta={dirty() ? `${changedFields().length} pending` : "none pending"} />
            <Show when={dirty()} fallback={<p class="gaugeapp-field-note">No pending changes.</p>}>
                <div class="gaugeapp-policy-change-list"><For each={changedFields()}>{(field) => <div class="gaugeapp-policy-change-row">
                    <span>{field.label}</span><span>{field.before}</span><span aria-hidden="true">→</span><strong>{field.after}</strong>
                </div>}</For></div>
            </Show>
            <div class="bar"><button class="tree-action" type="button" disabled={!dirty()} onClick={discard}>discard changes</button><button type="button" disabled={!dirty()} onClick={accept}>accept policy revision</button></div>
        </section>
    </>;
}

interface ProjectHostFixture {
    readonly name: string;
    readonly kind: string;
    readonly detail: string;
    readonly tone: "ready" | "warn";
    readonly action: string;
    readonly secondaryAction?: string;
}

function primaryProjectHost(scope: ScopeFixture): string {
    if (scope.kind === "signed-out-local" || scope.id === "personal-free") return "GaugeDesk desktop Project Host";
    if (scope.id === "personal-plus") return "Personal Cloud Project Host";
    if (scope.cloudHome === "self-managed") return "Office Mac Project Host";
    return `${scope.label} Cloud Project Host`;
}

function projectHosts(scope: ScopeFixture): readonly ProjectHostFixture[] {
    const primary = primaryProjectHost(scope);
    if (scope.kind === "signed-out-local") return [{
        name: primary, kind: "this computer", detail: "Available now · stores 2 project Homes · local custody", tone: "ready", action: "inspect",
    }];
    if (scope.id === "personal-free") return [{
        name: primary, kind: "self-managed", detail: "Available now · stores the Personal Home · account linked", tone: "ready", action: "inspect",
    }];
    if (scope.cloudHome === "self-managed") return [{
        name: primary, kind: "self-managed", detail: `Available · stores ${PROJECTS_BY_SCOPE[scope.id].length} project Home · reported 12 minutes ago`, tone: "ready", action: "inspect",
    }];
    const hosts: ProjectHostFixture[] = [{
        name: primary, kind: "managed", detail: `Available · us-east · stores ${PROJECTS_BY_SCOPE[scope.id].length} project Homes · background work enabled`, tone: "ready", action: "manage",
    }];
    if (scope.kind === "organization") hosts.push({
        name: "Office workstation", kind: "self-managed", detail: "Unreachable · no project Homes · last report 19 hours ago", tone: "warn", action: "diagnose", secondaryAction: "disconnect",
    });
    return hosts;
}

function ProjectHomeRow(props: { project: ProjectFixture; host: string }): JSX.Element {
    const interact = useContext(InteractionContext);
    return <div class="gaugeapp-home-row">
        <span><strong>{props.project.name}</strong><small>{props.project.isPersonal ? "Personal project" : `project:${props.project.id}`}</small></span>
        <span><small>Project Host</small><strong>{props.host}</strong></span>
        <span class="badge">available</span>
        <span class="gaugeapp-row-actions"><button type="button" class="tree-action" onClick={() => interact({
            action: "open project settings", title: props.project.name, kind: props.project.id,
            description: `Project authority and Home on ${props.host}`,
        })}>settings</button></span>
    </div>;
}

function ProjectHostsPanel(props: { scope: ScopeFixture }): JSX.Element {
    const projects = () => PROJECTS_BY_SCOPE[props.scope.id];
    const hosts = () => projectHosts(props.scope);
    const hostForProject = (index: number) => props.scope.id === "personal-plus" && index === 1
        ? "GaugeDesk desktop Project Host" : primaryProjectHost(props.scope);
    return <>
        <Notice tone="neutral"><strong>Every project has one authoritative Home on a Project Host.</strong> A Project Host stores one or more project Homes and can run background work. Trusted Devices connect to those Homes but never carry them.</Notice>
        <div class="gaugeapp-metrics gaugeapp-home-metrics">
            <Metric label="Project Homes" value={`${projects().length}`} note="one per project" />
            <Metric label="Project Hosts" value={`${hosts().length}`} note={hosts().some((host) => host.tone === "warn") ? "one needs attention" : "all available"} tone={hosts().some((host) => host.tone === "warn") ? "warn" : undefined} />
            <Metric label="Trusted Devices" value={props.scope.kind === "signed-out-local" ? "1 local" : "2 active"} note="managed under your account" />
        </div>
        <section class="admin-section"><SectionHeading title="Project Homes" meta={`${projects().length} authoritative`} />
            <p class="gaugeapp-section-intro">Each project has exactly one Home. Moving it is an explicit handoff from the project’s settings.</p>
            <div class="gaugeapp-home-list"><For each={projects()}>{(project, index) => <ProjectHomeRow project={project} host={hostForProject(index())} />}</For></div>
        </section>
        <section class="admin-section"><SectionHeading title="Admitted Project Hosts" meta={`${hosts().length} admitted`}
            action={props.scope.id === "personal-free" ? "add Cloud Home" : "add Project Host"} />
            <For each={hosts()}>{(host) => <Resource kind={host.kind} title={host.name} detail={host.detail} tone={host.tone}
                action={host.action} secondaryAction={host.secondaryAction} />}</For>
            <p class="gaugeapp-field-note">Adding a Project Host admits its identity and capabilities. It carries no project Home until you create one there or complete a handoff.</p>
        </section>
    </>;
}

function BackupsPanel(props: { scope: ScopeFixture }): JSX.Element {
    const [message, setMessage] = createSignal("");
    const [restoring, setRestoring] = createSignal(false);
    if (props.scope.kind === "signed-out-local") return <>
        <Notice tone="neutral">Local recovery stays on storage you control. No GaugeWright backup service or account recovery holder exists while signed out.</Notice>
        <section class="admin-section"><SectionHeading title="Local backup" action="schedule & retention" />
            <Resource kind="encrypted" title="Workspace backup" detail="Local drive · last recovery point 7 hours ago" tone="ready" action="create now" secondaryAction="turn off" onAction={() => setMessage("A local recovery point would be created.")} />
        </section>
        <section class="admin-section"><SectionHeading title="Recovery holder" />
            <Resource kind="this Trusted Device" title="GaugeDesk desktop" detail="The recovery key remains on this computer" tone="ready" action="recovery instructions" />
        </section>
        <Show when={message()}><p class="status" role="status">{message()}</p></Show>
    </>;
    if (props.scope.kind === "personal" && props.scope.cloudHome === "none") return <>
        <Notice tone="neutral">A free account carries identity, membership, routes, and encrypted account settings. It does not include a hosted project backup.</Notice>
        <section class="admin-section"><SectionHeading title="Hosted backup" meta="not added" action="upgrade to Plus" />
            <Definition label="Project backups" value="No GaugeWright backup destination" note="local or self-managed backup remains under the Home owner’s control" />
            <Definition label="Account recovery" value="Available" note="recovers account sign-in and identity, not project data" />
        </section>
    </>;
    if (props.scope.kind === "personal") return <>
        <section class="admin-section"><SectionHeading title="Backups" action="schedule & retention" />
            <Resource kind="daily" title="Personal Cloud Project Host backup" detail="30-day retention · last recovery point 7 hours ago" tone="ready" action="create now" secondaryAction="turn off" onAction={() => setMessage("Recovery point creation started.")} />
        </section>
        <section class="admin-section"><SectionHeading title="Recovery access" meta="your Trusted Devices" action="add recovery holder" />
            <Resource kind="trusted-device" title="Jack · GaugeDesk desktop" detail="Added Aug 12 · key remains on the Trusted Device" tone="ready" action="inspect" />
            <Resource kind="trusted-device" title="Jack · iPhone" detail="Added Aug 18 · recovery access enabled" tone="ready" action="inspect" secondaryAction="remove" />
        </section>
        <section class="admin-section"><SectionHeading title="Restore" action="view all points" />
            <Resource kind="Aug 21" title="09:10 UTC recovery point" detail="Healthy · encrypted · can restore to another Project Host" tone="ready" action={restoring() ? undefined : "restore"} onAction={() => setRestoring(true)} />
            <Show when={restoring()}><div class="gaugeapp-restore-form"><label>Restore to<select><option>New managed Project Host</option><option>GaugeDesk desktop Project Host</option></select></label>
                <div class="bar"><button class="tree-action" type="button" onClick={() => setRestoring(false)}>cancel</button><button type="button" onClick={() => { setRestoring(false); setMessage("Restore started on a new managed Project Host."); }}>start restore</button></div></div></Show>
        </section>
        <Show when={message()}><p class="status" role="status">{message()}</p></Show>
    </>;
    if (props.scope.cloudHome === "self-managed") return <>
        <Notice tone="neutral">GaugeWright has no project backup facility for this organization. Backup of the self-managed Home remains the operator’s responsibility.</Notice>
        <section class="admin-section"><SectionHeading title="Backups" meta="not configured" />
            <Definition label="Protection" value="Not configured in GaugeDesk" note="the Home operator owns backup and restore" />
            <Definition label="GaugeWright recovery access" value="None" note="no managed backup exists" />
        </section>
    </>;
    return <>
        <section class="admin-section"><SectionHeading title="Backups" action="schedule & retention" />
            <Resource kind="daily" title="Encrypted backup" detail="30-day retention · last recovery point 7 hours ago" tone="ready" action="create now" secondaryAction="turn off" onAction={() => setMessage("Recovery point creation started.")} />
        </section>
        <section class="admin-section"><SectionHeading title="Recovery access" meta="2 Trusted Devices" action="add recovery holder" />
            <Resource kind="trusted-device" title="Jack · GaugeDesk desktop" detail="Added Aug 12 · key remains on the Trusted Device" tone="ready" action="inspect" secondaryAction="remove" />
            <Resource kind="trusted-device" title="Maya · recovery Trusted Device" detail="Added Aug 16 · key remains on the Trusted Device" tone="ready" action="inspect" secondaryAction="remove" />
        </section>
        <section class="admin-section"><SectionHeading title="Restore" action="view all points" />
            <Resource kind="Aug 21" title="09:10 UTC recovery point" detail="Healthy · encrypted · can restore to another location" tone="ready" action={restoring() ? undefined : "restore"} onAction={() => setRestoring(true)} />
            <Show when={restoring()}><div class="gaugeapp-restore-form">
                <label>Restore to<select><option>New managed Project Host</option><option>{props.scope.label} Cloud Project Host</option></select></label>
                <div class="bar"><button class="tree-action" type="button" onClick={() => setRestoring(false)}>cancel</button><button type="button" onClick={() => { setRestoring(false); setMessage("Restore started on a new managed Project Host."); }}>start restore</button></div>
            </div></Show>
        </section>
        <Show when={message()}><p class="status" role="status">{message()}</p></Show>
    </>;
}

interface SoftwarePolicyDraft {
    readonly channel: "stable" | "stable-beta";
    readonly minimumVersion: string;
    readonly minimumProtocol: string;
    readonly graceDeadline: string;
}

function softwarePolicyValue(key: keyof SoftwarePolicyDraft, value: string): string {
    if (key === "channel") return value === "stable-beta" ? "Stable and beta" : "Stable";
    if (key === "minimumProtocol") return `Protocol ${value}`;
    return value || "Not set";
}

function SoftwarePanel(): JSX.Element {
    const report = useContext(ActionFeedbackContext);
    const initial: SoftwarePolicyDraft = { channel: "stable", minimumVersion: "", minimumProtocol: "4", graceDeadline: "" };
    const [saved, setSaved] = createSignal(initial);
    const [draft, setDraft] = createSignal(initial);
    const change = <K extends keyof SoftwarePolicyDraft>(key: K, value: SoftwarePolicyDraft[K]) => {
        setDraft((current) => ({ ...current, [key]: value }));
    };
    const dirty = createMemo(() => JSON.stringify(saved()) !== JSON.stringify(draft()));
    const changedFields = createMemo(() => {
        const names: Record<keyof SoftwarePolicyDraft, string> = {
            channel: "allowed channel", minimumVersion: "minimum version",
            minimumProtocol: "minimum protocol", graceDeadline: "grace deadline",
        };
        return (Object.keys(names) as (keyof SoftwarePolicyDraft)[])
            .filter((key) => saved()[key] !== draft()[key])
            .map((key) => ({ label: names[key], before: softwarePolicyValue(key, saved()[key]), after: softwarePolicyValue(key, draft()[key]) }));
    });
    return <>
        <section class="admin-section"><SectionHeading title="Allowed GaugeDesk versions" />
            <p class="gaugeapp-section-intro">Project Hosts refuse clients below the admitted protocol or version after any grace deadline.</p>
            <div class="gaugeapp-field-grid">
                <label>Allowed channel<select value={draft().channel} onChange={(event) => change("channel", event.currentTarget.value as SoftwarePolicyDraft["channel"])}>
                    <option value="stable">Stable</option><option value="stable-beta">Stable and beta</option>
                </select></label>
                <label>Minimum GaugeDesk version<input value={draft().minimumVersion} onInput={(event) => change("minimumVersion", event.currentTarget.value)} placeholder="Not set" /></label>
                <label>Minimum protocol<input type="number" min="1" value={draft().minimumProtocol} onInput={(event) => change("minimumProtocol", event.currentTarget.value)} /></label>
                <label>Grace deadline<input type="date" value={draft().graceDeadline} onInput={(event) => change("graceDeadline", event.currentTarget.value)} /></label>
            </div>
        </section>
        <section class="admin-section gaugeapp-form-card gaugeapp-policy-review" aria-label="Software policy change summary">
            <SectionHeading title="Policy changes" meta={dirty() ? `${changedFields().length} pending` : "none pending"} />
            <Show when={dirty()} fallback={<p class="gaugeapp-field-note">No pending changes.</p>}>
                <div class="gaugeapp-policy-change-list"><For each={changedFields()}>{(field) => <div class="gaugeapp-policy-change-row">
                    <span>{field.label}</span><span>{field.before}</span><span aria-hidden="true">→</span><strong>{field.after}</strong>
                </div>}</For></div>
            </Show>
            <div class="bar"><button class="tree-action" type="button" disabled={!dirty()} onClick={() => {
                setDraft(saved()); report("Software policy changes were discarded.");
            }}>discard changes</button><button type="button" disabled={!dirty()} onClick={() => {
                setSaved(draft()); report("Software policy revision applied for this prototype.");
            }}>apply policy</button></div>
        </section>
    </>;
}

function ClientsPanel(): JSX.Element {
    return <>
        <Notice tone="neutral">These are active GaugeDesk sessions. Commercial clients are in Commercial Operations.</Notice>
        <section class="admin-section"><SectionHeading title="Active clients" meta="2 admitted · 1 recovery-only" />
            <Resource kind="admitted" title="Jack · GaugeDesk desktop 0.4.6" detail="Linux · protocol 4 · last request 2 minutes ago" tone="ready" action="inspect" secondaryAction="revoke session" />
            <Resource kind="admitted" title="Maya · GaugeDesk desktop 0.4.6" detail="macOS · protocol 4 · last request 14 minutes ago" tone="ready" action="inspect" secondaryAction="revoke session" />
            <Resource kind="recovery only" title="Eli · GaugeDesk desktop 0.4.3" detail="version below proposed floor · updater and logout remain reachable" tone="warn" action="view admission" secondaryAction="revoke session" />
        </section>
    </>;
}

function BillingPanel(props: { scope: ScopeFixture }): JSX.Element {
    const interact = useContext(InteractionContext);
    const prototype = useContext(PrototypeOrganizationContext);
    if (props.scope.kind === "personal" && props.scope.cloudHome === "none") return <>
        <section class="admin-section"><SectionHeading title="Current account" />
            <SettingsRow title="Free account" note="Person identity, Personal tenant, invitations, memberships, Trusted Devices, and project routes" meta="active" />
            <Definition label="Work you can use" value="Any Home that admits you" note="your computer, a self-managed Home, or another tenant’s paid Home" />
            <Definition label="Hosted work you own" value="None" note="sign-up creates no unbounded storage or compute promise" />
        </section>
        <section class="admin-section"><SectionHeading title="GaugeDesk Plus" action="review options" />
            <Definition label="Cloud Home" value="One managed Project Host" note="durable projects and bounded workflow execution" />
            <Definition label="Cloud backup" value="Basic encrypted backup" note="recovery access remains explicit" />
        </section>
    </>;
    if (props.scope.kind === "personal") return <>
        <section class="admin-section"><SectionHeading title="Plan & services" />
            <SettingsRow title="Personal services" note="One owner · no seat entitlement" meta="active" action="change plan" />
            <Definition label="Cloud Home" value="Personal Cloud Project Host" note="active · us-east" />
            <Definition label="Backup" value="Daily" note="30-day encrypted retention" />
        </section>
        <section class="admin-section"><SectionHeading title="Payment & billing contact" />
            <SettingsRow title="Visa ending 4242" note="Expires 08/29 · used for GaugeWright services" meta="default" action="update" />
            <SettingsRow title="jack@gaugewright.com" note="Invoices and payment notices" meta="billing email" action="edit" />
        </section>
        <section class="admin-section"><SectionHeading title="Invoices" meta="processor records" action="view all" />
            <Resource kind="upcoming" title="September 1 invoice" detail="Estimate available · services may change before close" tone="neutral" action="view estimate" />
            <Resource kind="paid" title="August 1 invoice" detail="Paid Aug 1 · receipt available" tone="ready" action="view" secondaryAction="download PDF" />
            <Resource kind="paid" title="July 1 invoice" detail="Paid Jul 1 · receipt available" tone="ready" action="view" secondaryAction="download PDF" />
        </section>
    </>;
    const subscription = () => organizationSubscription(props.scope, prototype.get(props.scope.id));
    const baseOnly = () => subscription().plan === "base";
    return <>
        <Notice tone="neutral">Plan, seat, and organization-service changes are managed under Plans & services. Billing contains payment and accounting records only.</Notice>
        <section class="admin-section"><SectionHeading title="Current period" meta={baseOnly() ? "$0" : `${subscription().estimate} plan estimate`} action="open Plans & services"
            onAction={() => interact({ action: "open plans and services", title: "Plans & services" })} />
            <Show when={baseOnly()} fallback={<>
                <Definition label="Managed organization" value="$120.00" note={subscription().cadence} />
                <Definition label={`Seat capacity · ${subscription().purchasedSeats}`} value={`$${subscription().purchasedSeats * 20}.00`} note={`${subscription().assignedSeats} assigned · payment is not assignment`} />
                <Definition label="Encrypted backup" value="Included" note="managed plan · daily · 30-day retention" />
                <Definition label="Managed inference" value={props.scope.id === "gaugewright" ? "$40.20" : "$20.20"} note="usage through Aug 25" />
            </>}><Definition label="Base organization" value="$0" note="no paid services this period" /></Show>
        </section>
        <section class="admin-section"><SectionHeading title="Payment & billing contact" />
            <Show when={baseOnly()} fallback={<>
            <SettingsRow title="Visa ending 4242" note="Expires 08/29 · organization default" meta="default" action="update" />
            <SettingsRow title={`billing@${scopeDomain(props.scope)}`} note="Invoices and payment notices" meta="billing email" action="edit" />
            </>}><>
                <SettingsRow title="No payment method" note="Collected only when the organization adds a paid service" meta="none" />
                <SettingsRow title={`jack@${scopeDomain(props.scope)}`} note="Service notices and future invoices" meta="billing email" action="edit" />
            </></Show>
        </section>
        <Show when={!baseOnly()}><section class="admin-section"><SectionHeading title="Invoices" meta="processor records" action="view all" />
            <Resource kind="upcoming" title="September 1 invoice" detail="Estimate available · seats and usage may change before close" tone="neutral" action="view estimate" />
            <Resource kind="paid" title="August 1 invoice" detail="Paid Aug 1 · receipt available" tone="ready" action="view" secondaryAction="download PDF" />
            <Resource kind="paid" title="July 1 invoice" detail="Paid Jul 1 · receipt available" tone="ready" action="view" secondaryAction="download PDF" />
        </section></Show>
        <Show when={!baseOnly()}><section class="admin-section"><SectionHeading title="Usage charges" action="open Model Providers"
            onAction={() => interact({ action: "open model providers", title: "Organization model plan" })} />
            <div class="gaugeapp-plan"><div><strong>Managed inference</strong><span>42,180 of 250,000 included tokens used</span></div><span class="badge">17%</span></div>
            <div class="gaugeapp-usage"><span style={{ width: "17%" }} /></div>
            <SettingsRow title="Current model usage" note="42,180 used this period" meta={props.scope.id === "gaugewright" ? "$40.20" : "$20.20"} action="view usage" />
        </section></Show>
    </>;
}

function SettingsView(props: { scope: ScopeFixture; tab: string }): JSX.Element {
    const title = () => props.tab;
    return <><PageHeader eyebrow={props.scope.kind === "signed-out-local" ? "This computer" : "Your Account"} title={title()}
        description={props.tab === "Trusted Devices"
            ? props.scope.kind === "signed-out-local" ? "Phones and computers trusted by this computer’s local identity." : "Phones and computers trusted to act as you and request access from your project Homes."
            : props.tab === "Provider Connections"
                ? props.scope.kind === "signed-out-local"
                    ? "Provider credentials, local endpoints, and model defaults stored on this computer."
                    : "Provider sign-ins, API keys, local endpoints, and model defaults that belong to your account."
            : props.scope.kind === "signed-out-local" ? "Local identity, providers, Trusted Devices, and GaugeDesk preferences on this computer." : "Your GaugeDesk account, provider connections, Trusted Devices, and application preferences."} />
        <DashboardGrid surface>
            <Show when={props.tab === "Sign In"}><SignedOutAccountPanel /></Show>
            <Show when={props.tab === "Account Settings"}><AccountSettingsPanel /></Show>
            <Show when={props.tab === "Provider Connections"}><ModelAccessPanel scope={props.scope} owner="account" /></Show>
            <Show when={props.tab === "Trusted Devices"}><TrustedDevicesPanel scope={props.scope} /></Show>
            <Show when={props.tab === "Application Settings"}><ApplicationSettingsPanel /></Show>
        </DashboardGrid>
    </>;
}

function SignedOutAccountPanel(): JSX.Element {
    return <>
        <Notice tone="neutral">GaugeDesk works locally while signed out. Signing in links this Desk to your account; it does not upload or relocate local project work.</Notice>
        <section class="admin-section"><SectionHeading title="Current session" />
            <SettingsRow title="Signed out" note="Local authority on this computer" meta="local" action="sign in" />
        </section>
    </>;
}

function AccountSettingsPanel(): JSX.Element {
    const [message, setMessage] = createSignal("");
    return <>
        <section class="admin-section"><SectionHeading title="Account" />
            <SettingsRow title="Jack Scully" note="jack@gaugewright.com" meta="signed in" action="edit profile" />
        </section>
        <section class="admin-section"><SectionHeading title="Sessions" />
            <SettingsRow title="This GaugeDesk" note="Linux · admitted Aug 21" meta="current" action="sign out" onAction={() => setMessage("This GaugeDesk session would be signed out.")} />
            <SettingsRow title="Other sessions" note="Chrome on macOS · last active Aug 19" meta="1" action="sign out all" onAction={() => setMessage("Every other account session would be signed out.")} />
        </section>
        <section class="admin-section"><SectionHeading title="Membership invitations" meta="1" />
            <SettingsRow title="Northstar Labs" note="Member invitation from Priya Shah · expires Aug 28" meta="invited" action="accept" secondaryAction="decline" onAction={() => setMessage("The Northstar Labs invitation would be accepted.")} onSecondaryAction={() => setMessage("The Northstar Labs invitation would be declined.")} />
        </section>
        <Show when={message()}><p class="status" role="status">{message()}</p></Show>
    </>;
}

type ModelConnectionProvider = "openai-codex" | "openai" | "anthropic" | "xai-grok" | "xai" | "openrouter" | "openai-generic";
type ModelConnectionOwner = "organization" | "personal" | "computer";

function modelConnectionProviderName(provider: ModelConnectionProvider): string {
    return ({
        "openai-codex": "OpenAI Codex", openai: "OpenAI API", anthropic: "Anthropic",
        "xai-grok": "xAI Grok subscription", xai: "xAI API", openrouter: "OpenRouter",
        "openai-generic": "OpenAI-compatible endpoint",
    } as const)[provider];
}

function ModelConnectionForm(props: {
    local: boolean;
    owner: ModelConnectionOwner;
    ownerLabel: string;
    onCancel: () => void;
    onComplete: (provider: ModelConnectionProvider) => void;
}): JSX.Element {
    const organizationOwned = () => props.owner === "organization";
    const [provider, setProvider] = createSignal<ModelConnectionProvider>(organizationOwned() ? "openai" : "openai-codex");
    const isEndpoint = () => provider() === "openai-generic";
    const isAccountSignIn = () => provider() === "openai-codex" || provider() === "xai-grok";
    const takesModels = () => provider() === "openai-generic" || provider() === "openrouter";
    const providerName = () => modelConnectionProviderName(provider());
    return <div class="gaugeapp-model-connection-form">
        <div class="gaugeapp-field-grid">
            <label>Provider<select value={provider()} onChange={(event) => setProvider(event.currentTarget.value as ModelConnectionProvider)}>
                <Show when={!organizationOwned()}><option value="openai-codex">OpenAI Codex account</option><option value="xai-grok">xAI Grok subscription</option></Show>
                <option value="openai">OpenAI API</option><option value="anthropic">Anthropic</option><option value="xai">xAI API</option>
                <option value="openrouter">OpenRouter</option><option value="openai-generic">OpenAI-compatible endpoint</option>
            </select></label>
            <Show when={isEndpoint()}><label>Endpoint URL<input type="url" placeholder={props.local ? "http://localhost:11434/v1" : "https://api.example.com/v1"} /></label></Show>
            <Show when={!isAccountSignIn()}><label classList={{ "gaugeapp-field-span": !isEndpoint() }}>API key<input type="password" autocomplete="off" placeholder={props.local ? "Stored on this computer" : "Stored sealed to your account"} /></label></Show>
            <Show when={takesModels()}><label class="gaugeapp-field-span">Model IDs<textarea placeholder={provider() === "openrouter" ? 'anthropic/claude-sonnet-4.1\ngoogle/gemini-2.5-pro' : 'model-a\nmodel-b'} /></label></Show>
        </div>
        <Show when={isAccountSignIn()}><p class="gaugeapp-field-note">{provider() === "xai-grok"
            ? "xAI account authorization opens separately and uses your Grok or X Premium subscription."
            : "OpenAI authorization opens separately; your GaugeWright sign-in is not reused."}</p></Show>
        <Show when={organizationOwned()}><p class="gaugeapp-field-note">The secret is held for {props.ownerLabel}. Owners and admins may replace it; allowed members and projects can use it but never view it.</p></Show>
        <div class="bar"><button class="tree-action" type="button" onClick={props.onCancel}>cancel</button>
            <button type="button" aria-label={isAccountSignIn() ? undefined : `Add ${providerName()}`}
                onClick={() => props.onComplete(provider())}>{isAccountSignIn() ? `continue with ${provider() === "xai-grok" ? "xAI" : "OpenAI"}` : "add connection"}</button></div>
    </div>;
}

function ModelConnectionRow(props: {
    name: string;
    auth: string;
    owner: string;
    status?: string;
    action?: string;
    secondaryAction?: string;
    onAction?: () => void;
    onSecondaryAction?: () => void;
}): JSX.Element {
    return <div class="gaugeapp-model-connection-row">
        <span class="gaugeapp-model-connection-name"><strong>{props.name}</strong><small>{props.auth}</small></span>
        <span class="gaugeapp-model-connection-owner">{props.owner}</span>
        <span class="badge">{props.status ?? "connected"}</span>
        <Show when={props.action || props.secondaryAction}><span class="gaugeapp-row-actions">
            <Show when={props.action}><button type="button" class="tree-action" onClick={props.onAction}>{contextualActionLabel(props.action!)}</button></Show>
            <Show when={props.secondaryAction}><button type="button" class="tree-action" onClick={props.onSecondaryAction}>{contextualActionLabel(props.secondaryAction!)}</button></Show>
        </span></Show>
    </div>;
}

interface ModelPickerFixture {
    readonly key: string;
    readonly name: string;
    readonly connection: string;
}

interface ModelAccessGrantFixture {
    readonly id: string;
    readonly kind: "project" | "member";
    readonly target: string;
    readonly access: string;
    readonly used: number;
    readonly monthlyLimit: number | null;
}

interface OrganizationModelConnectionFixture { readonly name: string; readonly auth: string; }

function organizationModelConnections(scope: ScopeFixture): readonly OrganizationModelConnectionFixture[] {
    if (scope.id === "acorn") return [];
    if (scope.id === "gaugewright") return [
        { name: "OpenAI API", auth: "shared API key" },
        { name: "Anthropic", auth: "shared API key" },
    ];
    if (scope.id === "northstar") return [{ name: "Enterprise model gateway", auth: "shared endpoint" }];
    return [{ name: "OpenAI API", auth: "shared API key" }];
}

function initialModelAccessGrants(scope: ScopeFixture): readonly ModelAccessGrantFixture[] {
    const projects = PROJECTS_BY_SCOPE[scope.id] ?? [];
    if (scope.id === "acorn") return [];
    return [
        { id: `${scope.id}:project:1`, kind: "project", target: projects[0]?.name ?? "Primary project", access: "All organization connections", used: scope.id === "northstar" ? 612 : 126, monthlyLimit: scope.id === "northstar" ? 1500 : 500 },
        ...(projects[1] ? [{ id: `${scope.id}:project:2`, kind: "project" as const, target: projects[1].name, access: "OpenAI API only", used: 78, monthlyLimit: 250 }] : []),
        { id: `${scope.id}:member:jack`, kind: "member", target: "Jack Scully", access: "All organization connections", used: 42, monthlyLimit: 150 },
    ];
}

function ModelAccessGrantRow(props: {
    grant: ModelAccessGrantFixture;
    editable: boolean;
    onEdit: () => void;
    onRemove: () => void;
}): JSX.Element {
    return <div class="gaugeapp-model-grant-row">
        <span><strong>{props.grant.target}</strong><small>{props.grant.kind === "member" ? "person" : "project"}</small></span>
        <span>{props.grant.access}</span>
        <span>${props.grant.used.toLocaleString()}</span>
        <span>{props.grant.monthlyLimit === null ? "No hard cap" : `$${props.grant.monthlyLimit.toLocaleString()}`}</span>
        <Show when={props.editable}><span class="gaugeapp-row-actions"><button type="button" class="tree-action" onClick={props.onEdit}>edit</button><button type="button" class="tree-action" onClick={props.onRemove}>remove</button></span></Show>
    </div>;
}

function ModelPickerRow(props: {
    model: ModelPickerFixture;
    enabled: boolean;
    isDefault: boolean;
    defaultOwner: "account" | "organization";
    onEnabled: (enabled: boolean) => void;
    onDefault: () => void;
}): JSX.Element {
    return <div class="gaugeapp-model-picker-row">
        <label class="gaugeapp-model-picker-visibility" title={props.isDefault ? "The default model is always shown" : "Show in the chat model picker"}>
            <input type="checkbox" checked={props.enabled || props.isDefault} disabled={props.isDefault}
                aria-label={`Show ${props.model.name} in the model picker`}
                onChange={(event) => props.onEnabled(event.currentTarget.checked)} />
        </label>
        <strong title={props.model.name}>{props.model.name}</strong>
        <span title={props.model.connection}>{props.model.connection}</span>
        <label class="gaugeapp-model-picker-default">
            <input type="radio" name="default-model" checked={props.isDefault}
                aria-label={`Make ${props.model.name} the ${props.defaultOwner} default`} onChange={props.onDefault} />
            <span>{props.isDefault ? "default" : ""}</span>
        </label>
    </div>;
}

/** Fixture commercial terms exercise the complete enrollment path; they are not
 * accepted tariff or backend truth. The durable implementation already admits
 * plan/status/included-token records, while live processor activation remains a
 * separate commercial-infrastructure step. */
function ManagedInferenceSignup(props: {
    onCancel: () => void;
    onActivate: () => void;
}): JSX.Element {
    const [step, setStep] = createSignal<"plan" | "checkout">("plan");
    const [spending, setSpending] = createSignal("Stop when the plan allowance is reached");
    return <div class="gaugeapp-managed-signup">
        <div class="gaugeapp-managed-signup-head"><span><strong>Start managed inference</strong><small>Use hosted models without connecting a provider account.</small></span><button type="button" class="tree-action" onClick={props.onCancel}>cancel</button></div>
        <div class="gaugeapp-managed-signup-facts">
            <span><small>Service</small><strong>Managed inference</strong></span>
            <span><small>Models</small><strong>Shown before activation</strong></span>
            <span><small>Price</small><strong>Current terms at checkout</strong></span>
        </div>
        <Show when={step() === "plan"} fallback={<div class="gaugeapp-managed-payment">
            <div class="gaugeapp-managed-payment-head"><span class="gaugeapp-owner-chip">Stripe</span><span><strong>Secure checkout</strong><small>Payment details and final commercial terms are collected by the processor, outside Agent context.</small></span></div>
            <Definition label="GaugeDesk sends" value="Account and selected service" note="No project data, model credentials, or Agent context" />
            <Definition label="GaugeDesk receives" value="Payment confirmation and service reference" note="Used to activate the managed inference entitlement" />
            <div class="bar"><button type="button" class="tree-action" onClick={() => setStep("plan")}>back</button><button type="button" onClick={props.onActivate}>continue in secure checkout</button></div>
        </div>}>
            <label class="gaugeapp-managed-spending">Usage after allowance<select value={spending()} onChange={(event) => setSpending(event.currentTarget.value)}><option>Stop when the plan allowance is reached</option><option>Allow additional usage up to a spending limit</option></select></label>
            <p class="gaugeapp-field-note">Project policy and model-picker visibility still apply after the service is active.</p>
            <div class="bar"><button type="button" onClick={() => setStep("checkout")}>continue to secure checkout</button></div>
        </Show>
    </div>;
}
function ModelAccessPanel(props: { scope: ScopeFixture; owner: "account" | "organization" }): JSX.Element {
    const interact = useContext(InteractionContext);
    const local = () => props.owner === "account" && props.scope.kind === "signed-out-local";
    const organization = () => props.owner === "organization";
    const canManageOrganization = () => organization() && props.scope.organizationRole !== "member";
    const defaultStorageKey = () => organization()
        ? `gaugeapps.default-model.organization.${props.scope.id}`
        : local() ? "gaugeapps.default-model.local" : "gaugeapps.default-model.account";
    const fallbackDefault = () => local()
        ? "local:qwen3-coder"
        : organization() ? props.scope.id === "northstar" ? "managed:gpt-5.4-mini" : `org:${props.scope.id}:gpt-5.4`
        : "codex:gpt-5.6";
    const [addingFor, setAddingFor] = createSignal<ModelConnectionOwner | null>(null);
    const [editingModels, setEditingModels] = createSignal(false);
    const [confirmingRemove, setConfirmingRemove] = createSignal(false);
    const [settingUpPlan, setSettingUpPlan] = createSignal(false);
    const [grantEditorOpen, setGrantEditorOpen] = createSignal(false);
    const [editingGrantId, setEditingGrantId] = createSignal<string | null>(null);
    const [grantKind, setGrantKind] = createSignal<"project" | "member">("project");
    const [grantTarget, setGrantTarget] = createSignal("");
    const [grantAccess, setGrantAccess] = createSignal("All organization connections");
    const [grantLimit, setGrantLimit] = createSignal("250");
    const [grantOverrides, setGrantOverrides] = createSignal<Partial<Record<ScopeId, readonly ModelAccessGrantFixture[]>>>({});
    const [organizationConnectionOverrides, setOrganizationConnectionOverrides] = createSignal<Partial<Record<ScopeId, readonly OrganizationModelConnectionFixture[]>>>({});
    const [activatedPlanScopes, setActivatedPlanScopes] = createSignal(new Set<string>());
    const planAuthority = () => organization() ? props.scope.id : "personal";
    const planActive = () => activatedPlanScopes().has(planAuthority()) || (organization()
        ? props.scope.id !== "acorn"
        : props.scope.kind !== "signed-out-local" && props.scope.id !== "personal-free");
    const [modelFilter, setModelFilter] = createSignal("");
    const [defaultModel, setDefaultModel] = createSignal(localStorage.getItem(defaultStorageKey()) ?? fallbackDefault());
    const [enabledModels, setEnabledModels] = createSignal(new Set([
        "codex:gpt-5.6", "codex:gpt-5.4", "xai-sub:grok-4.6", "managed:gpt-5.4-mini", "local:qwen3-coder",
    ]));
    const [message, setMessage] = createSignal("");
    const organizationConnections = () => organizationConnectionOverrides()[props.scope.id] ?? organizationModelConnections(props.scope);
    const writeOrganizationConnections = (next: readonly OrganizationModelConnectionFixture[]) => setOrganizationConnectionOverrides((current) => ({ ...current, [props.scope.id]: next }));
    let defaultAuthority = defaultStorageKey();
    createEffect(() => {
        const nextAuthority = defaultStorageKey();
        if (nextAuthority === defaultAuthority) return;
        defaultAuthority = nextAuthority;
        setDefaultModel(localStorage.getItem(nextAuthority) ?? fallbackDefault());
    });
    const pickerModels = createMemo<readonly ModelPickerFixture[]>(() => local() ? [
        { key: "local:qwen3-coder", name: "qwen3-coder", connection: "Local endpoint" },
        { key: "local:deepseek-r1-14b", name: "deepseek-r1:14b", connection: "Local endpoint" },
    ] : organization() ? [
        ...organizationConnections().flatMap((connection): ModelPickerFixture[] => {
            if (connection.name.includes("Anthropic")) return [{ key: `org:${props.scope.id}:claude-sonnet-4.1`, name: "Claude Sonnet 4.1", connection: `${props.scope.label} · ${connection.name}` }];
            if (connection.name.includes("xAI")) return [{ key: `org:${props.scope.id}:grok-4.6`, name: "Grok 4.6", connection: `${props.scope.label} · ${connection.name}` }];
            if (connection.name.includes("OpenAI")) return [{ key: `org:${props.scope.id}:gpt-5.4`, name: "GPT-5.4", connection: `${props.scope.label} · ${connection.name}` }];
            return [];
        }),
        ...(planActive() ? [{ key: "managed:gpt-5.4-mini", name: "GPT-5.4 mini", connection: `${props.scope.label} · Managed inference` }] : []),
    ] : [
        { key: "codex:gpt-5.6", name: "GPT-5.6", connection: "OpenAI Codex" },
        { key: "codex:gpt-5.4", name: "GPT-5.4 (Codex)", connection: "OpenAI Codex" },
        { key: "openai:gpt-5.4", name: "GPT-5.4 (API)", connection: "OpenAI API" },
        { key: "xai-sub:grok-4.6", name: "Grok 4.6 (subscription)", connection: "xAI Grok" },
        { key: "xai:grok-4.6", name: "Grok 4.6 (API)", connection: "xAI API" },
        ...(planActive() ? [{ key: "managed:gpt-5.4-mini", name: "GPT-5.4 mini", connection: "Managed inference" }] : []),
        { key: "local:qwen3-coder", name: "qwen3-coder", connection: "Studio endpoint" },
    ]);
    const filteredModels = createMemo(() => {
        const query = modelFilter().trim().toLocaleLowerCase();
        return query ? pickerModels().filter((model) => `${model.name} ${model.connection}`.toLocaleLowerCase().includes(query)) : pickerModels();
    });
    const toggleModel = (key: string, enabled: boolean) => {
        setEnabledModels((current) => {
            const next = new Set(current);
            enabled ? next.add(key) : next.delete(key);
            return next;
        });
    };
    // Backend gap: /account/default-model currently reports the resolved default but
    // has no write route. The prototype keeps the intended account preference local.
    const chooseDefault = (model: ModelPickerFixture) => {
        setDefaultModel(model.key);
        setEnabledModels((current) => new Set(current).add(model.key));
        localStorage.setItem(defaultStorageKey(), model.key);
        setMessage(`${model.name} is now the default when an Agent or chat does not choose a model.`);
    };
    const activatePlan = () => setActivatedPlanScopes((current) => new Set(current).add(planAuthority()));
    const grants = () => grantOverrides()[props.scope.id] ?? initialModelAccessGrants(props.scope);
    const writeGrants = (next: readonly ModelAccessGrantFixture[]) => setGrantOverrides((current) => ({ ...current, [props.scope.id]: next }));
    const projectTargets = () => PROJECTS_BY_SCOPE[props.scope.id] ?? [];
    const memberTargets = ["Jack Scully", "Priya Shah", "Nora Chen"] as const;
    const openNewGrant = () => {
        setEditingGrantId(null);
        setGrantKind("project");
        setGrantTarget(projectTargets()[0]?.name ?? "");
        setGrantAccess("All organization connections");
        setGrantLimit("250");
        setGrantEditorOpen(true);
    };
    const openGrant = (grant: ModelAccessGrantFixture) => {
        setEditingGrantId(grant.id);
        setGrantKind(grant.kind);
        setGrantTarget(grant.target);
        setGrantAccess(grant.access);
        setGrantLimit(grant.monthlyLimit === null ? "" : String(grant.monthlyLimit));
        setGrantEditorOpen(true);
    };
    const saveGrant = () => {
        if (!grantTarget() || grantLimit().trim() === "") return;
        const parsedLimit = Math.max(0, Number(grantLimit()) || 0);
        const id = editingGrantId() ?? `${props.scope.id}:${grantKind()}:${Date.now()}`;
        const previous = grants().find((grant) => grant.id === id);
        const next: ModelAccessGrantFixture = {
            id, kind: grantKind(), target: grantTarget(), access: grantAccess(),
            used: previous?.used ?? 0, monthlyLimit: parsedLimit,
        };
        writeGrants(editingGrantId() ? grants().map((grant) => grant.id === id ? next : grant) : [...grants(), next]);
        setGrantEditorOpen(false);
        setMessage(`${grantTarget()} now has a $${parsedLimit.toLocaleString()} monthly organization-funded model usage cap.`);
    };
    const completeConnection = (provider: ModelConnectionProvider) => {
        const owner = addingFor();
        setAddingFor(null);
        if (owner === "organization") {
            const connection = {
                name: modelConnectionProviderName(provider),
                auth: provider === "openai-generic" ? "shared endpoint" : "shared API key",
            } satisfies OrganizationModelConnectionFixture;
            writeOrganizationConnections([...organizationConnections().filter((candidate) => candidate.name !== connection.name), connection]);
        }
        setMessage(owner === "organization"
            ? `${provider === "openai-generic" ? "The endpoint credential" : "The API key"} would be encrypted for ${props.scope.label} and become available only through its access grants.`
            : provider === "openai-codex" || provider === "xai-grok"
            ? `${provider === "xai-grok" ? "xAI account" : "OpenAI"} authorization would open in a separate browser flow.`
            : "The credential would be sealed and a new provider version would become active.");
    };
    // Backend/spec gap: ADR 0062 currently forbids organization-held credentials.
    // This reversible prototype instead treats them as server-custodied organization
    // secrets, usable only through explicit member/project grants with spend limits.
    return <>
        <Notice tone="neutral">{local()
            ? "Provider credentials and the default below are stored on this computer."
            : organization()
                ? `${props.scope.label} can hold shared API keys and managed inference. Owners and admins manage the secrets, provider access, and monthly usage caps for projects and people.`
                : "These provider sign-ins, API keys, and defaults belong to Jack Scully. Organization-owned connections are managed separately under Administration."}</Notice>
        <section class="admin-section gaugeapp-model-access-section">
            <Show when={addingFor()}>{(owner) => <div class="gaugeapp-model-add-card"><SectionHeading title={owner() === "organization" ? `Add ${props.scope.label} connection` : owner() === "computer" ? "Add connection on this computer" : "Add your connection"} />
                <ModelConnectionForm local={local()} owner={owner()} ownerLabel={owner() === "organization" ? props.scope.label : owner() === "computer" ? "this computer" : "Jack Scully"}
                    onCancel={() => setAddingFor(null)} onComplete={completeConnection} />
            </div>}</Show>
            <div class="gaugeapp-model-access-grid">
                <Show when={organization()}><div><SectionHeading title="Organization connections" meta={canManageOrganization() ? "shared · managed by owners and admins" : "shared · read only"}
                    action={canManageOrganization() && !addingFor() ? "add connection" : undefined} onAction={() => { setMessage(""); setAddingFor("organization"); }} />
                    <div class="gaugeapp-model-connection-columns" aria-hidden="true"><span>Provider</span><span>Owned by</span><span>Status</span><span /></div>
                    <For each={organizationConnections()} fallback={<p class="gaugeapp-model-empty-row">No shared connections yet.</p>}>
                        {(connection) => <ModelConnectionRow name={connection.name} auth={connection.auth} owner={props.scope.label}
                            action={canManageOrganization() ? "replace" : undefined} secondaryAction={canManageOrganization() ? "remove" : undefined}
                            onAction={() => setMessage(`A replacement ${connection.name} credential would become active without exposing either secret.`)}
                            onSecondaryAction={() => { writeOrganizationConnections(organizationConnections().filter((candidate) => candidate.name !== connection.name)); setMessage(`${connection.name} was removed; any allowance that depended on it would stop authorizing new runs.`); }} />}
                    </For>
                </div></Show>

                <Show when={organization()}><div><SectionHeading title="Usage caps" meta={`${grants().length} cap${grants().length === 1 ? "" : "s"}`}
                    action={canManageOrganization() && !grantEditorOpen() ? "set usage cap" : undefined} onAction={openNewGrant} />
                    <p class="gaugeapp-model-section-note">Set monthly organization-funded model spending by project or person. Project caps cover everyone using models in that project; person caps follow the user across organization projects. When both apply, both must have room.</p>
                    <div class="gaugeapp-model-grant-columns" aria-hidden="true"><span>Project or person</span><span>Provider access</span><span>Used this month</span><span>Monthly cap</span><span /></div>
                    <For each={grants()} fallback={<p class="gaugeapp-model-empty-row">No usage caps have been assigned.</p>}>
                        {(grant) => <ModelAccessGrantRow grant={grant} editable={canManageOrganization()} onEdit={() => openGrant(grant)}
                            onRemove={() => { writeGrants(grants().filter((candidate) => candidate.id !== grant.id)); setMessage(`${grant.target} no longer has an organization-funded model usage cap.`); }} />}
                    </For>
                    <Show when={grantEditorOpen()}><div class="gaugeapp-model-grant-editor">
                        <label>Cap applies to<select value={grantKind()} onChange={(event) => {
                            const kind = event.currentTarget.value as "project" | "member";
                            setGrantKind(kind); setGrantTarget(kind === "project" ? projectTargets()[0]?.name ?? "" : memberTargets[0]);
                        }}><option value="project">Project</option><option value="member">Person</option></select></label>
                        <label>{grantKind() === "project" ? "Project" : "Person"}<select value={grantTarget()} onChange={(event) => setGrantTarget(event.currentTarget.value)}>
                            <Show when={grantKind() === "project"} fallback={<For each={memberTargets}>{(member) => <option>{member}</option>}</For>}>
                                <For each={projectTargets()}>{(project) => <option>{project.name}</option>}</For>
                            </Show>
                        </select></label>
                        <label>Provider access<select value={grantAccess()} onChange={(event) => setGrantAccess(event.currentTarget.value)}><option>All organization connections</option><option>OpenAI API only</option><option>Anthropic only</option><option>Managed inference only</option></select></label>
                        <label>Monthly cap ($)<input type="number" min="0" step="10" required value={grantLimit()} placeholder="250" onInput={(event) => setGrantLimit(event.currentTarget.value)} /></label>
                        <span class="gaugeapp-row-actions"><button type="button" class="tree-action" onClick={() => setGrantEditorOpen(false)}>cancel</button><button type="button" onClick={saveGrant}>save cap</button></span>
                    </div></Show>
                </div></Show>

                <Show when={!organization()}><div><SectionHeading title={local() ? "Connections on this computer" : "Your connections"} action={addingFor() ? undefined : "add connection"} onAction={() => { setMessage(""); setAddingFor(local() ? "computer" : "personal"); }} />
                    <div class="gaugeapp-model-connection-columns" aria-hidden="true"><span>Provider</span><span>Owned by</span><span>Status</span><span /></div>
                    <Show when={local()} fallback={<>
                        <ModelConnectionRow name="OpenAI Codex" auth="account sign-in" owner="Jack Scully" action="reauthorize" onAction={() => setMessage("OpenAI reauthorization would open separately.")} />
                        <ModelConnectionRow name="xAI Grok" auth="account sign-in" owner="Jack Scully" action="reauthorize" onAction={() => setMessage("xAI account authorization would open separately.")} />
                        <ModelConnectionRow name="OpenAI API" auth="API key · v2" owner="Jack Scully" action="replace" secondaryAction="remove" onAction={() => setMessage("A replacement OpenAI key would create credential version 3.")} onSecondaryAction={() => setMessage("Removing OpenAI API would make its picker entries unavailable.")} />
                        <ModelConnectionRow name="xAI API" auth="API key · v1" owner="Jack Scully" action="replace" secondaryAction="remove" onAction={() => setMessage("A replacement xAI key would create credential version 2.")} onSecondaryAction={() => setMessage("Removing the xAI API key would leave the subscription connection available.")} />
                        <ModelConnectionRow name="Studio endpoint" auth="local endpoint" owner="This computer" action="models" secondaryAction="remove" onAction={() => setEditingModels(true)} onSecondaryAction={() => setConfirmingRemove(true)} />
                    </>}>
                        <ModelConnectionRow name="Local endpoint" auth="local endpoint" owner="This computer" action="models" secondaryAction="remove" onAction={() => setEditingModels(true)} onSecondaryAction={() => setConfirmingRemove(true)} />
                        <ModelConnectionRow name="OpenAI Codex" auth="account sign-in" owner="—" status="not connected" action="connect" onAction={() => completeConnection("openai-codex")} />
                        <ModelConnectionRow name="xAI Grok" auth="account sign-in" owner="—" status="not connected" action="connect" onAction={() => completeConnection("xai-grok")} />
                    </Show>
                    <Show when={editingModels()}><div class="gaugeapp-model-inline-editor"><label>Model IDs<textarea>qwen3-coder{`\n`}deepseek-r1:14b</textarea></label><span class="gaugeapp-row-actions"><button type="button" class="tree-action" onClick={() => setEditingModels(false)}>cancel</button><button type="button" onClick={() => { setEditingModels(false); setMessage("Endpoint model list updated."); }}>save models</button></span></div></Show>
                    <Show when={confirmingRemove()}><div class="gaugeapp-model-remove-confirm"><span><strong>Remove the endpoint?</strong><small>Its models disappear from the picker; existing chats retain their pinned provider and model.</small></span><span class="gaugeapp-row-actions"><button type="button" class="tree-action" onClick={() => setConfirmingRemove(false)}>cancel</button><button type="button" class="tree-action gaugeapp-danger-action" onClick={() => { setConfirmingRemove(false); setMessage("Endpoint removed from this prototype account."); }}>remove</button></span></div></Show>
                </div></Show>
                <div><SectionHeading title={organization() ? "Approved models" : "Models"} meta={`${pickerModels().length} available`} />
                    <div class="gaugeapp-model-picker-toolbar"><input type="search" value={modelFilter()} aria-label="Filter models"
                        placeholder="Filter models" onInput={(event) => setModelFilter(event.currentTarget.value)} /></div>
                    <div class="gaugeapp-model-picker-columns" aria-hidden="true"><span>Show</span><span>Model</span><span>Connection</span><span>Default</span></div>
                    <div class="gaugeapp-model-picker-list">
                        <For each={filteredModels()} fallback={<p class="gaugeapp-model-picker-empty">No matching models.</p>}>
                            {(model) => <ModelPickerRow model={model} enabled={enabledModels().has(model.key)} isDefault={defaultModel() === model.key}
                                defaultOwner={organization() ? "organization" : "account"}
                                onEnabled={(enabled) => toggleModel(model.key, enabled)} onDefault={() => chooseDefault(model)} />}
                        </For>
                    </div>
                </div>
            </div>
            <Show when={settingUpPlan()}><ManagedInferenceSignup onCancel={() => setSettingUpPlan(false)} onActivate={() => {
                activatePlan(); setSettingUpPlan(false); setMessage("Managed inference is active. Managed models are now available in the picker.");
            }} /></Show>
            <Show when={!local()}><Show when={planActive()} fallback={<div class="gaugeapp-model-plan-row" data-state="available">
                <span><strong>Managed inference</strong><small>{organization() ? "Not included with this Base organization" : "No personal plan set up · hosted models are unavailable"}</small></span>
                <span class="badge">not active</span>
                <button type="button" class="tree-action" onClick={() => organization()
                    ? interact({ action: "open plans and services", title: "Managed organization" })
                    : setSettingUpPlan(true)}>{organization() ? "review upgrade" : "set up plan"}</button>
            </div>}><div class="gaugeapp-model-plan-row">
                <span><strong>{organization() ? `${props.scope.label} model plan · Team` : "Personal model plan · Individual"}</strong>
                    <small>{organization() ? "2.4M of 5M included tokens used this month" : "18,420 of 100,000 included tokens used"}</small></span>
                <div class="gaugeapp-model-plan-usage" aria-label={organization() ? "48 percent used" : "18 percent used"}><span style={{ width: organization() ? "48%" : "18%" }} /></div>
                <span class="badge">active</span>
                <Show when={!organization() || props.scope.organizationRole !== "member"}>
                    <button type="button" class="tree-action" onClick={() => interact({ action: organization() ? "open plans and services" : "open billing", title: organization() ? `${props.scope.label} model plan` : "Personal model plan" })}>manage plan</button>
                </Show>
            </div></Show></Show>
        </section>
        <Show when={message()}><p class="status" role="status">{message()}</p></Show>
    </>;
}

interface TrustedDeviceFixture {
    readonly id: string;
    readonly label: string;
    readonly trustedSince: string;
    readonly form: "computer" | "phone" | "tablet";
    readonly activity: string;
    readonly routeSummary: string;
    readonly status: "active" | "revoked";
    readonly current?: boolean;
}

const TRUST_INVITES = [
    { device: "device:7r4mkq", code: "7R4M KQ2D", comparison: "482 719" },
    { device: "device:9x6pw3", code: "9X6P W3FA", comparison: "315 804" },
] as const;

function trustedDeviceFixtures(scope: ScopeFixture): readonly TrustedDeviceFixture[] {
    if (scope.kind === "signed-out-local") return [{
        id: "local-desktop", label: "GaugeDesk on jack-linux", trustedSince: "Local identity · created Aug 21", form: "computer",
        activity: "Active now", routeSummary: "2 local project Homes", status: "active", current: true,
    }];
    return [
        { id: "native-jack-linux", label: "GaugeDesk on jack-linux", trustedSince: "Trusted Aug 21", form: "computer", activity: "Active now", routeSummary: "2 project routes", status: "active", current: true },
        { id: "mobile-jack-iphone", label: "Jack’s iPhone", trustedSince: "Trusted Aug 14", form: "phone", activity: "Active 8 minutes ago", routeSummary: "2 project routes", status: "active" },
        { id: "mobile-travel-ipad", label: "Travel iPad", trustedSince: "Trusted Jun 2", form: "tablet", activity: "Trust revoked Jul 18", routeSummary: "No routes", status: "revoked" },
    ];
}

function TrustedDeviceRow(props: {
    device: TrustedDeviceFixture;
    onManage: () => void;
}): JSX.Element {
    return <div class="gaugeapp-device-row" data-status={props.device.status}>
        <span class="gaugeapp-device-kind" aria-hidden="true">{props.device.form === "phone" ? "▯" : props.device.form === "tablet" ? "▭" : "□"}</span>
        <span class="gaugeapp-device-identity"><span class="gaugeapp-device-title-line"><strong>{props.device.label}</strong><span class="badge">{props.device.current ? "this device" : props.device.status}</span></span><small>{props.device.trustedSince} · {props.device.activity}</small></span>
        <span class="gaugeapp-device-route"><small>Access</small>{props.device.routeSummary}</span>
        <span class="gaugeapp-row-actions"><button type="button" class="tree-action" onClick={props.onManage}>{props.device.status === "revoked" ? "view history" : "manage"}</button></span>
    </div>;
}

function TrustedDeviceEnrollmentCard(props: { local: boolean; onClose: () => void; onTrust: (type: "phone" | "computer") => void; onMessage: (message: string) => void }): JSX.Element {
    const [copied, setCopied] = createSignal(false);
    const [deviceType, setDeviceType] = createSignal<"phone" | "computer">("phone");
    const [stage, setStage] = createSignal<"invite" | "approve">("invite");
    const [inviteIndex, setInviteIndex] = createSignal(0);
    const invite = () => TRUST_INVITES[inviteIndex()];
    const ticket = () => pairingTicket(props.local ? "local" : "account", invite().device);
    const copyTicket = async () => {
        try {
            await navigator.clipboard.writeText(ticket());
            setCopied(true);
            props.onMessage("Pairing code copied.");
        } catch {
            props.onMessage("Copy was unavailable. Enter the code shown in GaugeDesk on the new device.");
        }
    };
    const newInvite = () => {
        setInviteIndex((current) => (current + 1) % TRUST_INVITES.length);
        setCopied(false);
        setStage("invite");
        props.onMessage("A new one-time pairing invitation is ready.");
    };
    return <div class="gaugeapp-device-enrollment" aria-label="Trust a device">
        <div class="gaugeapp-device-enrollment-head"><span><strong>Link another device</strong><small>On the new GaugeDesk client, choose <em>Link existing account</em>. Normal web sign-in creates a browser session; it does not trust a device.</small></span><button type="button" class="tree-action" onClick={props.onClose}>close</button></div>
        <div class="gaugeapp-device-type-choices" role="group" aria-label="Device type">
            <button type="button" classList={{ active: deviceType() === "phone" }} onClick={() => { setDeviceType("phone"); setStage("invite"); }}><strong>Phone or tablet</strong><small>Scan with GaugeDesk mobile or enter the code.</small></button>
            <button type="button" classList={{ active: deviceType() === "computer" }} onClick={() => { setDeviceType("computer"); setStage("invite"); }}><strong>Another computer</strong><small>Open GaugeDesk desktop and enter the code.</small></button>
        </div>
        <Show when={stage() === "invite"} fallback={<div class="gaugeapp-pairing-approval">
            <div class="gaugeapp-pairing-request"><span class="gaugeapp-device-kind" aria-hidden="true">{deviceType() === "phone" ? "▯" : "□"}</span><span><strong>{deviceType() === "phone" ? "New phone or tablet" : "New computer"}</strong><small>Pairing request received · device key verified</small></span></div>
            <div class="gaugeapp-pairing-compare"><span><strong>Compare on both devices</strong><small>Approve only if this number is identical on the new device.</small></span><code class="gaugeapp-sas-code">{invite().comparison}</code></div>
            <div class="gaugeapp-device-enrollment-actions"><button type="button" class="tree-action" onClick={() => { props.onMessage("Pairing denied; no Trusted Device was added."); props.onClose(); }}>deny</button><button type="button" onClick={() => props.onTrust(deviceType())}>codes match — link device</button></div>
        </div>}>
            <div class="gaugeapp-pairing-invite">
                <div class="gaugeapp-pairing-qr"><div aria-label="Scannable device pairing code" innerHTML={qrSvg(ticket(), 4)} /><small>one use · expires in 3 minutes</small></div>
                <div class="gaugeapp-pairing-instructions"><span><strong>{deviceType() === "phone" ? "Scan with the new device" : "Enter the code on the new computer"}</strong><small>The new device creates its own key, then asks this trusted device for approval.</small></span>
                    <div class="gaugeapp-enrollment-ticket"><code>{invite().code}</code><button type="button" class="tree-action" onClick={() => void copyTicket()}>{copied() ? "copied" : "copy code"}</button></div>
                    <div class="gaugeapp-device-enrollment-actions"><button type="button" class="tree-action" onClick={newInvite}>new code</button><button type="button" onClick={() => setStage("approve")}>check for request</button></div>
                </div>
            </div>
        </Show>
    </div>;
}

function TrustedDevicesPanel(props: { scope: ScopeFixture }): JSX.Element {
    const [enrolling, setEnrolling] = createSignal(false);
    const [message, setMessage] = createSignal("");
    const [addedDevice, setAddedDevice] = createSignal<TrustedDeviceFixture | null>(null);
    const interact = useContext(InteractionContext);
    const devices = createMemo(() => {
        const base = trustedDeviceFixtures(props.scope);
        return addedDevice() ? [...base, addedDevice()!] : base;
    });
    const activeCount = createMemo(() => devices().filter((device) => device.status === "active").length);
    const revokedCount = createMemo(() => devices().filter((device) => device.status === "revoked").length);
    const trustDevice = (form: "phone" | "computer") => {
        setAddedDevice({ id: "trusted-new-device", label: form === "phone" ? "New phone" : "New computer", trustedSince: "Trusted today", form, activity: "Active now", routeSummary: "Routes discovering", status: "active" });
        setEnrolling(false);
        setMessage("Trusted Device added. It can now discover your memberships and request access from each project Home.");
    };
    return <>
        <Notice tone="neutral"><strong>Trusted Devices are account clients, not Project Hosts.</strong> They act as you, discover opaque project routes, and ask each project Home for access. Project data remains on its Project Host.</Notice>
        <section class="admin-section gaugeapp-devices-section">
            <SectionHeading title="Trusted Devices"
                meta={`${activeCount()} active${revokedCount() ? ` · ${revokedCount()} revoked` : ""}`} action={enrolling() ? undefined : "link device"} onAction={() => { setMessage(""); setEnrolling(true); }} />
            <Show when={enrolling()}><TrustedDeviceEnrollmentCard local={props.scope.kind === "signed-out-local"} onClose={() => setEnrolling(false)} onTrust={trustDevice} onMessage={setMessage} /></Show>
            <div class="gaugeapp-device-list">
                <For each={devices()}>{(device) => <TrustedDeviceRow device={device} onManage={() => interact({
                    action: device.status === "revoked" ? "view Trusted Device history" : "manage Trusted Device", title: device.label,
                    description: `${device.trustedSince} · ${device.activity} · ${device.routeSummary}`, kind: device.form, meta: device.status,
                })} />}</For>
            </div>
            <Show when={activeCount() === 1}><p class="gaugeapp-field-note">Trust another device before revoking the only active identity holder.</p></Show>
        </section>
        <section class="admin-section"><SectionHeading title="Desk on the web" />
            <Definition label="Browser access" value="Sign in at desk.gaugewright.com" note="A browser creates an account session; it is neither a Trusted Device nor a Project Host and receives no project copy." />
            <Definition label="Session control" value="Account Settings" note="Review and sign out browser sessions there." />
        </section>
        <Show when={message()}><p class="status" role="status">{message()}</p></Show>
    </>;
}

function ApplicationSettingsPanel(): JSX.Element {
    const [questionAttention, setQuestionAttention] = createSignal("Task bar");
    const [conflictAttention, setConflictAttention] = createSignal("Task bar");
    const [reviewAttention, setReviewAttention] = createSignal("Task bar");
    const [replyAttention, setReplyAttention] = createSignal("Quiet");
    const [paths, setPaths] = createSignal(["docs/**", "tests/fixtures/**"]);
    const [newPath, setNewPath] = createSignal("");
    const report = useContext(ActionFeedbackContext);
    return <>
        <section class="admin-section"><SectionHeading title="Attention" action="restore defaults" onAction={() => { setQuestionAttention("Task bar"); setConflictAttention("Task bar"); setReviewAttention("Task bar"); setReplyAttention("Quiet"); report("Application attention settings were restored to their prototype defaults."); }} />
            <AttentionRow label="The agent asks you a question" value={questionAttention()} onValue={setQuestionAttention} />
            <AttentionRow label="A merge conflicts" value={conflictAttention()} onValue={setConflictAttention} />
            <AttentionRow label="Changes wait for your review" value={reviewAttention()} onValue={setReviewAttention} />
            <AttentionRow label="The agent finishes any reply" value={replyAttention()} onValue={setReplyAttention} />
        </section>
        <section class="admin-section"><SectionHeading title="Keep automatically" action="clear all" onAction={() => { setPaths([]); report("All automatic keep paths were removed."); }} />
            <p class="gaugeapp-section-intro">Changes in these paths can be kept without asking.</p>
            <div class="gaugeapp-chips"><For each={paths()}>{(path) => <span>{path} <button type="button" aria-label={`Remove ${path}`} onClick={() => setPaths((current) => current.filter((candidate) => candidate !== path))}>×</button></span>}</For></div>
            <div class="gaugeapp-inline-form"><label>Workspace path pattern<input value={newPath()} onInput={(event) => setNewPath(event.currentTarget.value)} placeholder="packages/example/**" /></label><button type="button" disabled={!newPath().trim()} onClick={() => { setPaths((current) => [...current, newPath().trim()]); setNewPath(""); }}>add path</button></div>
        </section>
    </>;
}

function DashboardGrid(props: { children: JSX.Element; surface?: boolean }): JSX.Element {
    return <div class="gaugeapp-dashboard-grid" classList={{ "gaugeapp-guide-surface": props.surface }}>{props.children}</div>;
}
function PageHeader(props: { eyebrow: string; title: string; description: string; actions?: JSX.Element }): JSX.Element {
    return <header class="gaugeapp-page-header"><div><span class="gaugeapp-eyebrow">{props.eyebrow}</span><h1>{props.title}</h1><p>{props.description}</p></div><Show when={props.actions}><div class="gaugeapp-page-actions">{props.actions}</div></Show></header>;
}
function SectionHeading(props: { title: string; meta?: string; action?: string; onAction?: () => void }): JSX.Element {
    const interact = useContext(InteractionContext);
    const run = () => props.onAction ? props.onAction() : interact({ action: props.action!, title: props.title, meta: props.meta });
    return <div class="gaugeapp-section-heading"><div><h4>{props.title}</h4><Show when={props.meta}><span>{props.meta}</span></Show></div><Show when={props.action}><button class="tree-action" type="button" onClick={run}>{props.action}</button></Show></div>;
}
function Notice(props: { tone: "neutral" | "warn"; children: JSX.Element }): JSX.Element {
    return <div class="gaugeapp-notice" data-tone={props.tone}>{props.children}</div>;
}
function Metric(props: { label: string; value: string; note: string; tone?: "warn" }): JSX.Element {
    return <div class="gaugeapp-metric" data-tone={props.tone ?? "neutral"}><span>{props.label}</span><strong>{props.value}</strong><small>{props.note}</small></div>;
}
function Definition(props: { label: string; value: string; note?: string; actions?: readonly DetailCommand[]; onAction?: (action: DetailCommand) => void }): JSX.Element {
    return <div class="resource-row gaugeapp-definition"><span class="resource-kind">{props.label}</span><span class="resource-title">{props.value}<Show when={props.note}><small>{props.note}</small></Show></span>
        <Show when={props.actions?.length}><span class="gaugeapp-row-actions"><For each={props.actions}>{(action) => <button type="button" class="tree-action"
            classList={{ "gaugeapp-danger-action": action.danger }} onClick={() => props.onAction?.(action)}>{contextualActionLabel(action.label)}</button>}</For></span></Show></div>;
}
function contextualActionLabel(action: string): string {
    const normalized = action.toLowerCase();
    if (normalized === "inspect" || normalized === "recovery instructions" || normalized.startsWith("view ") || normalized.startsWith("open ")) return "view";
    if (normalized === "project settings" || normalized === "open project settings") return "settings";
    if (normalized.startsWith("manage ")) return "manage";
    if (normalized.startsWith("edit ")) return "edit";
    if (normalized.startsWith("revoke ")) return "revoke";
    if (normalized === "download pdf") return "download";
    return action;
}
function Resource(props: { kind: string; title: string; detail: string; tone: "ready" | "warn" | "neutral"; client?: boolean; titleFirst?: boolean; action?: string; actionLabel?: string; secondaryAction?: string; secondaryActionLabel?: string; onAction?: () => void; onSecondaryAction?: () => void }): JSX.Element {
    const interact = useContext(InteractionContext);
    const run = () => props.onAction ? props.onAction() : interact({ action: props.action!, title: props.title, description: props.detail, kind: props.kind });
    const runSecondary = () => props.onSecondaryAction ? props.onSecondaryAction() : interact({ action: props.secondaryAction!, title: props.title, description: props.detail, kind: props.kind });
    return <div class="resource-row gaugeapp-resource gaugeapp-ledger-resource" classList={{ "gaugeapp-client-resource": props.client }} data-tone={props.tone}>
        <span class="gaugeapp-ledger-identity"><span class="resource-title">{props.title}</span><span class="resource-kind">{props.kind}</span><small>{props.detail}</small></span>
        <Show when={props.action || props.secondaryAction}><span class="gaugeapp-row-actions"><Show when={props.action}><button class="tree-action" type="button" onClick={run}>{props.actionLabel ?? contextualActionLabel(props.action!)}</button></Show><Show when={props.secondaryAction}><button class="tree-action" type="button" onClick={runSecondary}>{props.secondaryActionLabel ?? contextualActionLabel(props.secondaryAction!)}</button></Show></span></Show></div>;
}
function ProjectAccessRow(props: { name: string; email: string; role: string; access: string; source: string; action?: string; danger?: boolean }): JSX.Element {
    const interact = useContext(InteractionContext);
    return <div class="gaugeapp-project-access-row">
        <span class="gaugeapp-avatar">{props.name.split(" ").map((part) => part[0]).join("")}</span>
        <span><strong>{props.name}</strong><small>{props.email}</small></span>
        <span><small>Access</small>{props.access}</span>
        <span><small>Source</small>{props.source}</span>
        <Show when={props.action}><button type="button" class="tree-action" classList={{ "gaugeapp-danger-action": props.danger }}
            onClick={() => interact({ action: props.action!, title: props.name, description: `${props.email} · ${props.access}`, kind: props.source, meta: props.role })}>{contextualActionLabel(props.action!)}</button></Show>
    </div>;
}
function ProjectGovernanceRow(props: { project: ProjectFixture; facts: ProjectGovernanceFixture }): JSX.Element {
    const interact = useContext(InteractionContext);
    const target = (action: string): InteractionTarget => ({
        action,
        title: props.project.name,
        description: `${props.project.detail} · ${props.facts.people} people · ${props.facts.agents} Agent placements`,
        kind: props.project.id,
        meta: props.facts.state,
    });
    return <div class="gaugeapp-project-governance-row" data-tone={props.facts.state === "attention" ? "warn" : "ready"}>
        <span><strong>{props.project.name}</strong><small>proj_{props.project.id} · active {props.facts.activity}</small></span>
        <span><small>Authoritative Home</small>{props.project.detail}</span>
        <span><small>People</small>{props.facts.people} reachable · {props.facts.explicitGrants} explicit</span>
        <span><small>Agents & work</small>{props.facts.agents} Agents · {props.facts.targets} targets</span>
        <span class="badge" classList={{ "badge-warn": props.facts.state === "attention" }}>{props.facts.state}</span>
        <span class="gaugeapp-row-actions"><button class="tree-action" type="button" onClick={() => interact(target("inspect"))}>view</button>
            <button class="tree-action" type="button" onClick={() => interact(target("open project settings"))}>settings</button></span>
    </div>;
}
function TargetAccessRow(props: { kind: string; title: string; scope: string; acts: readonly string[]; detail: string; action: string }): JSX.Element {
    const interact = useContext(InteractionContext);
    return <div class="gaugeapp-target-access-row">
        <span class="gaugeapp-record-identity"><span><strong>{props.title}</strong><span class="resource-kind">{props.kind}</span></span><small>{props.detail}</small></span>
        <span><small>Path scope</small><code>{props.scope}</code></span>
        <span class="gaugeapp-act-list"><For each={props.acts}>{(act) => <span>{act}</span>}</For></span>
        <button type="button" class="tree-action" onClick={() => interact({ action: props.action, title: props.title, description: `${props.detail} · ${props.acts.join(", ")}`, kind: props.kind, meta: props.scope })}>{contextualActionLabel(props.action)}</button>
    </div>;
}
function PlacementAccessRow(props: { kind: string; title: string; state: string; version: string; authority: string; action: string; secondaryAction?: string; warn?: boolean }): JSX.Element {
    const interact = useContext(InteractionContext);
    const target = (action: string): InteractionTarget => ({ action, title: props.title, description: `${props.authority} · ${props.version}`, kind: props.kind, meta: props.state });
    return <div class="gaugeapp-placement-access-row" data-tone={props.warn ? "warn" : "ready"}>
        <span class="gaugeapp-record-identity"><span><strong>{props.title}</strong><span class="resource-kind">{props.kind}</span></span><small>{props.authority}</small></span>
        <span class="badge" classList={{ "badge-warn": props.warn }}>{props.state}</span>
        <span><small>Version</small>{props.version}</span>
        <span class="gaugeapp-row-actions"><button type="button" class="tree-action" onClick={() => interact(target(props.action))}>{contextualActionLabel(props.action)}</button>
            <Show when={props.secondaryAction}><button type="button" class="tree-action" onClick={() => interact(target(props.secondaryAction!))}>{contextualActionLabel(props.secondaryAction!)}</button></Show></span>
    </div>;
}
function AgentProductCard(props: { agent: AgentProductFixture }): JSX.Element {
    const interact = useContext(InteractionContext);
    const target = (action: string): InteractionTarget => ({ action, title: props.agent.name, description: props.agent.summary, kind: props.agent.kind, meta: props.agent.agreements });
    return <article class="gaugeapp-catalog-card">
        <div class="gaugeapp-catalog-card-head"><span class="gaugeapp-catalog-card-title"><h3>{props.agent.name}</h3><small>{props.agent.kind}</small></span>
            <span class="gaugeapp-row-actions"><button class="tree-action" type="button" onClick={() => interact(target("view product"))}>view</button><button class="tree-action" type="button" onClick={() => interact(target("edit product"))}>edit</button></span></div>
        <p>{props.agent.summary}</p>
        <dl><div><dt>Price</dt><dd>{props.agent.pricing}</dd></div><div><dt>Delivery</dt><dd>{props.agent.delivery}</dd></div></dl>
        <div class="gaugeapp-catalog-card-foot"><span>{props.agent.agreements}</span></div>
    </article>;
}

function ManagedEngagementRow(props: {
    kind: "offer" | "agreement";
    reference?: string;
    agent: string;
    client: string;
    stage: string;
    commercial: string;
    fulfillment: string;
    nextAction: string;
    attention?: boolean;
    closed?: boolean;
}): JSX.Element {
    const interact = useContext(InteractionContext);
    const target = (action: string): InteractionTarget => ({
        action, title: `${props.agent} · ${props.client}`, description: props.commercial,
        kind: props.kind, meta: `${props.reference ?? "proposal"} · ${props.stage}${props.closed ? " · closed" : ""}`,
    });
    return <div class="gaugeapp-managed-engagement-row" data-tone={props.attention ? "warn" : "neutral"}>
        <span class="gaugeapp-engagement-identity"><strong>{props.agent}</strong><small>{props.client}{props.reference ? ` · ${props.reference}` : " · proposal"}</small></span>
        <div class="gaugeapp-engagement-facts"><span><small>Commercial terms</small>{props.commercial}</span>
            <span><small>Deployment & access</small>{props.fulfillment}</span></div>
        <span class="gaugeapp-engagement-controls"><span class="badge" classList={{ "badge-warn": props.attention }}>{props.stage}</span>
            <button class="tree-action" type="button" onClick={() => interact(target(props.nextAction))}>{props.nextAction === "edit proposal" ? "edit" : "view"}</button></span>
    </div>;
}
function MemberRow(props: { name: string; email: string; role: string; detail: string; pending?: boolean; action?: string; secondaryAction?: string }): JSX.Element {
    const report = useContext(ActionFeedbackContext);
    const interact = useContext(InteractionContext);
    const target = (action: string): InteractionTarget => ({ action, title: props.name, description: `${props.email} · ${props.detail}`, kind: props.role, meta: props.pending ? "pending" : "active" });
    return <div class="gaugeapp-member-row"><span class="gaugeapp-avatar">{props.name.split(" ").map((part) => part[0]).join("")}</span><span><strong>{props.name}</strong><small>{props.email} · {props.detail}</small></span><select aria-label={`${props.name} role`} disabled={props.role === "owner"} title={props.role === "owner" ? "Transfer ownership from Organization" : undefined} onChange={(event) => report(`Prototype: ${props.name}'s role would change to ${event.currentTarget.value}.`)}><option selected>{props.role}</option><option>admin</option><option>member</option></select><span class="badge" classList={{ "badge-warn": props.pending }}>{props.pending ? "pending" : "active"}</span><Show when={props.action || props.secondaryAction}><span class="gaugeapp-row-actions"><Show when={props.action}><button class="tree-action" type="button" onClick={() => interact(target(props.action!))}>{contextualActionLabel(props.action!)}</button></Show><Show when={props.secondaryAction}><button class="tree-action" type="button" onClick={() => interact(target(props.secondaryAction!))}>{contextualActionLabel(props.secondaryAction!)}</button></Show></span></Show></div>;
}
function SettingsRow(props: { title: string; note: string; meta: string; action?: string; secondaryAction?: string; onAction?: () => void; onSecondaryAction?: () => void }): JSX.Element {
    const interact = useContext(InteractionContext);
    const run = () => props.onAction ? props.onAction() : interact({ action: props.action!, title: props.title, description: props.note, meta: props.meta });
    const runSecondary = () => props.onSecondaryAction ? props.onSecondaryAction() : interact({ action: props.secondaryAction!, title: props.title, description: props.note, meta: props.meta });
    return <div class="gaugeapp-settings-row"><span><strong>{props.title}</strong><small>{props.note}</small></span><span class="badge">{props.meta}</span><Show when={props.action || props.secondaryAction}><span class="gaugeapp-row-actions"><Show when={props.action}><button class="tree-action" type="button" onClick={run}>{contextualActionLabel(props.action!)}</button></Show><Show when={props.secondaryAction}><button class="tree-action" type="button" onClick={runSecondary}>{contextualActionLabel(props.secondaryAction!)}</button></Show></span></Show></div>;
}
function ConnectSettingRow(props: { title: string; note: string; status: string; action: string }): JSX.Element {
    const interact = useContext(InteractionContext);
    const label = () => props.action === "view documents" ? "view" : props.action === "open Stripe support" ? "support" : "manage";
    return <div class="gaugeapp-connect-row"><span><span><strong>{props.title}</strong><span class="badge">{props.status}</span></span><small>{props.note}</small></span>
        <button class="tree-action" type="button" onClick={() => interact({ action: props.action, title: props.title, description: props.note, kind: "Stripe Connect" })}>{label()}</button></div>;
}
function AttentionRow(props: { label: string; value: string; onValue: (value: string) => void }): JSX.Element {
    return <div class="gaugeapp-policy-row"><span><strong>{props.label}</strong><small>Choose Task bar, Chat dot, or Quiet.</small></span><select aria-label={props.label} value={props.value} onChange={(event) => props.onValue(event.currentTarget.value)}><option>Task bar</option><option>Chat dot</option><option>Quiet</option></select></div>;
}
