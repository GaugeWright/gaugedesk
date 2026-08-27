declare const brand: unique symbol;
type Brand<T, B> = T & { readonly [brand]: B };

export type ScopeId = Brand<string, "ScopeId">;
export type EngagementId = Brand<string, "EngagementId">;
/** An **archetype** — the reusable method (ADR 0035; the old "agent definition"). */
export type ArchetypeId = Brand<string, "ArchetypeId">;
export type ProjectId = Brand<string, "ProjectId">;
export type HomeId = Brand<string, "HomeId">;
/** A **placement** — an archetype installed on a project (ADR 0035; the old
 *  "using instance"). Identity is `archetype · project`. */
export type PlacementId = Brand<string, "PlacementId">;
/** Immutable workspace identity shared by a chat and every line it may join. For a
 * work chat this is its placement instance; for an edit chat it is the archetype's
 * authoring instance. */
export type WorkspaceRootId = Brand<string, "WorkspaceRootId">;
/** A **workstream** — a named shared auto-sync line within a placement (WS-F). The
 *  UI keys and compares on this id (membership, join/leave), so it is branded like
 *  the other domain ids rather than left a bare `string`. */
export type WorkstreamId = Brand<string, "WorkstreamId">;
/** The independently-authoritative repository/folder/managed body a chat changes. */
export type WorkTargetId = Brand<string, "WorkTargetId">;

export function scopeId(raw: string): ScopeId {
    if (!raw) throw new Error("empty ScopeId");
    return raw as ScopeId;
}
export function engagementId(raw: string): EngagementId {
    if (!raw) throw new Error("empty EngagementId");
    return raw as EngagementId;
}
export function workstreamId(raw: string): WorkstreamId {
    if (!raw) throw new Error("empty WorkstreamId");
    return raw as WorkstreamId;
}
export function workTargetId(raw: string): WorkTargetId {
    if (!raw) throw new Error("empty WorkTargetId");
    return raw as WorkTargetId;
}

// ----- The library facet tree (ADR 0035/0036 data model) -----

/** A chat's **kind** is its ROOT (ADR 0035), fixed at creation, never toggled:
 *  rooted on an archetype ⇒ `edit` (improve the method); rooted on a placement ⇒
 *  `work` (do the job). This replaces the old `use`/`edit` ChatMode toggle. */
export type ChatKind = "edit" | "work";
export type WorkTargetKind = "managed" | "external-vcs" | "external-folder";
export type TargetVcsPosture = "managed" | "external-vcs" | "unversioned";
export type WorkTargetStatus = "available" | "unavailable" | "retired";
export type TargetActKind = "read" | "propose" | "apply" | "publish" | "release";
export type TargetConcurrency = "serialized" | "native-vcs" | "compare-before-write-weak";

export interface TargetCapabilities {
    readonly read: boolean;
    readonly propose: boolean;
    readonly apply: boolean;
    readonly publish: boolean;
    readonly release: boolean;
}

/** Locator-free projection of a work-target record. Raw machine paths,
 * credentials, and local storage ids never cross this client boundary. */
export interface WorkTargetNode {
    readonly id: WorkTargetId;
    readonly name: string;
    readonly ownerKind: "project" | "archetype";
    readonly ownerId: string;
    readonly authority: string;
    readonly parties: readonly string[];
    readonly kind: WorkTargetKind;
    readonly adapter: string;
    readonly adapterFamily: string;
    readonly vcsPosture: TargetVcsPosture;
    readonly currentBasis: string | null;
    readonly pathScope: readonly string[];
    readonly capabilities: TargetCapabilities;
    readonly status: WorkTargetStatus;
    readonly concurrency: TargetConcurrency;
}

/** A chat (engagement) leaf in the nav tree. */
export interface ChatNode {
    readonly id: EngagementId;
    readonly title: string;
    readonly kind: ChatKind;
    /** The id of the workstream this chat is homed to, or `null` for the placement
     *  mainline (the default). Drives workstream grouping in the nav (WS-F). */
    readonly workstream: WorkstreamId | null;
    /** The chat's placement (its authoring/work instance). Lets a workstream be created
     *  from this chat row, resolving the placement to the chat's own home (WS-H). */
    readonly placement: PlacementId | null;
    /** The immutable workspace root used for workstream admission. */
    readonly workspaceRoot: WorkspaceRootId;
    readonly targetId: WorkTargetId;
    readonly targetBasis: string;
    readonly targetKind: WorkTargetKind;
    readonly targetAdapter: string;
    readonly targetPathScope: readonly string[];
    readonly targetCapabilities: TargetCapabilities;
    readonly candidateRevision: string;
    readonly availableActs: readonly TargetActKind[];
    /** Per-chat status for the nav gem (WS-H b/c), folded from the chat's merge
     *  scope: an auto-sync / merge hit a conflict being repaired. The companion
     *  `changes` dot went with per-change review (ADR 0136) — a clean candidate
     *  always settles now, so there is nothing for it to report. */
    readonly conflict: boolean;
    /** True while re-homing would discard/transplant a candidate workspace. */
    readonly rehomeBlocked: boolean;
}

/** A **workstream** (WS-E): a named shared auto-sync line within a placement. Member
 *  chats greedily sync into its main; promotion to the mainline is explicit. */
export interface WorkstreamNode {
    readonly id: WorkstreamId;
    readonly name: string;
    readonly placementId: PlacementId;
    /** Exact immutable root eligible member chats must share. */
    readonly workspaceRoot: WorkspaceRootId;
    readonly targetId: WorkTargetId;
    readonly status: "active" | "archived";
    /** The chat ids currently homed to this workstream. */
    readonly members: EngagementId[];
}
/** An **archetype** (library method) with its edit chats (ADR 0035). Its edit chats can
 *  collaborate on the method in a workstream too (WS-F). */
export interface ArchetypeNode {
    readonly id: ArchetypeId;
    readonly name: string;
    readonly kind: AgentKind;
    readonly panelProfile: PanelPublicProfile | null;
    /** The archetype's authoring instance — the root a workstream over its edit chats is
     *  created on (WS-F). */
    readonly instanceId: PlacementId;
    readonly authoringTargetId: WorkTargetId;
    readonly isDefault: boolean;
    /** The source this archetype was forked from (ADR 0038), or null for an original.
     *  A fork shares its source's history, so it can pull upstream improvements. */
    readonly forkedFrom: ArchetypeId | null;
    readonly forkedFromName: string | null;
    readonly chats: ChatNode[];
    readonly workstreams: WorkstreamNode[];
}
export type AgentKind = "work" | "panel";
export type AgentAbility = "workspace.read" | "workspace.write" | "command.run";

export interface PublicDeploymentBindingSummary {
    readonly id: string;
    readonly deploymentId: string;
    readonly edgeOrigin: string;
    readonly activeReleaseId: string | null;
    readonly status: "pending_publish" | "active" | "legacy_confirmation_required";
}
/** A **placement**: an archetype installed on a project, with its work chats. Its
 *  lineage (`archetypeName`) is always visible — a placement is never an orphan. */
export interface PlacementNode {
    readonly placementId: PlacementId;
    readonly kind: AgentKind;
    readonly archetypeId: ArchetypeId;
    readonly archetypeName: string;
    /** The project's built-in **general** placement (project-tied default): the nav hides
     *  it as a node and shows its chats directly under the project (WS-H / project.md). */
    readonly isDefault: boolean;
    /** Whether this placement carries a config-only customization (config overlay or
     *  notes) — the nav badges it so a customized client placement is legible. */
    readonly hasConfig: boolean;
    /** The pinned (installed, read-only) method version, or `null` if unpinned. */
    readonly pinnedVersion: string | null;
    /** The archetype version this placement runs (UX-9). */
    readonly version: number;
    /** The archetype's current published version. */
    readonly currentVersion: number;
    readonly panelProfile: PanelPublicProfile | null;
    /** Whether a newer archetype version is available to upgrade to (UX-9). */
    readonly upgradeAvailable: boolean;
    /** Whether this placement is **pending approval** (APPROVE-1, ADR 0064): approved-but-
     *  not-yet-accepted under an approval-required policy. It can't host work chats until
     *  the owner accepts it; the nav flags it. Frictionless placements are never pending. */
    readonly pending: boolean;
    readonly deployments: readonly PublicDeploymentBindingSummary[];
    readonly targetIds: readonly WorkTargetId[];
    readonly chats: ChatNode[];
    /** The named workstreams (shared auto-sync lines) in this placement (WS-F). */
    readonly workstreams: WorkstreamNode[];
}
/** A **project** — a trust/data boundary (ADR 0036) holding its placements. */
export interface ProjectNode {
    readonly id: ProjectId;
    readonly homeId: HomeId;
    readonly name: string;
    /** The always-visible zero-setup personal trust boundary (ADR 0097). */
    readonly isPersonal: boolean;
    /** Network egress posture (RF-B3): `true` isolates this project's chats from
     *  the network (fail-closed); `false` (the default) lets them reach the model. */
    readonly networkIsolated: boolean;
    readonly targets: readonly WorkTargetNode[];
    readonly placements: PlacementNode[];
}

export interface PublicDeploymentInput {
    readonly placement_id: PlacementId;
    readonly deployment_id: string;
    readonly edge_origin: string;
    readonly allowed_origins: readonly string[];
    readonly max_spend_cents: number | null;
    readonly max_session_spend_cents: number | null;
    readonly max_turn_spend_cents: number | null;
    readonly per_visitor_turn_limit: number;
    readonly max_concurrent_sessions: number;
    /** Product-facing funding choice. Managed funding names an authenticated
     * account/tenant; the Hub-signed claims derive the hosted funding reference. */
    readonly funding: {
        readonly kind: "managed";
        readonly tenant_id: string;
        readonly entitlement?: import("./control-plane-tenant").ManagedInferenceEntitlement;
    } | {
        readonly kind: "byok";
        readonly credential_ref: string;
    };
    readonly audience?: {
        readonly anonymous_allowed: boolean;
        readonly oidc?: { readonly issuer: string; readonly audience: string };
    };
    readonly white_label: boolean;
    /** How long a visitor may resume, within the ceiling the release declares
     *  (ADR 0109). A resumption window, not a collection deadline — collection
     *  latency is independent of it, which is why the two are separate fields
     *  rather than one "how long do we keep this". Omitted fields take the
     *  server's defaults. */
    readonly retention_idle_ttl_seconds?: number;
    readonly retention_absolute_ttl_seconds?: number;
    /** End already-open visitor sessions when activating this configuration. */
    readonly end_sessions?: boolean;
}

export interface PanelPreviewInput {
    readonly agent_id: ArchetypeId;
    readonly placement_id?: PlacementId;
    readonly edge_origin: string;
    readonly allowed_origin: string;
    readonly funding: PublicDeploymentInput["funding"];
}

export interface PanelPreviewOutcome {
    readonly preview_id: string;
    readonly deployment_id: string;
    readonly release_id: string;
    readonly edge_origin: string;
    readonly deployment_url: string;
    readonly panels: readonly string[];
    readonly expires_at_unix_ms: number;
}

/** What a collecting deployment gathers, and who it seals to (ADR 0109 §5–§7).
 *
 *  `exportable_paths` and `transcript_eligible` are release content — what the
 *  author declared may leave at all. `recipient_ref` and `recipient_public_keys`
 *  are the *deployment's* choice of keyring, and the edge refuses a reference
 *  whose class the release does not permit. There is no ambient fallback: a
 *  deployment that names no recipient collects nothing. */
export interface PublicDeploymentCollection {
    readonly exportable_paths: readonly string[];
    readonly transcript_eligible: boolean;
    readonly schema_ref: string;
    readonly recipient_class: string;
    readonly max_artifact_bytes: number;
    readonly recipient_ref: string;
    /** Public halves only, hex SEC1 P-256. The private halves never leave the
     *  Home — they are what opens a drained artifact. */
    readonly recipient_public_keys: readonly string[];
}

export type PublicPanelComponent = "gw-chat" | "gw-viewer" | "gw-files" | "gw-chats";
export type AudienceInputClass = "text" | "image" | "document" | "audio";

export interface PanelPublicProfile {
    readonly panels: {
        readonly components: readonly PublicPanelComponent[];
        readonly default_component: PublicPanelComponent;
        readonly attribution: "gauge_wright" | "white_label_eligible";
    };
    readonly public_abilities: readonly AgentAbility[];
    readonly provider: {
        readonly provider: string;
        readonly model: string;
        readonly base_url: string;
        readonly credential_class: string;
        readonly max_input_tokens?: number;
        readonly max_output_tokens?: number;
    };
    readonly audience_inputs: readonly AudienceInputClass[];
    readonly initial_workspace: readonly {
        readonly path: string;
        readonly media_type: string;
        readonly sha256: string;
        readonly bytes: readonly number[];
    }[];
    readonly retention: {
        readonly idle_ttl_seconds: number;
        readonly absolute_ttl_seconds: number;
        readonly transcript_retained: boolean;
        readonly workspace_retained: boolean;
    };
    readonly collection: Omit<PublicDeploymentCollection, "recipient_ref" | "recipient_public_keys"> | null;
}

/** One collection recipient keyring this Home holds. */
export interface CollectionRecipient {
    readonly recipient_id: string;
    readonly recipient_ref: string;
    readonly public_key_hex: string;
}

export interface PublicDeploymentOutcome {
    readonly binding_id: string;
    readonly project_id: string;
    readonly placement_id: PlacementId;
    readonly deployment_id: string;
    readonly release_id: string;
    readonly edge_origin: string;
    readonly deployment_url: string;
    readonly embed_html: string;
    readonly deployment: unknown;
}

export interface LegacyDeploymentImportOutcome {
    readonly binding_id: string;
    readonly project_id: string;
    readonly deployment_id: string;
    readonly active_release_id: string;
}

export interface PublicCredentialMetadata {
    readonly credential_ref: string;
    readonly provider: "openai" | "anthropic";
    readonly credential_class: string;
    readonly label: string;
    readonly created_at_unix_ms: number;
}

export interface ProvisionPublicCredentialInput {
    readonly edge_origin: string;
    readonly provider: "openai" | "anthropic";
    readonly credential_class: string;
    readonly api_key: string;
    readonly label: string;
}

export interface PublicDeploymentInspection {
    readonly deployment: {
        readonly lifecycle: "active" | "paused" | "revoked";
        readonly config: {
            readonly deployment_id: string;
            readonly allowed_origins: readonly string[];
            readonly panel_ceiling: readonly string[];
            readonly max_spend_cents: number | null;
            readonly max_session_spend_cents: number | null;
            readonly max_turn_spend_cents: number | null;
            readonly per_visitor_turn_limit: number;
            readonly max_concurrent_sessions: number;
            readonly funding_ref?: string;
            readonly credential_class?: string;
            readonly credential_ref?: string;
            readonly audience?: {
                readonly anonymous_allowed: boolean;
                readonly oidc?: { readonly issuer: string; readonly audience: string };
            };
            readonly retention?: {
                readonly idle_ttl_seconds: number;
                readonly absolute_ttl_seconds: number;
            };
            readonly white_label?: boolean;
        };
        readonly active_release_id: string;
        readonly activation_revision: number;
        readonly spent_cents: number;
        readonly reserved_cents: number;
        readonly sessions: number;
        readonly settled_turns: number;
    };
    readonly audience: readonly {
        readonly session_id: string;
        readonly release_id: string;
        readonly origin: string;
        readonly principal_mode: "anonymous" | "authenticated";
        readonly audience_id: string | null;
        readonly created_at_unix_ms: number;
        readonly settled_turns: number;
        readonly expired_at_unix_ms?: number;
    }[];
}
/** A recent-chat row retained for search and activity projections. */
export interface RecentChat {
    readonly id: EngagementId;
    readonly title: string;
    readonly archetype: string;
    readonly kind: ChatKind;
    readonly workstream: WorkstreamId | null;
    /** The chat's placement (its home instance). */
    readonly placement: PlacementId | null;
    readonly workspaceRoot: WorkspaceRootId;
    readonly targetId: WorkTargetId;
    readonly targetBasis: string;
    readonly targetKind: WorkTargetKind;
    readonly targetAdapter: string;
    readonly candidateRevision: string;
    readonly availableActs: readonly TargetActKind[];
    /** Per-chat nav-gem status (WS-H b/c); see {@link ChatNode}. */
    readonly conflict: boolean;
    readonly rehomeBlocked: boolean;
}
/** The whole facet tree the nav renders: a projection over the library records. */
export interface Workspace {
    readonly archetypes: ArchetypeNode[];
    readonly projects: ProjectNode[];
    readonly recent: RecentChat[];
    readonly workstreams: WorkstreamNode[];
    readonly workTargets: WorkTargetNode[];
    /** The explicit Personal project's default placement. Retained as a direct
     * quick-start address alongside the rooted project tree. */
    readonly personalPlacement: PlacementId | null;
}

/** One chat-content search hit: a chat whose **log** (SEARCH-1) or **worktree file**
 *  (SEARCH-2) matched the query, with a one-line snippet of the match. These are the
 *  server's content relevance tiers (`navigation.md`); the title tier is filtered
 *  client-side over the tree. `tier` tells log from file (log ranks above file, and the
 *  server emits at most one hit per chat via its strongest tier); `path` is the matching
 *  file for a `file` hit (the snippet already leads with it), absent for a `log` hit. */
export interface SearchHit {
    readonly id: EngagementId;
    readonly title: string;
    readonly snippet: string;
    readonly tier: "log" | "file";
    readonly path?: string;
}

/** A workspace-change **reference** pushed on the event stream (ADR 0037): what
 *  library record changed and how — never its content. The nav resolves a scoped
 *  delta projection on receipt. */
export interface WorkspaceChange {
    readonly record: "archetype" | "project" | "placement" | "chat" | "workstream" | "work_target";
    readonly id: string;
    readonly op: "upsert" | "tombstone";
}

/** An event from the control-plane stream that clients reduce into a transcript.
 *  `origin` (ADR 0141) marks a line inherited from a fork ancestor — the
 *  transcript projection stamps it on every inherited durable record, whatever
 *  its kind, so the client can place the fork-point seam correctly. Only `text`
 *  lacks it: streamed deltas are operational-only and never inherited. */
export type StreamEvent =
    | { type: "user"; text: string; entry_id?: number; forkable?: boolean; origin?: string }
    | { type: "assistant"; text: string; entry_id?: number; forkable?: boolean; origin?: string }
    | { type: "text"; delta: string }
    | { type: "tool"; tool: string; mediated: boolean; call_id?: string; target?: string; args?: string; origin?: string }
    | { type: "toolresult"; call_id: string; ok: boolean; result?: string; origin?: string }
    | { type: "blocked"; tool: string; reason: string; origin?: string }
    | { type: "error"; reason: string; code?: string; origin?: string }
    | { type: "admitted"; kind: string; text: string; origin?: string };

const WORKSPACE_RECORDS: readonly WorkspaceChange["record"][] = ["archetype", "project", "placement", "chat", "workstream", "work_target"];
/** Narrow a raw event `record` to the closed {@link WorkspaceChange} set. */
export function isWorkspaceRecord(v: unknown): v is WorkspaceChange["record"] {
    return typeof v === "string" && (WORKSPACE_RECORDS as readonly string[]).includes(v);
}

/** The kinds of task the top bar surfaces (ADR 0075 §5): a clean-merge chat
 *  awaiting keep/reject (`review`), an onboarding checklist item from the
 *  per-boundary whip tracker (`issue`), or inbound material a project's gate
 *  has parked on a person (`screen`, ADR 0110 §7). */
/** `review` is absent by design: ADR 0136 retired that ask with the per-change
 *  hold. A server that still sends it degrades to `reply` in {@link getTasks}. */
export type TaskKind = "answer" | "repair" | "reply" | "issue" | "screen";

/** One item in the human task queue (the top bar). The kind is the **ask** —
 *  the verb the human is being asked to perform (ADR 0082 §2): `review` a clean
 *  merge (keep/reject), `answer` the agent's pending question, `repair` a merge
 *  conflict; `issue` tasks come from the account-global whip tracker
 *  (onboarding); `screen` inbound material a project's gate parked on a person.
 *  Note `id` is an {@link EngagementId} for chat asks but a whip work-item id
 *  (`WS-N`) for `issue` tasks — narrow on `kind` before treating it as an
 *  engagement. A `screen` task's `id` *is* an engagement, but the task belongs
 *  to `project` rather than to that chat. */
export interface HumanTask {
    readonly id: string;
    readonly title: string;
    readonly agent: string;
    readonly kind: TaskKind;
    /** The authority this task is assigned to — v1: the acting/owner authority.
     *  Undefined = unassigned / visible to the boundary owner (ADR 0075 §4). */
    readonly assignee?: string;
    /** `issue` only: the tracker boundary required when assigning its item id. */
    readonly boundary?: string;
    /** `screen` only: the project whose quarantine this counts. The task is
     *  project-scoped — `id` names the chat the index opens in, which is where a
     *  reviewer goes to look, not what the count belongs to. */
    readonly project?: string;
    /** `screen` only: how many items are waiting on a person. */
    readonly waiting?: number;
}

/** One active member in the host-derived roster used by ask and assignment. */
export interface RosterPerson {
    readonly authority: string;
    readonly display: string;
    readonly role: string;
}

function requiredString(value: unknown, field: string): string {
    if (typeof value !== "string" || !value) throw new Error(`workspace: expected ${field}`);
    return value;
}

function stringList(value: unknown, field: string): string[] {
    if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
        throw new Error(`workspace: expected ${field} string array`);
    }
    return value;
}

function valueList(value: unknown, field: string): unknown[] {
    if (!Array.isArray(value)) throw new Error(`workspace: expected ${field} array`);
    return value;
}

function parseTargetKind(value: unknown, field: string): WorkTargetKind {
    if (value === "managed" || value === "external-vcs" || value === "external-folder") return value;
    throw new Error(`workspace: expected ${field}`);
}

function parseTargetCapabilities(value: unknown, field: string): TargetCapabilities {
    const o = (value ?? {}) as Record<string, unknown>;
    for (const act of ["read", "propose", "apply", "publish", "release"] as const) {
        if (typeof o[act] !== "boolean") throw new Error(`workspace: expected ${field}.${act}`);
    }
    return {
        read: o.read as boolean,
        propose: o.propose as boolean,
        apply: o.apply as boolean,
        publish: o.publish as boolean,
        release: o.release as boolean,
    };
}

function parseTargetActs(value: unknown, field: string): TargetActKind[] {
    const allowed = new Set<TargetActKind>(["read", "propose", "apply", "publish", "release"]);
    const values = stringList(value, field);
    for (const act of values) {
        if (!allowed.has(act as TargetActKind)) throw new Error(`workspace: bad ${field}`);
    }
    return values as TargetActKind[];
}

type RawChat = {
    id: string;
    title: string;
    kind?: ChatKind;
    workstream?: string | null;
    placement?: string | null;
    workspace_root: string;
    target_id: string;
    target_basis: string;
    target_kind: WorkTargetKind;
    target_adapter: string;
    target_path_scope: string[];
    target_capabilities: TargetCapabilities;
    candidate_revision: string;
    available_acts: TargetActKind[];
    changes?: boolean;
    conflict?: boolean;
    rehome_blocked?: boolean;
};

const parseChat = (c: RawChat): ChatNode => ({
    id: engagementId(c.id),
    title: c.title,
    kind: c.kind === "edit" ? "edit" : "work",
    workstream: c.workstream ? workstreamId(c.workstream) : null,
    placement: c.placement ? (c.placement as PlacementId) : null,
    workspaceRoot: requiredString(c.workspace_root, "chat.workspace_root") as WorkspaceRootId,
    targetId: workTargetId(requiredString(c.target_id, "chat.target_id")),
    targetBasis: requiredString(c.target_basis, "chat.target_basis"),
    targetKind: parseTargetKind(c.target_kind, "chat.target_kind"),
    targetAdapter: requiredString(c.target_adapter, "chat.target_adapter"),
    targetPathScope: stringList(c.target_path_scope, "chat.target_path_scope"),
    targetCapabilities: parseTargetCapabilities(c.target_capabilities, "chat.target_capabilities"),
    candidateRevision: requiredString(c.candidate_revision, "chat.candidate_revision"),
    availableActs: parseTargetActs(c.available_acts, "chat.available_acts"),
    conflict: c.conflict ?? false,
    rehomeBlocked: c.rehome_blocked ?? true,
});

export const parseWorkstream = (w: {
    id: string;
    name: string;
    placement_id: string;
    workspace_root: string;
    target_id: string;
    status?: string;
    members?: string[];
}): WorkstreamNode => ({
    id: workstreamId(w.id),
    name: w.name,
    placementId: w.placement_id as PlacementId,
    workspaceRoot: requiredString(w.workspace_root, "workstream.workspace_root") as WorkspaceRootId,
    targetId: workTargetId(requiredString(w.target_id, "workstream.target_id")),
    status: w.status === "archived" ? "archived" : "active",
    members: (w.members ?? []).map(engagementId),
});

export function parseWorkTarget(raw: unknown): WorkTargetNode {
    const o = (raw ?? {}) as Record<string, unknown>;
    if (typeof o.id !== "string" || !o.id) throw new Error("work target: expected id");
    const kind = parseTargetKind(o.kind, `work target ${o.id}.kind`);
    const ownerKind = o.owner_kind === "archetype" ? "archetype" : o.owner_kind === "project" ? "project" : null;
    if (!ownerKind) throw new Error(`work target ${o.id}: bad owner`);
    if (o.vcs_posture !== "managed" && o.vcs_posture !== "external-vcs" && o.vcs_posture !== "unversioned") {
        throw new Error(`work target ${o.id}: bad VCS posture`);
    }
    const vcsPosture = o.vcs_posture as TargetVcsPosture;
    if (o.status !== "available" && o.status !== "unavailable" && o.status !== "retired") {
        throw new Error(`work target ${o.id}: bad status`);
    }
    const status = o.status as WorkTargetStatus;
    if (o.concurrency !== "serialized" && o.concurrency !== "native-vcs" && o.concurrency !== "compare-before-write-weak") {
        throw new Error(`work target ${o.id}: bad concurrency posture`);
    }
    return {
        id: workTargetId(o.id),
        name: requiredString(o.name, `work target ${o.id}.name`),
        ownerKind,
        ownerId: requiredString(o.owner_id, `work target ${o.id}.owner_id`),
        authority: requiredString(o.authority, `work target ${o.id}.authority`),
        parties: stringList(o.parties, `work target ${o.id}.parties`),
        kind,
        adapter: requiredString(o.adapter, `work target ${o.id}.adapter`),
        adapterFamily: requiredString(o.adapter_family, `work target ${o.id}.adapter_family`),
        vcsPosture,
        currentBasis: o.current_basis === null ? null : requiredString(o.current_basis, `work target ${o.id}.current_basis`),
        pathScope: stringList(o.path_scope, `work target ${o.id}.path_scope`),
        capabilities: parseTargetCapabilities(o.capabilities, `work target ${o.id}.capabilities`),
        status,
        concurrency: o.concurrency,
    };
}

/** Parse the raw workspace tree (the same wire shape from `GET /workspace` and the
 *  `/projections/library/workspace` carriage value) into the branded {@link Workspace}. */
export function parseWorkspace(raw: unknown): Workspace {
    const o = (raw ?? {}) as {
        archetypes?: { id: string; name: string; kind?: AgentKind; panel_profile?: PanelPublicProfile | null; instance_id?: string; authoring_target_id: string; is_default: boolean; forked_from?: string | null; forked_from_name?: string | null; chats: RawChat[]; workstreams?: { id: string; name: string; placement_id: string; workspace_root: string; target_id: string; status?: string; members?: string[] }[] }[];
        projects?: {
            id: string;
            home_id?: string;
            name: string;
            is_personal?: boolean;
            network_isolated?: boolean;
            targets: unknown[];
            placements: {
                placement_id: string;
                kind?: AgentKind;
                archetype_id: string;
                archetype_name: string;
                is_default?: boolean;
                has_config?: boolean;
                pinned_version: string | null;
                version?: number;
                current_version?: number;
                panel_profile?: PanelPublicProfile | null;
                upgrade_available?: boolean;
                pending?: boolean;
                deployments?: { id: string; deployment_id: string; edge_origin: string; active_release_id?: string | null; status: PublicDeploymentBindingSummary["status"] }[];
                target_ids: string[];
                chats: RawChat[];
                workstreams?: { id: string; name: string; placement_id: string; workspace_root: string; target_id: string; status?: string; members?: string[] }[];
            }[];
        }[];
        recent?: (RawChat & { archetype: string })[];
        workstreams?: { id: string; name: string; placement_id: string; workspace_root: string; target_id: string; status?: string; members?: string[] }[];
        work_targets: unknown[];
        personal_placement?: string | null;
    };
    return {
        archetypes: (o.archetypes ?? []).map((a) => ({
            id: a.id as ArchetypeId,
            name: a.name,
            kind: a.kind ?? "work",
            panelProfile: a.panel_profile ?? null,
            instanceId: (a.instance_id ?? "") as PlacementId,
            authoringTargetId: workTargetId(requiredString(a.authoring_target_id, "archetype.authoring_target_id")),
            isDefault: a.is_default,
            forkedFrom: a.forked_from ? (a.forked_from as ArchetypeId) : null,
            forkedFromName: a.forked_from_name ?? null,
            chats: a.chats.map(parseChat),
            workstreams: (a.workstreams ?? []).map(parseWorkstream),
        })),
        projects: (o.projects ?? []).map((p) => ({
            id: p.id as ProjectId,
            homeId: (p.home_id ?? "") as HomeId,
            name: p.name,
            isPersonal: p.is_personal ?? false,
            networkIsolated: p.network_isolated ?? false,
            targets: valueList(p.targets, "project.targets").map(parseWorkTarget),
            placements: p.placements.map((pl) => ({
                placementId: pl.placement_id as PlacementId,
                kind: pl.kind ?? "work",
                archetypeId: pl.archetype_id as ArchetypeId,
                archetypeName: pl.archetype_name,
                isDefault: pl.is_default ?? false,
                hasConfig: pl.has_config ?? false,
                pinnedVersion: pl.pinned_version ?? null,
                version: pl.version ?? 1,
                currentVersion: pl.current_version ?? 1,
                panelProfile: pl.panel_profile ?? null,
                upgradeAvailable: pl.upgrade_available ?? false,
                pending: pl.pending ?? false,
                deployments: (pl.deployments ?? []).map((deployment) => ({
                    id: deployment.id,
                    deploymentId: deployment.deployment_id,
                    edgeOrigin: deployment.edge_origin,
                    activeReleaseId: deployment.active_release_id ?? null,
                    status: deployment.status,
                })),
                targetIds: stringList(pl.target_ids, "placement.target_ids").map(workTargetId),
                chats: pl.chats.map(parseChat),
                workstreams: (pl.workstreams ?? []).map(parseWorkstream),
            })),
        })),
        recent: (o.recent ?? []).map((c) => ({
            id: engagementId(c.id),
            title: c.title,
            archetype: c.archetype,
            kind: c.kind === "edit" ? "edit" : "work",
            workstream: c.workstream ? workstreamId(c.workstream) : null,
            placement: c.placement ? (c.placement as PlacementId) : null,
            workspaceRoot: requiredString(c.workspace_root, "recent.workspace_root") as WorkspaceRootId,
            targetId: workTargetId(requiredString(c.target_id, "recent.target_id")),
            targetBasis: requiredString(c.target_basis, "recent.target_basis"),
            targetKind: parseTargetKind(c.target_kind, "recent.target_kind"),
            targetAdapter: requiredString(c.target_adapter, "recent.target_adapter"),
            candidateRevision: requiredString(c.candidate_revision, "recent.candidate_revision"),
            availableActs: parseTargetActs(c.available_acts, "recent.available_acts"),
                conflict: c.conflict ?? false,
            rehomeBlocked: c.rehome_blocked ?? true,
        })),
        workstreams: (o.workstreams ?? []).map(parseWorkstream),
        workTargets: valueList(o.work_targets, "work_targets").map(parseWorkTarget),
        personalPlacement: o.personal_placement ? (o.personal_placement as PlacementId) : null,
    };
}

// ----- Run lifecycle projection (mirrors gaugedesk_core::run) -----

export type RunPhase =
    | "Init"
    | "Requested"
    | "Admitted"
    | "Running"
    | "Completed"
    | "Failed"
    | "Canceled";

export interface RunState {
    readonly phase: RunPhase;
    readonly admittedOnce: boolean;
}

/** Run commands the client may submit (it requests; the server decides). */
export type RunCommand =
    | "RequestRun"
    | "AdmitRun"
    | "StartRun"
    | "AwaitHuman"
    | "ResumeRun"
    | "CompleteRun"
    | "FailRun"
    | "CancelRun"
    | "RetryRun";

export interface Engagement {
    readonly id: EngagementId;
    readonly branch: string;
    readonly path: string;
}

/** A rejected command is a receipt, not a fact (`INV-2`). */
export class Rejected extends Error {
    constructor(
        public readonly reason: string,
        /** The command-receipt status behind an idempotency refusal, when the
         *  refusal came from the command envelope: `applied` means the request
         *  already ran to completion, `processing` means its fate is still
         *  unknown. A caller retrying under a stable key needs that difference —
         *  "it already happened" and "it might be happening" are opposite
         *  answers, and the reason string alone conflates them. */
        public readonly commandStatus?: string,
    ) {
        super(`rejected: ${reason}`);
    }
}

/** The status a turn route answers when the turn was **stopped on purpose**.
 *  nginx's "client closed the request", and it means the same thing here: the
 *  caller withdrew, so nothing failed. */
export const TURN_STOPPED_STATUS = 499;

/** A turn that ended because someone stopped it.
 *
 *  Its own type because every layer above has to tell it from a failure, and a
 *  status code alone does not survive the trip: as a generic error it surfaced
 *  as `POST /chats/…/task: 502 turn interrupted` on the composer's error line —
 *  the composer calling the reader's own decision a fault — and the outbox kept
 *  the cancelled message, held, for a retry nobody asked for. */
export class TurnStopped extends Error {
    constructor() {
        super("stopped");
        this.name = "TurnStopped";
    }
}

/** Was this rejection simply the turn being stopped? */
export function turnStopped(error: unknown): boolean {
    return error instanceof TurnStopped;
}

/** Did this refusal mean the command had already run to completion?
 *
 *  Only true for a receipt the server settled as `applied`. Every other status —
 *  `processing`, `received`, `rejected`, `expired` — leaves the outcome open, and
 *  a caller must not treat any of them as success. */
export function alreadyApplied(error: unknown): boolean {
    return error instanceof Rejected && error.commandStatus === "applied";
}

/** Phrase a failed command for the user, keeping the `INV-2` distinction the
 *  `Rejected` receipt models: a rejection is the *expected* "the authority
 *  declined, and here is why" outcome (surface the reason), while anything else is
 *  an unexpected transport/internal failure. `action` is an imperative phrase,
 *  e.g. `"hand off"` → `"couldn't hand off — already home"`. */
export function describeFailure(action: string, e: unknown): string {
    return e instanceof Rejected
        ? `couldn't ${action} — ${e.reason}`
        : `${action} failed — something went wrong`;
}

// ----- Review / export projections (mirror gaugedesk_core::review / resource_export) -----

export type ReviewPhase = "Init" | "Proposed" | "Cleared" | "Released" | "Withheld";
export interface ReviewState {
    readonly phase: ReviewPhase;
    readonly required: string[];
    readonly consented: string[];
}
/** Decisions a caller may make on a concrete resource review. The authenticated
 * actor is materialized by the server and is never accepted from this payload. */
export type ResourceReviewAction = "consent" | "reject" | "revoke" | "release";

export type ExportPhase = "Init" | "Requested" | "Cleared" | "Exported" | "Denied";
export interface ExportState {
    readonly phase: ExportPhase;
    readonly source_required: string[];
    readonly source_consented: string[];
    readonly target_admitted: boolean;
}
/** Source decisions on a concrete resource export. Target admission and the
 * final export fact belong to the egress implementation, not this caller. */
export type ResourceExportAction = "consent" | "reject" | "revoke";

/** One row of the audit timeline (`INV-6`). */
export interface AuditEvent {
    readonly position: number;
    readonly kind: string;
    readonly payload: string;
}

// ----- Durable resources projection (mirrors gaugedesk_core::resource / resource_access) -----

/** A resource's **kind** — `method | context | output`, an *open* set (the core
 *  treats it as a string, `INV-12`). The UI keys its panels on the three known
 *  kinds and passes any other through verbatim. */
export type ResourceKind = "method" | "context" | "output" | (string & {});

/** The access lifecycle phase for a resource handle (mirrors `AccessPhase`): a
 *  handle conveys no payload access until `Granted` (`INV-10`). A **closed** set —
 *  the core enum has exactly these five variants — so an unknown wire value is a
 *  parse error, not a silently-rendered phase. */
export type AccessPhase = "Init" | "Requested" | "Granted" | "Revoked" | "Denied";

const ACCESS_PHASES: readonly AccessPhase[] = ["Init", "Requested", "Granted", "Revoked", "Denied"];
/** Validate a wire `access` value against the closed lifecycle (mirrors core
 *  `AccessPhase`); an unknown value throws at the edge rather than reading as a
 *  benign `Init`. */
export function parseAccessPhase(v: unknown): AccessPhase {
    if (typeof v === "string" && (ACCESS_PHASES as readonly string[]).includes(v)) return v as AccessPhase;
    throw new Error(`bad access phase: ${JSON.stringify(v)}`);
}

/** One durable resource as the `GET /chats/:id/resources` projection emits it:
 *  handle + metadata only — never the payload (`INV-10`). */
export interface ResourceView {
    readonly id: string;
    readonly kind: ResourceKind;
    readonly owner: string;
    readonly stakeholders: readonly string[];
    /** The access lifecycle phase; only `Granted` resolves the payload. */
    readonly access: AccessPhase;
    /** Whether the payload was erased via the tombstone lifecycle (`INV-18`). */
    readonly tombstoned: boolean;
}

/** Parse one raw resource row (snake-ish wire shape) into the branded view. The
 *  identity (`id`) and `kind` are required strings and `access` a valid phase — a
 *  malformed row throws at the edge rather than rendering as a plausible-but-wrong
 *  resource (`id:""`, `kind:"context"`, `access:"Init"`). */
export function parseResourceView(raw: unknown): ResourceView {
    const o = (raw ?? {}) as Record<string, unknown>;
    if (typeof o.id !== "string") throw new Error("resource: expected string id");
    if (typeof o.kind !== "string") throw new Error(`resource ${o.id}: expected string kind`);
    return {
        id: o.id,
        kind: o.kind,
        owner: typeof o.owner === "string" ? o.owner : "",
        stakeholders: Array.isArray(o.stakeholders) ? o.stakeholders.map(String) : [],
        access: parseAccessPhase(o.access),
        tombstoned: Boolean(o.tombstoned),
    };
}

// ----- Merge lifecycle (the diff review surface) -----

export type MergePhase =
    | "Idle"
    | "Merging"
    | "Clean"
    | "Rejected"
    | "Repairing"
    | "Advanced"
    | "Integrated";
/** Why a `Rejected` merge isolated: a git **Conflict** (couldn't be merged) vs a user
 *  discard (`Success`/`Unknown`). Lets the UI tell "this conflicted" from "you discarded". */
export type GitOutcome = "Unknown" | "Success" | "Conflict";
export interface MergeState {
    readonly phase: MergePhase;
    readonly thread_state: string;
    readonly git_outcome: GitOutcome;
}
export type MergeAction = "admit" | "reject" | "repair" | "retry" | "integrate";

const isMergePhase = (v: unknown): v is MergePhase =>
    typeof v === "string" &&
    ["Idle", "Merging", "Clean", "Rejected", "Repairing", "Advanced", "Integrated"].includes(v);

/** Parse a raw control-plane payload into the branded {@link MergeState}. Validates
 *  the lifecycle phase at the edge (cf. {@link parseRunState}) so an out-of-set
 *  phase is a parse error here, not a silent mis-render downstream. */
export function parseMergeState(raw: unknown): MergeState {
    const o = (raw ?? {}) as Record<string, unknown>;
    if (!isMergePhase(o.phase)) throw new Error(`bad merge phase: ${JSON.stringify(raw)}`);
    const git_outcome: GitOutcome =
        o.git_outcome === "Conflict" || o.git_outcome === "Success" ? o.git_outcome : "Unknown";
    return {
        phase: o.phase,
        thread_state: typeof o.thread_state === "string" ? o.thread_state : "",
        git_outcome,
    };
}

const isReviewPhase = (v: unknown): v is ReviewPhase =>
    typeof v === "string" && ["Init", "Proposed", "Cleared", "Released", "Withheld"].includes(v);

/** Parse a raw payload into the branded {@link ReviewState} (phase-guarded edge). */
export function parseReviewState(raw: unknown): ReviewState {
    const o = (raw ?? {}) as Record<string, unknown>;
    if (!isReviewPhase(o.phase)) throw new Error(`bad review phase: ${JSON.stringify(raw)}`);
    return {
        phase: o.phase,
        required: Array.isArray(o.required) ? o.required.map(String) : [],
        consented: Array.isArray(o.consented) ? o.consented.map(String) : [],
    };
}

const isExportPhase = (v: unknown): v is ExportPhase =>
    typeof v === "string" && ["Init", "Requested", "Cleared", "Exported", "Denied"].includes(v);

/** Parse a raw payload into the branded {@link ExportState} (phase-guarded edge). */
export function parseExportState(raw: unknown): ExportState {
    const o = (raw ?? {}) as Record<string, unknown>;
    if (!isExportPhase(o.phase)) throw new Error(`bad export phase: ${JSON.stringify(raw)}`);
    return {
        phase: o.phase,
        source_required: Array.isArray(o.source_required) ? o.source_required.map(String) : [],
        source_consented: Array.isArray(o.source_consented) ? o.source_consented.map(String) : [],
        target_admitted: Boolean(o.target_admitted),
    };
}

/** Parse one raw audit row into the branded {@link AuditEvent}. The timeline is
 *  `INV-6` product truth, so it is validated at the edge rather than passed raw. */
export function parseAuditEvent(raw: unknown): AuditEvent {
    const o = (raw ?? {}) as Record<string, unknown>;
    if (typeof o.position !== "number") throw new Error(`bad audit position: ${JSON.stringify(raw)}`);
    return {
        position: o.position,
        kind: typeof o.kind === "string" ? o.kind : "",
        payload: typeof o.payload === "string" ? o.payload : "",
    };
}

/** One worktree file-tree entry. */
export interface FileEntry {
    readonly path: string;
    readonly isDir: boolean;
}

const isPhase = (v: unknown): v is RunPhase =>
    typeof v === "string" &&
    [
        "Init",
        "Requested",
        "Admitted",
        "Running",
        "Completed",
        "Failed",
        "Canceled",
    ].includes(v);

/** Parse a raw control-plane payload into the branded `RunState`. */
export function parseRunState(raw: unknown): RunState {
    const o = raw as Record<string, unknown>;
    if (!isPhase(o?.phase)) throw new Error(`bad run phase: ${JSON.stringify(raw)}`);
    return { phase: o.phase, admittedOnce: Boolean(o.admitted_once) };
}
