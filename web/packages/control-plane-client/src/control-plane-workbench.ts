import { type ProjectionCarriage, parseProjectionCarriage } from "./projection-carriage";
import { parseWorkspaceDelta, type WorkspaceDelta } from "./workspace-delta";
import { type ProjectHome, parseProjectHome } from "./project-home";
import {
    engagementId,
    isWorkspaceRecord,
    parseAccessPhase,
    parseAuditEvent,
    parseExportState,
    parseMergeState,
    parseResourceView,
    parseReviewState,
    parseRunState,
    parseWorkspace,
    parseWorkTarget,
    parseWorkstream,
    type StreamEvent,
} from "./control-plane-domain";
import type {
    AccessPhase,
    AgentAbility,
    AgentKind,
    ArchetypeId,
    AuditEvent,
    Engagement,
    EngagementId,
    ExportState,
    FileEntry,
    HumanTask,
    LegacyDeploymentImportOutcome,
    MergeAction,
    MergeState,
    PanelPublicProfile,
    PlacementId,
    ProjectId,
    CollectionRecipient,
    PublicDeploymentInput,
    PublicDeploymentInspection,
    PublicDeploymentOutcome,
    PublicCredentialMetadata,
    ProvisionPublicCredentialInput,
    ResourceView,
    RosterPerson,
    ResourceExportAction,
    ResourceReviewAction,
    ReviewState,
    RunCommand,
    RunState,
    ScopeId,
    SearchHit,
    WorkTargetId,
    WorkTargetKind,
    WorkTargetNode,
    WorkstreamId,
    WorkstreamNode,
    Workspace,
    WorkspaceChange,
} from "./control-plane-domain";
import type { RouteJson } from "./control-plane-transport";
import { newIdempotencyKey } from "./control-plane-transport";
import type { RouteEventStream, RouteRequest } from "./browser-route-json";

export interface WorkbenchTransport {
    readonly base: string;
    readonly json: RouteJson;
    readonly request?: RouteRequest;
    readonly events?: RouteEventStream;
}

function request(transport: WorkbenchTransport, path: string, init?: RequestInit): Promise<Response> {
    if (transport.request) return transport.request(path, init);
    return fetch(transport.base + path, { ...init, credentials: "include" });
}

export async function getRun(transport: WorkbenchTransport, scope: ScopeId): Promise<RunState> {
    return parseRunState(await transport.json("GET", `/scopes/${scope}/run`));
}

export async function listEngagements(transport: WorkbenchTransport): Promise<EngagementId[]> {
    const o = (await transport.json("GET", "/chats")) as { engagements: string[] };
    return o.engagements.map(engagementId);
}

/** The whole nav tree: archetypes, projects, recent chats, and workstreams. */
export async function getWorkspace(transport: WorkbenchTransport): Promise<Workspace> {
    return parseWorkspace(await transport.json("GET", "/workspace"));
}

/** The workspace in its freshness carriage (ADR 0037). */
export async function getWorkspaceCarriage(
    transport: WorkbenchTransport,
): Promise<ProjectionCarriage<Workspace>> {
    const raw = (await transport.json(
        "GET",
        "/projections/library/workspace?freshness=live",
    )) as {
        value: unknown;
        freshness: { marker?: unknown; generated_at?: unknown; repair_hint?: unknown };
        client_request_id?: unknown;
    };
    return parseProjectionCarriage(raw, (v) => parseWorkspace(v));
}

/** Resolve a reference-only workspace event into the narrow projection nodes
 * needed to patch the current tree (UX-12 / ADR 0037). */
export async function getWorkspaceDeltaCarriage(
    transport: WorkbenchTransport,
    change: WorkspaceChange,
): Promise<ProjectionCarriage<WorkspaceDelta>> {
    const record = encodeURIComponent(change.record);
    const id = encodeURIComponent(change.id);
    const raw = (await transport.json(
        "GET",
        `/projections/library/workspace/${record}/${id}?freshness=live`,
    )) as {
        value: unknown;
        freshness: { marker?: unknown; generated_at?: unknown; repair_hint?: unknown };
        client_request_id?: unknown;
    };
    return parseProjectionCarriage(raw, (value) => parseWorkspaceDelta(value, change));
}

/** The human task queue (top bar): onboarding issues + ask-typed chat tasks
 *  (ADR 0082 §2 — `answer`/`repair`/`reply`). Chat-ask ids are engagement ids;
 *  `issue` ids are whip work-item ids (`WS-N`), so we keep `id` a raw string
 *  here and narrow on `kind` at the use site. An unknown kind degrades to
 *  `reply` — the always-safe ask, because it just opens the chat and offers no
 *  action the server did not ask for. It used to degrade to `review`, which
 *  carried a one-click keep: the wrong thing to offer for an ask you could not
 *  identify, and moot now that ADR 0136 has retired that kind entirely. */
export async function getTasks(transport: WorkbenchTransport): Promise<HumanTask[]> {
    const o = (await transport.json("GET", "/tasks")) as {
        tasks: {
            id: string;
            title: string;
            agent: string;
            kind: string;
            assignee?: string;
            boundary?: string;
            project?: string;
            waiting?: number;
        }[];
    };
    const kinds = new Set(["answer", "repair", "reply", "issue", "screen"]);
    return o.tasks.map((t) => ({
        id: t.id,
        title: t.title,
        agent: t.agent,
        kind: (kinds.has(t.kind) ? t.kind : "reply") as HumanTask["kind"],
        assignee: t.assignee,
        boundary: t.boundary,
        project: t.project,
        waiting: t.waiting,
    }));
}

/** Active people who may be asked or assigned work. */
export async function getRoster(transport: WorkbenchTransport): Promise<RosterPerson[]> {
    const value = (await transport.json("GET", "/roster")) as { people?: unknown };
    if (!Array.isArray(value.people)) throw new Error("roster: expected people array");
    return value.people.map((person) => {
        if (!person || typeof person !== "object") throw new Error("roster: expected person");
        const row = person as Record<string, unknown>;
        const field = (name: "authority" | "display" | "role") => {
            const candidate = row[name];
            if (typeof candidate !== "string" || !candidate) {
                throw new Error(`roster: expected ${name}`);
            }
            return candidate;
        };
        return {
            authority: field("authority"),
            display: field("display"),
            role: field("role"),
        };
    });
}

/** Direct a tracker item at an active roster authority, or clear it with null. */
export async function assignWorkItem(
    transport: WorkbenchTransport,
    boundary: string,
    item: string,
    to: string | null,
): Promise<string | null> {
    const value = (await transport.json(
        "POST",
        `/work-items/${encodeURIComponent(item)}/assign`,
        { boundary_id: boundary, to },
    )) as { assigned_to?: unknown };
    if (value.assigned_to !== null && typeof value.assigned_to !== "string") {
        throw new Error("work item assignment: expected assigned_to");
    }
    return value.assigned_to ?? null;
}

/** Content search across chat transcripts (SEARCH-1) and worktree files (SEARCH-2).
 *  The server ranks log hits before file hits and emits one hit per chat via its
 *  strongest tier; the tree renders each hit's snippet in place. */
export async function search(transport: WorkbenchTransport, query: string): Promise<SearchHit[]> {
    if (!query.trim()) return [];
    const o = (await transport.json("GET", `/search?q=${encodeURIComponent(query)}`)) as {
        hits?: { id: string; title: string; snippet: string; tier?: "log" | "file"; path?: string }[];
    };
    return (o.hits ?? []).map((h) => ({
        id: engagementId(h.id),
        title: h.title,
        snippet: h.snippet,
        tier: h.tier ?? "log",
        path: h.path,
    }));
}

export async function createArchetype(
    transport: WorkbenchTransport,
    name: string,
    kind: AgentKind = "work",
): Promise<ArchetypeId> {
    const o = (await transport.json("POST", "/archetypes", { name, kind })) as { id: string };
    return o.id as ArchetypeId;
}

export async function copyAgentAsPanel(
    transport: WorkbenchTransport,
    id: ArchetypeId,
    name?: string,
): Promise<ArchetypeId> {
    const o = (await transport.json("POST", `/archetypes/${id}/copy-as-panel`, { name })) as { id: string };
    return o.id as ArchetypeId;
}

export async function getPanelProfile(
    transport: WorkbenchTransport,
    id: ArchetypeId,
): Promise<PanelPublicProfile> {
    return await transport.json("GET", `/archetypes/${id}/panel-profile`) as PanelPublicProfile;
}

export async function setPanelProfile(
    transport: WorkbenchTransport,
    id: ArchetypeId,
    profile: PanelPublicProfile,
): Promise<PanelPublicProfile> {
    return await transport.json("PUT", `/archetypes/${id}/panel-profile`, profile) as PanelPublicProfile;
}

export async function renameArchetype(
    transport: WorkbenchTransport,
    id: ArchetypeId,
    name: string,
): Promise<void> {
    await transport.json("PUT", `/archetypes/${id}`, { name });
}

export async function getArchetypeConfig(
    transport: WorkbenchTransport,
    id: ArchetypeId,
): Promise<string> {
    const o = (await transport.json("GET", `/archetypes/${id}`)) as { config: string };
    return o.config;
}

/** Save an archetype's config; a 400 means it failed boundary parse. */
export async function setArchetypeConfig(
    transport: WorkbenchTransport,
    id: ArchetypeId,
    config: string,
): Promise<void> {
    const res = await request(transport, `/archetypes/${id}`, {
        method: "PUT",
        headers: { "content-type": "application/json", "idempotency-key": newIdempotencyKey() },
        body: JSON.stringify({ config }),
    });
    if (res.status === 400) throw new Error(`invalid config: ${await res.text()}`);
    if (!res.ok) throw new Error(`PUT archetype: ${res.status}`);
}

export async function getArchetypeAbilities(
    transport: WorkbenchTransport,
    id: ArchetypeId,
): Promise<AgentAbility[]> {
    const o = (await transport.json("GET", `/archetypes/${id}/abilities`)) as {
        abilities: AgentAbility[];
    };
    return o.abilities;
}

export async function setArchetypeAbilities(
    transport: WorkbenchTransport,
    id: ArchetypeId,
    abilities: AgentAbility[],
): Promise<void> {
    await transport.json("PUT", `/archetypes/${id}/abilities`, { abilities });
}

export async function getPlacementAbilities(
    transport: WorkbenchTransport,
    id: PlacementId,
): Promise<AgentAbility[]> {
    const o = (await transport.json("GET", `/placements/${id}/abilities`)) as {
        abilities: AgentAbility[];
    };
    return o.abilities;
}

export async function deleteArchetype(
    transport: WorkbenchTransport,
    id: ArchetypeId,
): Promise<void> {
    await transport.json("DELETE", `/archetypes/${id}`);
}

export async function forkArchetype(
    transport: WorkbenchTransport,
    id: ArchetypeId,
    name?: string,
): Promise<ArchetypeId> {
    const o = (await transport.json("POST", `/archetypes/${id}/fork`, name ? { name } : {})) as {
        id: string;
    };
    return o.id as ArchetypeId;
}

export async function pullFromSource(
    transport: WorkbenchTransport,
    id: ArchetypeId,
): Promise<void> {
    await transport.json("POST", `/archetypes/${id}/pull-from-source`, {});
}

export async function publishArchetype(
    transport: WorkbenchTransport,
    id: ArchetypeId,
    autoUpgrade?: boolean,
): Promise<{ version: number; autoUpgraded: number }> {
    const o = (await transport.json(
        "POST",
        `/archetypes/${id}/publish`,
        autoUpgrade === undefined ? {} : { auto_upgrade: autoUpgrade },
    )) as { version: number; auto_upgraded: number };
    return { version: o.version, autoUpgraded: o.auto_upgraded };
}

export async function upgradePlacement(
    transport: WorkbenchTransport,
    placementId: PlacementId,
): Promise<number> {
    const o = (await transport.json("POST", `/placements/${placementId}/upgrade`, {})) as { version: number };
    return o.version;
}

/** Accept a pending placement (APPROVE-1, ADR 0064): the owner's second act, flipping it
 *  Pending → Active so it can host work chats. */
export async function acceptPlacement(
    transport: WorkbenchTransport,
    placementId: PlacementId,
): Promise<void> {
    await transport.json("POST", `/placements/${placementId}/accept`, {});
}

export type DistributionProfile = "licensed" | "protected_commercial";

export interface PlacementDistributionStatus {
    readonly placement_id: string;
    readonly profile: DistributionProfile;
    readonly recipient_authority: string;
    readonly service_origin: string;
    readonly lease_seconds: number;
    readonly max_runs: number;
    readonly state: "licensed" | "awaiting_issue" | "issued" | "revoked";
    readonly license_id: string | null;
    readonly attribution_id: string | null;
    readonly expires_at: number | null;
}

export async function getPlacementDistribution(
    transport: WorkbenchTransport,
    placementId: PlacementId,
): Promise<PlacementDistributionStatus> {
    return await transport.json(
        "GET",
        `/placements/${placementId}/distribution`,
    ) as PlacementDistributionStatus;
}

export async function setPlacementDistribution(
    transport: WorkbenchTransport,
    placementId: PlacementId,
    input: {
        profile: DistributionProfile;
        recipient_authority?: string;
        lease_seconds?: number;
        max_runs?: number;
    },
): Promise<PlacementDistributionStatus> {
    return await transport.json(
        "PUT",
        `/placements/${placementId}/distribution`,
        input,
    ) as PlacementDistributionStatus;
}

export async function revokePlacementDistribution(
    transport: WorkbenchTransport,
    placementId: PlacementId,
): Promise<PlacementDistributionStatus> {
    return await transport.json(
        "POST",
        `/placements/${placementId}/distribution/revoke`,
        {},
    ) as PlacementDistributionStatus;
}

export async function renewPlacementDistribution(
    transport: WorkbenchTransport,
    placementId: PlacementId,
): Promise<PlacementDistributionStatus> {
    return await transport.json(
        "POST",
        `/placements/${placementId}/distribution/renew`,
        {},
    ) as PlacementDistributionStatus;
}

export async function getPlacementDistributionAudit(
    transport: WorkbenchTransport,
    placementId: PlacementId,
): Promise<{ events: readonly { action: string; at: number; uses: number; detail: string }[] }> {
    return await transport.json(
        "GET",
        `/placements/${placementId}/distribution/audit`,
    ) as { events: readonly { action: string; at: number; uses: number; detail: string }[] };
}

export async function getPlacementConfig(
    transport: WorkbenchTransport,
    placementId: PlacementId,
): Promise<{ config: string; notes: string }> {
    const s = (await transport.json("GET", `/placements/${placementId}`)) as {
        local_config?: string | null;
        notes?: string | null;
    };
    return { config: s.local_config ?? "", notes: s.notes ?? "" };
}

export async function setPlacementConfig(
    transport: WorkbenchTransport,
    placementId: PlacementId,
    config: string,
    notes: string,
): Promise<void> {
    await transport.json("POST", `/placements/${placementId}/command`, { SetLocalConfig: { config, notes } });
}

export async function forkChat(
    transport: WorkbenchTransport,
    id: EngagementId,
): Promise<EngagementId> {
    const o = (await transport.json("POST", `/chats/${id}/fork`, {})) as { id: string };
    return o.id as EngagementId;
}

export async function forkChatAt(
    transport: WorkbenchTransport,
    id: EngagementId,
    entryId: number,
): Promise<EngagementId> {
    const o = (await transport.json("POST", `/chats/${id}/fork/${entryId}`, {})) as { id: string };
    return o.id as EngagementId;
}

export async function revertChat(transport: WorkbenchTransport, id: EngagementId): Promise<void> {
    await transport.json("POST", `/chats/${id}/revert`, {});
}

export async function createProject(
    transport: WorkbenchTransport,
    name: string,
): Promise<ProjectId> {
    const o = (await transport.json("POST", "/projects", { name })) as { id: string };
    return o.id as ProjectId;
}

/** Attach an existing repository/folder without exposing its native path in
 * the returned target projection. */
export async function attachTarget(
    transport: WorkbenchTransport,
    projectId: ProjectId,
    name: string,
    kind: Exclude<WorkTargetKind, "managed">,
    path: string,
): Promise<WorkTargetNode> {
    return parseWorkTarget(await transport.json("POST", `/projects/${projectId}/targets`, {
        name,
        kind,
        path,
        path_scope: ["."],
    }));
}

export async function renameProject(
    transport: WorkbenchTransport,
    id: ProjectId,
    name: string,
): Promise<void> {
    await transport.json("PUT", `/projects/${id}`, { name });
}

export async function setProjectNetworkIsolated(
    transport: WorkbenchTransport,
    id: ProjectId,
    isolated: boolean,
): Promise<void> {
    await transport.json("PUT", `/projects/${id}`, { network_isolated: isolated });
}

export async function deleteProject(transport: WorkbenchTransport, id: ProjectId): Promise<void> {
    await transport.json("DELETE", `/projects/${id}`);
}

export async function projectHome(transport: WorkbenchTransport, id: ProjectId): Promise<ProjectHome> {
    return parseProjectHome(await transport.json("GET", `/projects/${id}/home`));
}

export async function placeArchetype(
    transport: WorkbenchTransport,
    pid: ProjectId,
    archetypeId: ArchetypeId,
    recipient?: CollectionRecipient,
): Promise<PlacementId> {
    const o = (await transport.json("POST", `/projects/${pid}/placements`, {
        agent_id: archetypeId,
        collection_recipient: recipient ? {
            recipient_ref: recipient.recipient_id,
            recipient_public_keys: [recipient.public_key_hex],
        } : undefined,
    })) as {
        instance_id: string;
    };
    return o.instance_id as PlacementId;
}

export async function publishDeployment(
    transport: WorkbenchTransport,
    input: PublicDeploymentInput,
): Promise<PublicDeploymentOutcome> {
    const response = (await transport.json(
        "POST",
        "/public-deployments",
        input,
    )) as { deployment?: PublicDeploymentOutcome };
    if (
        !response.deployment
        || typeof response.deployment.binding_id !== "string"
        || typeof response.deployment.project_id !== "string"
        || typeof response.deployment.placement_id !== "string"
        || typeof response.deployment.deployment_id !== "string"
        || typeof response.deployment.release_id !== "string"
        || typeof response.deployment.edge_origin !== "string"
        || typeof response.deployment.deployment_url !== "string"
        || typeof response.deployment.embed_html !== "string"
    ) {
        throw new Error("deployment publisher response is malformed");
    }
    return response.deployment;
}

export async function importLegacyDeployment(
    transport: WorkbenchTransport,
    input: PublicDeploymentInput,
): Promise<LegacyDeploymentImportOutcome> {
    const response = await transport.json("POST", "/public-deployments/import", {
        placement_id: input.placement_id,
        deployment_id: input.deployment_id,
        edge_origin: input.edge_origin,
    }) as LegacyDeploymentImportOutcome;
    if (
        typeof response.binding_id !== "string"
        || typeof response.project_id !== "string"
        || typeof response.deployment_id !== "string"
        || typeof response.active_release_id !== "string"
    ) throw new Error("legacy deployment import response is malformed");
    return response;
}

export async function inspectDeployment(
    transport: WorkbenchTransport,
    edgeOrigin: string,
    deploymentId: string,
): Promise<PublicDeploymentInspection> {
    const value = await transport.json("POST", "/public-deployments/inspect", {
        edge_origin: edgeOrigin,
        deployment_id: deploymentId,
    }) as PublicDeploymentInspection;
    if (
        !value.deployment
        || !["active", "paused", "revoked"].includes(value.deployment.lifecycle)
        || !Number.isSafeInteger(value.deployment.activation_revision)
        || !Array.isArray(value.audience)
    ) {
        throw new Error("deployment inspection response is malformed");
    }
    return value;
}

export async function controlDeployment(
    transport: WorkbenchTransport,
    edgeOrigin: string,
    deploymentId: string,
    command: "pause" | "resume" | "revoke",
    expectedRevision: number,
): Promise<PublicDeploymentInspection["deployment"]> {
    const value = await transport.json("POST", "/public-deployments/control", {
        edge_origin: edgeOrigin,
        deployment_id: deploymentId,
        command,
        expected_revision: expectedRevision,
    }) as { deployment?: PublicDeploymentInspection["deployment"] };
    if (!value.deployment) throw new Error("deployment control response is malformed");
    return value.deployment;
}

export async function erasePublicSession(
    transport: WorkbenchTransport,
    edgeOrigin: string,
    deploymentId: string,
    sessionId: string,
): Promise<void> {
    await transport.json("POST", "/public-deployments/erase-session", {
        edge_origin: edgeOrigin,
        deployment_id: deploymentId,
        session_id: sessionId,
    });
}

function parsePublicCredential(value: unknown): PublicCredentialMetadata {
    const credential = value as Partial<PublicCredentialMetadata>;
    if (
        !credential
        || typeof credential.credential_ref !== "string"
        || !["openai", "anthropic"].includes(String(credential.provider))
        || typeof credential.credential_class !== "string"
        || typeof credential.label !== "string"
        || !Number.isSafeInteger(credential.created_at_unix_ms)
    ) {
        throw new Error("public credential response is malformed");
    }
    return credential as PublicCredentialMetadata;
}

export async function listPublicCredentials(
    transport: WorkbenchTransport,
    edgeOrigin: string,
): Promise<PublicCredentialMetadata[]> {
    const value = await transport.json(
        "POST",
        "/public-deployments/credentials/list",
        { edge_origin: edgeOrigin },
    ) as { credentials?: unknown };
    if (!Array.isArray(value.credentials)) {
        throw new Error("public credential list is malformed");
    }
    return value.credentials.map(parsePublicCredential);
}

export async function provisionPublicCredential(
    transport: WorkbenchTransport,
    input: ProvisionPublicCredentialInput,
): Promise<PublicCredentialMetadata> {
    const value = await transport.json(
        "POST",
        "/public-deployments/credentials/provision",
        input,
    ) as { credential?: unknown };
    return parsePublicCredential(value.credential);
}

export async function revokePublicCredential(
    transport: WorkbenchTransport,
    edgeOrigin: string,
    credentialRef: string,
): Promise<void> {
    await transport.json("POST", "/public-deployments/credentials/revoke", {
        edge_origin: edgeOrigin,
        credential_ref: credentialRef,
    });
}

export async function removePlacement(
    transport: WorkbenchTransport,
    pid: ProjectId,
    placementId: PlacementId,
): Promise<void> {
    await transport.json("DELETE", `/projects/${pid}/placements/${placementId}`);
}

export async function createChatUnderArchetype(
    transport: WorkbenchTransport,
    archetypeId: ArchetypeId,
    title: string,
): Promise<EngagementId> {
    const o = (await transport.json("POST", `/archetypes/${archetypeId}/chats`, {
        title,
    })) as { id: string };
    return engagementId(o.id);
}

export async function useArchetype(
    transport: WorkbenchTransport,
    archetypeId: ArchetypeId,
    title: string,
): Promise<EngagementId> {
    const o = (await transport.json("POST", `/archetypes/${archetypeId}/use`, {
        title,
    })) as { id: string };
    return engagementId(o.id);
}

export async function createChatUnderPlacement(
    transport: WorkbenchTransport,
    pid: ProjectId,
    placementId: PlacementId,
    title: string,
    targetId: WorkTargetId,
): Promise<EngagementId> {
    const o = (await transport.json("POST", `/projects/${pid}/placements/${placementId}/chats`, {
        title,
        target_id: targetId,
    })) as { id: string };
    return engagementId(o.id);
}

export async function renameChat(
    transport: WorkbenchTransport,
    id: EngagementId,
    title: string,
): Promise<void> {
    await transport.json("PUT", `/chats/${id}/title`, { title });
}

export async function deleteChat(transport: WorkbenchTransport, id: EngagementId): Promise<void> {
    await transport.json("DELETE", `/chats/${id}`);
}

export async function engagementDiff(transport: WorkbenchTransport, id: EngagementId): Promise<string> {
    const o = (await transport.json("GET", `/chats/${id}/diff`)) as { diff: string };
    return o.diff;
}

export async function submitRunCommand(
    transport: WorkbenchTransport,
    scope: ScopeId,
    command: RunCommand,
): Promise<RunState> {
    return parseRunState(await transport.json("POST", `/scopes/${scope}/run/command`, command));
}

export async function createEngagement(
    transport: WorkbenchTransport,
    id?: EngagementId,
): Promise<Engagement> {
    const o = (await transport.json("POST", "/chats", id ? { id } : {})) as {
        id: string;
        branch: string;
        path: string;
    };
    return { id: engagementId(o.id), branch: o.branch, path: o.path };
}

/** Run one turn.
 *
 *  `composedId` is the outbox id the message was composed under (ADR 0137 §3).
 *  Passing it makes the turn idempotent under the composed identity rather than
 *  under a key minted per attempt: a client that dies between handing the
 *  message to the transport and hearing back can resend it and be told the turn
 *  already ran, instead of having to choose between losing the message and
 *  running it twice. Omitting it keeps the old behaviour — a fresh key per
 *  attempt, so every send is a distinct command. */
export async function runTask(
    transport: WorkbenchTransport,
    id: EngagementId,
    prompt: string,
    images: { data: string; mimeType: string }[] = [],
    composedId?: string,
): Promise<unknown> {
    const body = {
        prompt,
        ...(images.length ? { images } : {}),
    };
    return transport.json(
        "POST",
        `/chats/${id}/task`,
        body,
        composedId ? { idempotencyKey: composedId } : undefined,
    );
}

/** What Stop actually did. `stopped: false` is a refusal, not a quiet success:
 *  either nothing was running or the running turn carries no interrupt handle.
 *  Callers must say which — a Stop that reports nothing is the one failure a
 *  person cannot tell apart from the turn simply continuing. */
export interface StopTurnResult {
    readonly stopped: boolean;
    readonly reason?: string;
}

export async function stopTurn(
    transport: WorkbenchTransport,
    id: EngagementId,
): Promise<StopTurnResult> {
    return (await transport.json("POST", `/chats/${id}/stop`)) as StopTurnResult;
}

export async function syncFromMain(
    transport: WorkbenchTransport,
    id: EngagementId,
): Promise<{ synced: boolean; conflict: boolean }> {
    return (await transport.json("POST", `/chats/${id}/sync`)) as { synced: boolean; conflict: boolean };
}

export async function createWorkstream(
    transport: WorkbenchTransport,
    placementId: PlacementId,
    name: string,
    targetId: WorkTargetId,
): Promise<WorkstreamNode> {
    const o = (await transport.json("POST", `/placements/${placementId}/workstreams`, {
        name,
        target_id: targetId,
    })) as {
        id: string;
        name: string;
        placement_id: string;
        workspace_root: string;
        target_id: string;
        status?: string;
        members?: string[];
    };
    return parseWorkstream(o);
}

export async function listWorkstreams(
    transport: WorkbenchTransport,
    placementId: PlacementId,
): Promise<WorkstreamNode[]> {
    const o = (await transport.json("GET", `/placements/${placementId}/workstreams`)) as {
        workstreams?: { id: string; name: string; placement_id: string; workspace_root: string; target_id: string; status?: string; members?: string[] }[];
    };
    return (o.workstreams ?? []).map(parseWorkstream);
}

export async function joinWorkstream(
    transport: WorkbenchTransport,
    ws: WorkstreamId,
    chat: EngagementId,
): Promise<void> {
    await transport.json("POST", `/workstreams/${ws}/join`, { chat });
}

export async function leaveWorkstream(
    transport: WorkbenchTransport,
    ws: WorkstreamId,
    chat: EngagementId,
): Promise<void> {
    await transport.json("POST", `/workstreams/${ws}/leave`, { chat });
}

export async function archiveWorkstream(
    transport: WorkbenchTransport,
    ws: WorkstreamId,
): Promise<void> {
    await transport.json("POST", `/workstreams/${ws}/archive`);
}

export async function promoteWorkstream(
    transport: WorkbenchTransport,
    ws: WorkstreamId,
): Promise<void> {
    await transport.json("POST", `/workstreams/${ws}/promote`);
}

export async function getMerge(transport: WorkbenchTransport, id: EngagementId): Promise<MergeState> {
    return parseMergeState(await transport.json("GET", `/chats/${id}/merge`));
}

export async function getMergeCarriage(
    transport: WorkbenchTransport,
    id: EngagementId,
): Promise<ProjectionCarriage<MergeState>> {
    const raw = (await transport.json("GET", `/projections/${id}/merge?freshness=live`)) as {
        value: unknown;
        freshness: { marker?: unknown; generated_at?: unknown; repair_hint?: unknown };
        client_request_id?: unknown;
    };
    return parseProjectionCarriage(raw, (v) => parseMergeState(v));
}

export async function mergeCommand(
    transport: WorkbenchTransport,
    id: EngagementId,
    action: MergeAction,
): Promise<MergeState> {
    return parseMergeState(await transport.json("POST", `/chats/${id}/merge/command`, { action }));
}

export function subscribe(
    transport: WorkbenchTransport,
    id: EngagementId,
    onEvent: (ev: StreamEvent) => void,
    onOpen?: () => void,
): () => void {
    if (transport.events) {
        return transport.events(
            `/chats/${id}/events`,
            (data) => {
                try {
                    onEvent(JSON.parse(data) as StreamEvent);
                } catch {
                    /* ignore malformed frames */
                }
            },
            onOpen,
        );
    }
    // `withCredentials` sends the shared `.gaugewright.com` session cookie on the cross-origin
    // stream (the Console → hub), so SSE authenticates like the fetch routes (ADR 0077).
    const es = new EventSource(`${transport.base}/chats/${id}/events`, { withCredentials: true });
    if (onOpen) es.onopen = onOpen;
    es.onmessage = (m) => {
        try {
            onEvent(JSON.parse(m.data) as StreamEvent);
        } catch {
            /* ignore malformed frames */
        }
    };
    return () => es.close();
}

export function subscribeWorkspace(
    transport: WorkbenchTransport,
    onChange: (change: WorkspaceChange) => void,
): () => void {
    const accept = (data: string) => {
        try {
            const ev = JSON.parse(data) as {
                type?: string;
                record?: string;
                id?: string;
                op?: string;
            };
            if (ev.type === "workspacechanged" && isWorkspaceRecord(ev.record)) {
                onChange({
                    record: ev.record,
                    id: ev.id ?? "",
                    op: ev.op === "tombstone" ? "tombstone" : "upsert",
                });
            }
        } catch {
            /* ignore malformed frames */
        }
    };
    if (transport.events) return transport.events("/workspace/events", accept);
    const es = new EventSource(`${transport.base}/workspace/events`, { withCredentials: true });
    es.onmessage = (m) => accept(m.data);
    return () => es.close();
}

export async function getResourceReview(
    transport: WorkbenchTransport,
    id: EngagementId,
    resource: string,
): Promise<ReviewState> {
    return parseReviewState(
        await transport.json("GET", `/chats/${id}/resources/${encodeURIComponent(resource)}/review`),
    );
}

export async function resourceReviewCommand(
    transport: WorkbenchTransport,
    id: EngagementId,
    resource: string,
    action: ResourceReviewAction,
    idempotencyKey = newIdempotencyKey(),
): Promise<ReviewState> {
    return parseReviewState(
        await transport.json(
            "POST",
            `/chats/${id}/resources/${encodeURIComponent(resource)}/review/command`,
            { action },
            { idempotencyKey },
        ),
    );
}

export async function getResourceExport(
    transport: WorkbenchTransport,
    id: EngagementId,
    resource: string,
): Promise<ExportState> {
    return parseExportState(
        await transport.json("GET", `/chats/${id}/resources/${encodeURIComponent(resource)}/export`),
    );
}

export async function resourceExportCommand(
    transport: WorkbenchTransport,
    id: EngagementId,
    resource: string,
    action: ResourceExportAction,
    idempotencyKey = newIdempotencyKey(),
): Promise<ExportState> {
    return parseExportState(
        await transport.json(
            "POST",
            `/chats/${id}/resources/${encodeURIComponent(resource)}/export/command`,
            { action },
            { idempotencyKey },
        ),
    );
}

export async function getAudit(transport: WorkbenchTransport, scope: ScopeId): Promise<AuditEvent[]> {
    const o = (await transport.json("GET", `/scopes/${scope}/audit`)) as { events?: unknown };
    return (Array.isArray(o.events) ? o.events : []).map(parseAuditEvent);
}

export async function getChatGovernanceAudit(
    transport: WorkbenchTransport,
    id: EngagementId,
): Promise<unknown[]> {
    const value = await transport.json("GET", `/chats/${id}/audit`);
    if (!Array.isArray(value)) throw new Error("chat governance audit must be an array");
    return value;
}

export async function getTargetActs(
    transport: WorkbenchTransport,
    target: WorkTargetId,
): Promise<unknown[]> {
    const value = (await transport.json("GET", `/targets/${target}/acts`)) as {
        acts?: unknown;
    };
    if (!Array.isArray(value.acts)) throw new Error("target acts must be an array");
    return value.acts;
}

export async function publishTarget(
    transport: WorkbenchTransport,
    chat: EngagementId,
): Promise<void> {
    const value = (await transport.json(
        "POST",
        `/chats/${chat}/target-acts/publish`,
        {},
    )) as { published?: unknown };
    if (value.published !== true) throw new Error("target publish was not completed");
}

export async function getResources(
    transport: WorkbenchTransport,
    id: EngagementId,
): Promise<ResourceView[]> {
    const o = (await transport.json("GET", `/chats/${id}/resources`)) as unknown[];
    return (Array.isArray(o) ? o : []).map(parseResourceView);
}

function parseResourceAccess(raw: unknown): AccessPhase {
    return parseAccessPhase((raw as { phase?: unknown } | null)?.phase);
}

export async function getResourceContent(
    transport: WorkbenchTransport,
    id: EngagementId,
    resource: string,
    path?: string,
): Promise<string> {
    const query = path === undefined ? "" : `?path=${encodeURIComponent(path)}`;
    const response = await request(
        transport,
        `/chats/${id}/resources/${encodeURIComponent(resource)}/content${query}`,
    );
    if (!response.ok) throw new Error(`GET resource content: ${response.status}`);
    return response.text();
}

export async function getResourceAccess(
    transport: WorkbenchTransport,
    id: EngagementId,
    resource: string,
): Promise<AccessPhase> {
    return parseResourceAccess(
        await transport.json(
            "GET",
            `/chats/${id}/resources/${encodeURIComponent(resource)}/access`,
        ),
    );
}

export async function requestResourceAccess(
    transport: WorkbenchTransport,
    id: EngagementId,
    resource: string,
): Promise<AccessPhase> {
    return parseResourceAccess(
        await transport.json(
            "POST",
            `/chats/${id}/resources/${encodeURIComponent(resource)}/access/request`,
            {},
        ),
    );
}

export async function approveResourceAccess(
    transport: WorkbenchTransport,
    id: EngagementId,
    resource: string,
): Promise<AccessPhase> {
    return parseResourceAccess(
        await transport.json(
            "POST",
            `/chats/${id}/resources/${encodeURIComponent(resource)}/access/approve`,
            {},
        ),
    );
}

export async function revokeResourceAccess(
    transport: WorkbenchTransport,
    id: EngagementId,
    resource: string,
): Promise<AccessPhase> {
    return parseResourceAccess(
        await transport.json(
            "POST",
            `/chats/${id}/resources/${encodeURIComponent(resource)}/access/revoke`,
            {},
        ),
    );
}

export async function proposeResourceReview(
    transport: WorkbenchTransport,
    id: EngagementId,
    resource: string,
): Promise<{ scope: string; state: ReviewState }> {
    const raw = (await transport.json(
        "POST",
        `/chats/${id}/resources/${encodeURIComponent(resource)}/review`,
        {},
    )) as { scope?: unknown; state?: unknown };
    if (typeof raw.scope !== "string") throw new Error("resource review: missing scope");
    return { scope: raw.scope, state: parseReviewState(raw.state) };
}

export async function proposeResourceExport(
    transport: WorkbenchTransport,
    id: EngagementId,
    resource: string,
): Promise<{ scope: string; state: ExportState }> {
    const raw = (await transport.json(
        "POST",
        `/chats/${id}/resources/${encodeURIComponent(resource)}/export`,
        {},
    )) as { scope?: unknown; state?: unknown };
    if (typeof raw.scope !== "string") throw new Error("resource export: missing scope");
    return { scope: raw.scope, state: parseExportState(raw.state) };
}

/** Materialize an already-admitted resource export into a desktop directory.
 * This route is intentionally available only on the local control plane; the
 * enterprise server rejects it because its filesystem is not the user's endpoint. */
export async function exportResourceToDisk(
    transport: WorkbenchTransport,
    id: EngagementId,
    resource: string,
    dest: string,
    path?: string,
): Promise<{ exported: string[]; dest: string }> {
    const raw = (await transport.json(
        "POST",
        `/chats/${id}/resources/${encodeURIComponent(resource)}/export-to-disk`,
        { dest, ...(path === undefined ? {} : { path }) },
    )) as { exported?: unknown; dest?: unknown };
    if (!Array.isArray(raw.exported) || !raw.exported.every((item) => typeof item === "string")) {
        throw new Error("resource export-to-disk: malformed exported files");
    }
    if (typeof raw.dest !== "string") {
        throw new Error("resource export-to-disk: malformed destination");
    }
    return { exported: raw.exported, dest: raw.dest };
}

export async function tombstoneResource(
    transport: WorkbenchTransport,
    id: EngagementId,
    resource: string,
): Promise<void> {
    await transport.json(
        "POST",
        `/chats/${id}/resources/${encodeURIComponent(resource)}/tombstone`,
        {},
    );
}

export async function getTranscript(
    transport: WorkbenchTransport,
    id: EngagementId,
): Promise<StreamEvent[]> {
    return (await transport.json("GET", `/chats/${id}/transcript`)) as StreamEvent[];
}

/** The chat's latest settled context-window reading (the composer's meter):
 *  the runtime's own compaction-trigger number against the window of the model
 *  that read it. `null` until a turn on a reporting runtime settles — the
 *  meter is honestly absent rather than estimated. */
export interface ChatContextUsage {
    readonly used_tokens: number;
    readonly window_tokens: number;
    readonly provider: string;
    readonly model: string;
}

export async function getContextUsage(
    transport: WorkbenchTransport,
    id: EngagementId,
): Promise<ChatContextUsage | null> {
    return (await transport.json("GET", `/chats/${id}/context-usage`)) as ChatContextUsage | null;
}

export async function getTree(transport: WorkbenchTransport, id: EngagementId): Promise<FileEntry[]> {
    const o = (await transport.json("GET", `/chats/${id}/tree`)) as {
        files: { path: string; is_dir: boolean }[];
    };
    return o.files.map((f) => ({ path: f.path, isDir: f.is_dir }));
}

export async function getFile(
    transport: WorkbenchTransport,
    id: EngagementId,
    path: string,
): Promise<string> {
    const res = await request(transport, `/chats/${id}/file?path=${encodeURIComponent(path)}`);
    if (!res.ok) throw new Error(`read ${path}: ${res.status}`);
    return res.text();
}

/**
 * `getFile`, also reading the `x-workspace-cut` header — the recorded state
 * this read serves (SUB-6 §12). A cut-carrying save sends it back as the
 * three-way base; `cut` is null against servers that predate it.
 */
export async function getFileWithCut(
    transport: WorkbenchTransport,
    id: EngagementId,
    path: string,
): Promise<{ content: string; cut: string | null }> {
    const res = await request(transport, `/chats/${id}/file?path=${encodeURIComponent(path)}`);
    if (!res.ok) throw new Error(`read ${path}: ${res.status}`);
    return { content: await res.text(), cut: res.headers.get("x-workspace-cut") };
}

export async function putFile(
    transport: WorkbenchTransport,
    id: EngagementId,
    path: string,
    content: string,
): Promise<void> {
    const res = await request(transport, `/chats/${id}/file?path=${encodeURIComponent(path)}`, {
        method: "PUT",
        headers: { "idempotency-key": newIdempotencyKey() },
        body: content,
    });
    if (!res.ok) throw new Error(`write ${path}: ${res.status}`);
}

/** One span of a merged/conflicted save (whip's text-merge piece surface). */
export type MergePiece =
    | { kind: "merged"; text: string; provenance: "base" | "ours" | "theirs" | "both" | "resolved" }
    | { kind: "conflict"; base_text: string; ours_text: string; theirs_text: string };

/** One fold-settled region riding a resolve re-save (§12.2): the exact
 *  three texts the user saw plus the text they chose or authored. The
 *  server records it as durable region-resolution memory. */
export interface RegionResolution {
    base_text: string;
    ours_text: string;
    theirs_text: string;
    resolution_text: string;
}

/** The editor's save base: the cut it loaded (preferred; the GET header),
 *  or the content it loaded (pre-cut fallback, resolved server-side). */
export type SaveBase = { cut: string } | { content: string };

export type SaveFileResult =
    | { kind: "saved"; cut: string | null }
    | { kind: "merged"; cut: string | null; content: string; pieces: MergePiece[] }
    | { kind: "conflict"; current: string; currentCut: string | null; pieces: MergePiece[] };

/**
 * Base-carrying save (SUB-6): `base` names the state the editor loaded.
 * Concurrent changes merge through whip's token-level engine server-side
 * (region memory applies); a real divergence resolves to `conflict` with
 * the structured regions and the file's current body + cut (the re-save
 * base) — nothing written. `resolutions` are fold-settled regions riding
 * a resolve re-save: they mint durable memory that pays forward.
 */
/** The JSON body a base-carrying save PUTs (shared by every transport). */
export function saveFileBody(
    content: string,
    base: SaveBase,
    resolutions: RegionResolution[] = [],
): string {
    const body: Record<string, unknown> = { content };
    if ("cut" in base) body.base_cut = base.cut;
    else body.base_content = base.content;
    if (resolutions.length) body.resolutions = resolutions;
    return JSON.stringify(body);
}

/** Decode a base-carrying save response (200 or 409) — shared by every
 *  transport so desktop, embed, and remote agree on the wire shape. */
export function decodeSaveFileResponse(status: number, payload: unknown): SaveFileResult {
    if (status === 409) {
        const conflict = payload as {
            current: string;
            current_cut?: string | null;
            pieces: MergePiece[];
        };
        return {
            kind: "conflict",
            current: conflict.current,
            currentCut: conflict.current_cut ?? null,
            pieces: conflict.pieces,
        };
    }
    const saved = payload as {
        merged?: boolean;
        cut?: string | null;
        content?: string;
        pieces?: MergePiece[];
    };
    if (saved.merged && typeof saved.content === "string") {
        return {
            kind: "merged",
            cut: saved.cut ?? null,
            content: saved.content,
            pieces: saved.pieces ?? [],
        };
    }
    return { kind: "saved", cut: saved.cut ?? null };
}

export async function saveFile(
    transport: WorkbenchTransport,
    id: EngagementId,
    path: string,
    content: string,
    base: SaveBase,
    resolutions: RegionResolution[] = [],
): Promise<SaveFileResult> {
    const res = await request(transport, `/chats/${id}/file?path=${encodeURIComponent(path)}`, {
        method: "PUT",
        headers: { "content-type": "application/json", "idempotency-key": newIdempotencyKey() },
        body: saveFileBody(content, base, resolutions),
    });
    if (!res.ok && res.status !== 409) throw new Error(`write ${path}: ${res.status}`);
    return decodeSaveFileResponse(res.status, await res.json());
}

/** The read-only preview of a base-carrying save (the live fold, §12.3). */
export type MergePreviewResult =
    | { knownBase: false }
    | {
          knownBase: true;
          clean: boolean;
          merged: string | null;
          currentCut: string | null;
          pieces: MergePiece[];
      };

/**
 * What WOULD this draft do against the file as it stands? Nothing moves;
 * region memory applies exactly as a save would apply it. `knownBase:
 * false` means the base cut isn't recorded there (stale tab — reload).
 */
/** Decode a merge-preview response — shared by every transport. */
export function decodePreviewResponse(payload: unknown): MergePreviewResult {
    const preview = payload as {
        known_base: boolean;
        clean?: boolean;
        merged?: string | null;
        current_cut?: string | null;
        pieces?: MergePiece[];
    };
    if (!preview.known_base) return { knownBase: false };
    return {
        knownBase: true,
        clean: preview.clean ?? false,
        merged: preview.merged ?? null,
        currentCut: preview.current_cut ?? null,
        pieces: preview.pieces ?? [],
    };
}

export async function previewMerge(
    transport: WorkbenchTransport,
    id: EngagementId,
    path: string,
    draft: string,
    baseCut: string,
): Promise<MergePreviewResult> {
    const res = await request(transport, `/chats/${id}/merge-preview`, {
        method: "POST",
        headers: { "content-type": "application/json", "idempotency-key": newIdempotencyKey() },
        body: JSON.stringify({ path, draft, base_cut: baseCut }),
    });
    if (!res.ok) throw new Error(`preview ${path}: ${res.status}`);
    return decodePreviewResponse(await res.json());
}

export async function getConfig(transport: WorkbenchTransport, id: EngagementId): Promise<string> {
    const res = await request(transport, `/chats/${id}/config`);
    if (!res.ok) throw new Error(`GET config: ${res.status}`);
    return res.text();
}

export async function putConfig(
    transport: WorkbenchTransport,
    id: EngagementId,
    raw: string,
): Promise<void> {
    const res = await request(transport, `/chats/${id}/config`, {
        method: "PUT",
        headers: { "content-type": "application/json", "idempotency-key": newIdempotencyKey() },
        body: raw,
    });
    if (res.status === 400) throw new Error(`invalid config: ${await res.text()}`);
    if (!res.ok) throw new Error(`PUT config: ${res.status}`);
}

export async function ingestContext(
    transport: WorkbenchTransport,
    id: EngagementId,
    path: string,
): Promise<number> {
    const o = (await transport.json("POST", `/chats/${id}/context`, { path })) as {
        ingested: number;
    };
    return o.ingested;
}

/** One uploaded context file: a name and its text content (`ENTSEC-5`). */
export interface UploadContextFile {
    name: string;
    content: string;
}

/**
 * Upload context from the client's own files rather than a server-local path
 * (`POST /chats/:id/context/upload`, `ENTSEC-5`). This is the browser's path-free
 * ingest: a native picker hands us `File`s, we read their text and upload it —
 * no absolute filesystem path (which browsers hide) is involved. Works in both
 * solo and enterprise modes; enterprise *requires* it, since the server-path
 * ingest is disabled there.
 */
export async function ingestContextUpload(
    transport: WorkbenchTransport,
    id: EngagementId,
    files: UploadContextFile[],
): Promise<number> {
    const o = (await transport.json("POST", `/chats/${id}/context/upload`, { files })) as {
        ingested: number;
    };
    return o.ingested;
}

export async function openPairing(
    transport: WorkbenchTransport,
    device: string,
    bridgeGrant: string | null,
): Promise<{ pairingId: string; bridgeGrant: string }> {
    const o = (await transport.json("POST", "/pairing-requests", {
        device,
        bridge_grant: bridgeGrant,
    })) as { pairing_id?: unknown; bridge_grant?: unknown };
    if (typeof o.pairing_id !== "string") throw new Error("pairing-requests: missing pairing_id");
    return {
        pairingId: o.pairing_id,
        bridgeGrant: typeof o.bridge_grant === "string" ? o.bridge_grant : "",
    };
}

export async function acceptBoundary(
    transport: WorkbenchTransport,
    boundaryId: string,
    participant: string,
): Promise<void> {
    await transport.json("POST", `/boundaries/${boundaryId}/accept`, { participant });
}

export async function pairingStatus(
    transport: WorkbenchTransport,
    boundaryId: string,
): Promise<unknown> {
    return transport.json("GET", `/pairing-status/${boundaryId}`);
}

/** One quarantined inbound item, as the review surface shows it (ADR 0110 §7). */
export interface QuarantinedItem {
    readonly item_id: string;
    readonly source_id: string;
    readonly schema_ref: string;
    readonly byte_len: number;
    readonly arrived_at_unix_ms: number;
    readonly status: "Pending" | "Approved" | "Rejected";
    readonly workspace_path?: string | null;
}

/** Normalize the authoritative Rust lifecycle shape at the transport boundary.
 *
 * `ItemStatus` is an internally tagged enum (`{ state: "approved",
 * workspace_path: "…" }`). The review UI deliberately consumes a small stable
 * projection instead of depending on serde's wire representation. Keeping this
 * parser here also prevents an unknown server state from being rendered as a
 * pending item with active verdict buttons.
 */
export function parseQuarantinedItem(value: unknown): QuarantinedItem {
    const item = (value ?? {}) as Record<string, unknown>;
    const lifecycle = (item.status ?? {}) as Record<string, unknown>;
    const state = lifecycle.state;
    const status = state === "pending"
        ? "Pending"
        : state === "approved"
        ? "Approved"
        : state === "rejected"
        ? "Rejected"
        : null;
    if (
        typeof item.item_id !== "string"
        || typeof item.source_id !== "string"
        || typeof item.schema_ref !== "string"
        || typeof item.byte_len !== "number"
        || !Number.isFinite(item.byte_len)
        || typeof item.arrived_at_unix_ms !== "number"
        || !Number.isFinite(item.arrived_at_unix_ms)
        || status === null
    ) {
        throw new Error("quarantine item was malformed");
    }
    const workspacePath = lifecycle.workspace_path;
    if (workspacePath !== undefined && workspacePath !== null && typeof workspacePath !== "string") {
        throw new Error("quarantine item workspace path was malformed");
    }
    return {
        item_id: item.item_id,
        source_id: item.source_id,
        schema_ref: item.schema_ref,
        byte_len: Math.max(0, Math.floor(item.byte_len)),
        arrived_at_unix_ms: Math.max(0, Math.floor(item.arrived_at_unix_ms)),
        status,
        workspace_path: typeof workspacePath === "string" ? workspacePath : null,
    };
}

/** A project's quarantine index: provenance only, never payload.
 *
 *  `pending` is the store's count of unruled items. It is deliberately *not* the
 *  top bar's number, which counts what the gate parked on a **person** — an item
 *  still being screened is pending here and is not yet anyone's work
 *  (ADR 0117 §5). */
export interface QuarantineIndex {
    readonly project_id: string;
    readonly pending: number;
    readonly items: readonly QuarantinedItem[];
}

export async function listQuarantine(
    transport: WorkbenchTransport,
    project: string,
): Promise<QuarantineIndex> {
    const o = (await transport.json(
        "GET",
        `/projects/${encodeURIComponent(project)}/quarantine`,
    )) as { project_id?: unknown; pending?: unknown; items?: unknown };
    if (
        typeof o.project_id !== "string"
        || typeof o.pending !== "number"
        || !Number.isFinite(o.pending)
        || !Array.isArray(o.items)
    ) {
        throw new Error("quarantine index was malformed");
    }
    return {
        project_id: o.project_id,
        pending: Math.max(0, Math.floor(o.pending)),
        items: o.items.map(parseQuarantinedItem),
    };
}

/** One item's bytes, for a person to read. Never an agent's path: no file store
 *  root resolves into quarantine (ADR 0110 §1), and this route is the reviewer's. */
export async function readQuarantinedItem(
    transport: WorkbenchTransport,
    project: string,
    item: string,
): Promise<string> {
    // Read as text, not parsed JSON: a reviewer needs the exact bytes an agent
    // would get, not a re-serialization of them. Round-tripping through
    // parse/stringify is how a reviewer approves something subtly different from
    // what they read.
    const res = await request(
        transport,
        `/projects/${encodeURIComponent(project)}/quarantine/${encodeURIComponent(item)}`,
    );
    if (!res.ok) throw new Error(`quarantined item unavailable (${res.status})`);
    return res.text();
}

/** Start the project's installed gate over one quarantined item.
 *
 * This is deliberately separate from review: the first pass may settle the
 * item or park a question on a person. Sending a human verdict before this
 * call creates no vouched queue and therefore cannot settle anything.
 */
export async function screenQuarantinedItem(
    transport: WorkbenchTransport,
    project: string,
    item: string,
): Promise<{ workspacePath: string | null; parked: boolean }> {
    const o = (await transport.json(
        "POST",
        `/projects/${encodeURIComponent(project)}/quarantine/${encodeURIComponent(item)}/screen`,
        {},
    )) as { workspace_path?: unknown; parked?: unknown };
    if (typeof o.parked !== "boolean") {
        throw new Error("quarantine screening result was malformed");
    }
    return {
        workspacePath: typeof o.workspace_path === "string" ? o.workspace_path : null,
        parked: o.parked,
    };
}

/** A reviewer's verdict on one item. The route hands it to the project's gate,
 *  which is the only producer of a verdict (ADR 0117 §1) — this client never
 *  decides, it carries the answer. */
export async function reviewQuarantinedItem(
    transport: WorkbenchTransport,
    project: string,
    item: string,
    verdict: "keep" | "flag",
): Promise<{ workspacePath: string | null }> {
    // The gate may rule or may park, and the caller has to be able to tell.
    // Discarding this made a parked gate indistinguishable from an approval in
    // the one surface a person uses.
    const o = (await transport.json(
        "POST",
        `/projects/${encodeURIComponent(project)}/quarantine/${encodeURIComponent(item)}/review`,
        { verdict },
    )) as { workspace_path?: unknown };
    return {
        workspacePath: typeof o.workspace_path === "string" ? o.workspace_path : null,
    };
}

/** The collection recipient keyrings this Home holds (ADR 0109 §7). */
export async function listCollectionRecipients(
    transport: WorkbenchTransport,
): Promise<CollectionRecipient[]> {
    const o = (await transport.json("GET", "/collection-recipients")) as {
        recipients?: CollectionRecipient[];
    };
    return o.recipients ?? [];
}

/** Load or create a keyring, returning its publishable half.
 *
 *  Idempotent: republishing must reuse the same keyring, because artifacts
 *  already sealed to a previous one would otherwise never open again. */
export async function ensureCollectionRecipient(
    transport: WorkbenchTransport,
    recipientId: string,
): Promise<CollectionRecipient> {
    return (await transport.json("POST", "/collection-recipients", {
        recipient_id: recipientId,
    })) as CollectionRecipient;
}

/** Drain a deployment's waiting collections into a project's quarantine.
 *
 *  Where this surface ends (ADR 0110): what arrives is quarantined, reachable by
 *  no agent, and enters the workspace only through the project's gate. The reply
 *  is a count and the item ids, never payload. */
export async function drainCollections(
    transport: WorkbenchTransport,
    input: {
        readonly binding_id: string;
    },
): Promise<{ landed: readonly string[]; refused: readonly unknown[] }> {
    const o = (await transport.json("POST", "/public-deployments/collect", input)) as {
        collected?: { landed?: string[]; refused?: unknown[] };
    };
    return {
        landed: o.collected?.landed ?? [],
        refused: o.collected?.refused ?? [],
    };
}
