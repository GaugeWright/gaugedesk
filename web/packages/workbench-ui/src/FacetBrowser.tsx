/**
 * The facet browser (`navigation.md` B2, ADR 0035/0036): the nav is
 * **project-first** — facets **Recent | Projects | Workshop**, defaulting to
 * Projects. It renders a projection (`GET /workspace`) and submits commands; it
 * never owns truth (`INV-5`).
 *
 * The model (ADR 0035): an **archetype** is the reusable, named behaviour shown
 * in the Workshop (the UI calls it an "Agent" throughout); a
 * **placement** is an archetype installed on a **project** (Projects) — what you
 * chat with to do work. A chat's **kind** is its ROOT, fixed at creation: rooted
 * on an archetype ⇒ an **edit** chat; rooted on a placement ⇒ a **work** chat.
 * There is no mode toggle. The default "Personal" project is explicit (ADR 0097).
 *
 * The archetype↔placement relation is many-to-many and navigable **both ways**
 * (the C1 pivot): a placement shows its archetype's name as lineage, and an
 * archetype lists everywhere it is placed.
 */

import { createEffect, createMemo, createResource, createSignal, For, onCleanup, Show } from "solid-js";
import { createStore, reconcile } from "solid-js/store";
import { LoadError } from "./LoadError";
import { navLoadState } from "./nav-load-state";
import {
    Rejected,
    type AgentKind,
    type ArchetypeId,
    type Engagement,
    type EngagementId,
    type PlacementId,
    type ProjectId,
    type SearchHit,
    type Workspace,
    type WorkspaceChange,
    type WorkspaceDelta,
    type WorkspaceRootId,
    type WorkTargetId,
    type WorkTargetNode,
    type WorkstreamId,
    type WorkstreamNode,
    applyWorkspaceDelta,
} from "@gaugewright/control-plane-client";
import type { ProjectionCarriage } from "@gaugewright/control-plane-client";
import { ContextMenu, type MenuState } from "./ContextMenu";
import { displayChatTitle, untitledTag } from "./chat-title";
import { type ChatRunTone } from "./chat-run-state";
import { StatusGem } from "./StatusGem";
import { forkSource } from "./fork-lineage";
import { groupChatsByWorkstream } from "./workstream-grouping";
import { Icon, type IconName } from "./icons";
import { canTransferToMain, canTransferToWorkstream } from "./workstream-transfer";
import {
    archetypeVisible,
    childrenFor,
    markMatch,
    placementVisible,
    projectVisible,
    recentLineage,
    recentVisible,
    searching as isSearching,
} from "./facet-filter";

type Facet = "recent" | "projects" | "library";

/** Project child grouping: `chats` is flat/current-first; `archetype` shows
 *  Agent placements. The Projects filter applies one lens across its tree. */
type ProjectLens = "chats" | "archetype";
type ProjectStatus = "active" | "archived" | "all";
const GROUPING_KEY = "ui.projectsGrouping";
const STATUS_KEY = "ui.projectsStatus";

function readStoredChoice<T extends string>(key: string, allowed: readonly T[], fallback: T): T {
    try {
        const value = window.localStorage?.getItem(key);
        return allowed.find((choice) => choice === value) ?? fallback;
    } catch {
        return fallback;
    }
}

type DraggableChat = {
    id: EngagementId;
    title: string;
    workspaceRoot: WorkspaceRootId;
    workstream?: WorkstreamId | null;
    rehomeBlocked: boolean;
};

/** Plain-language blast radius for deleting a non-empty project (round-6 #6):
 *  state what else goes before the confirming click, instead of a blind "delete". */
function projectBlastRadius(p: { placements: { chats: unknown[] }[] }): string | undefined {
    const methods = p.placements.length;
    const chats = p.placements.reduce((n, pl) => n + pl.chats.length, 0);
    if (methods === 0 && chats === 0) return undefined; // empty project — no warning needed
    const parts: string[] = [];
    if (methods > 0) parts.push(`${methods} Agent placement${methods === 1 ? "" : "s"}`);
    if (chats > 0) parts.push(`${chats} chat${chats === 1 ? "" : "s"}`);
    return `also removes ${parts.join(" and ")} — this can't be undone`;
}

const FACETS: { id: Facet; label: string }[] = [
    { id: "recent", label: "Recent" },
    { id: "projects", label: "Projects" },
    { id: "library", label: "Workshop" },
];

function AgentKindMark(props: { kind: AgentKind; settings?: boolean }) {
    const label = () => props.kind === "panel" ? "Panel agent" : "Agent";
    return (
        <span class="agent-kind-mark" data-agent-kind={props.kind} title={label()} aria-label={label()}>
            <Icon name={props.kind === "panel" ? "panel" : "chat-bubble"} />
            <Show when={props.settings}><Icon name="gear" class="agent-settings-corner" /></Show>
        </span>
    );
}

export interface FacetBrowserApi {
    getWorkspaceCarriage(): Promise<ProjectionCarriage<Workspace>>;
    /** Mobile's ADR 0037 reference resolver. Optional because the desktop shell
     * keeps its existing full-refresh policy; `deltaSync` requires both methods. */
    getWorkspaceDeltaCarriage?(change: WorkspaceChange): Promise<ProjectionCarriage<WorkspaceDelta>>;
    subscribeWorkspace?(onChange: (change: WorkspaceChange) => void, onOpen?: () => void): () => void;
    search(query: string): Promise<SearchHit[]>;
    getPlacementConfig(placementId: PlacementId): Promise<{ config: string; notes: string }>;
    setPlacementConfig(placementId: PlacementId, config: string, notes: string): Promise<void>;
    createArchetype(name: string, kind?: AgentKind): Promise<ArchetypeId>;
    copyAgentAsPanel(id: ArchetypeId, name?: string): Promise<ArchetypeId>;
    createProject(name: string): Promise<ProjectId>;
    renameArchetype(id: ArchetypeId, name: string): Promise<void>;
    renameProject(id: ProjectId, name: string): Promise<void>;
    renameChat(id: EngagementId, title: string): Promise<void>;
    createWorkstream(placementId: PlacementId, name: string): Promise<WorkstreamNode>;
    joinWorkstream(ws: WorkstreamId, chat: EngagementId): Promise<void>;
    leaveWorkstream(ws: WorkstreamId, chat: EngagementId): Promise<void>;
    promoteWorkstream(ws: WorkstreamId): Promise<void>;
    settleWorkstreamTarget(ws: WorkstreamId, target: WorkTargetId, act: "apply" | "publish" | "release", promotionManifestRef?: string): Promise<void>;
    settleChatTargets(chat: EngagementId, members: readonly { target_id: WorkTargetId; act: "apply" | "publish" | "release" }[]): Promise<void>;
    queryTargetSettlementMember(declarationId: string, memberId: string): Promise<void>;
    retryTargetSettlementMember(declarationId: string, memberId: string): Promise<void>;
    getTargetSettlement(declarationId: string): Promise<void>;
    supersedeTargetSettlementMember(declarationId: string, memberId: string, laterDeclarationId: string, laterMemberId: string): Promise<void>;
    compensateTargetSettlement(declarationId: string, receiptLinks: readonly {
        original_receipt_ref: string;
        compensation_declaration_id: string;
        compensation_member_id: string;
        compensation_receipt_ref: string;
    }[]): Promise<void>;
    abandonTargetSettlement(declarationId: string, reason: string): Promise<void>;
    cancelTargetSettlement(declarationId: string, reason: string): Promise<void>;
    archiveWorkstream(ws: WorkstreamId): Promise<void>;
    createChatUnderArchetype(archetypeId: ArchetypeId, title: string): Promise<EngagementId>;
    createChatUnderPlacement(pid: ProjectId, placementId: PlacementId, title: string, targetIds: readonly WorkTargetId[]): Promise<EngagementId>;
    reviseChatTargets(id: EngagementId, targets: readonly { targetId: WorkTargetId; participation: "read-only" | "writable" }[]): Promise<void>;
    useArchetype(archetypeId: ArchetypeId, title: string): Promise<EngagementId>;
    createEngagement(): Promise<Engagement>;
    deleteChat(id: EngagementId): Promise<void>;
    organizeChat(id: EngagementId, change: { archived?: boolean; pinned?: boolean }): Promise<void>;
    forkChat(id: EngagementId, destination?: { kind: "inherit" } | { kind: "main" } | { kind: "workstream"; workstream_id: string }): Promise<EngagementId>;
    deleteProject(id: ProjectId): Promise<void>;
    upgradePlacement(placementId: PlacementId): Promise<number>;
    acceptPlacement(placementId: PlacementId): Promise<void>;
    removePlacement(pid: ProjectId, placementId: PlacementId): Promise<void>;
    publishArchetype(id: ArchetypeId, autoUpgrade?: boolean): Promise<{ version: number; autoUpgraded: number }>;
    forkArchetype(id: ArchetypeId, name?: string): Promise<ArchetypeId>;
    pullFromSource(id: ArchetypeId): Promise<void>;
    deleteArchetype(id: ArchetypeId): Promise<void>;
    placeArchetype(pid: ProjectId, archetypeId: ArchetypeId, recipient?: import("@gaugewright/control-plane-client").CollectionRecipient): Promise<PlacementId>;
    ensureCollectionRecipient?(recipientId: string): Promise<import("@gaugewright/control-plane-client").CollectionRecipient>;
}

export function FacetBrowser(props: {
    api: FacetBrowserApi;
    selected: EngagementId | null;
    onSelect: (id: EngagementId) => void;
    onOpenArchetypeSettings: (id: ArchetypeId, name: string, kind: AgentKind) => void;
    /** Open the per-project Engagement pane (hand off / share a project, FED-7). */
    onOpenEngagement: (id: ProjectId, name: string) => void;
    onOpenModelAccess: (id: ProjectId, name: string) => void;
    onOpenProjectHome: (id: ProjectId, name: string) => void;
    onOpenProjectTasks?: (id: ProjectId, name: string) => void;
    onOpenTutorials?: (id: ProjectId) => void;
    /** Hand the exact tested placement to the managed website-deployment flow. */
    onDeployPlacement?: (selection: {
        projectId: ProjectId;
        projectName: string;
        placementId: PlacementId;
        archetypeName: string;
        version: number;
        profile: import("@gaugewright/control-plane-client").PanelPublicProfile;
        deployments: Workspace["projects"][number]["placements"][number]["deployments"];
    }) => void;
    /** Open a Panel agent — its edit chat in Chat, the agent itself in Content — or,
     *  with a project, the same surface pinned to that project's placement (PANEL-12). */
    onOpenPanelAgent?: (agent: Workspace["archetypes"][number], project?: Workspace["projects"][number]) => void;
    onOpenInbox?: (project: ProjectId, name: string) => void;
    onAttachTarget?: (id: ProjectId, name: string, kind: "external-vcs" | "external-folder") => void;
    onOpenForkTree: (chat: EngagementId) => void;
    onChatRemoved: (id: EngagementId) => void;
    onStatus: (msg: string) => void;
    /** A chat's agent run tone (round-13): drives the status dot beside its name —
     *  working / needs-review / error, or undefined when idle (no dot). Optional so
     *  the mobile shell can omit it. */
    runToneOf?: (id: EngagementId) => ChatRunTone | undefined;
    /** Bumped by the shell after a turn settles so the tree picks up changes made
     *  outside the nav (e.g. auto-titling a chat from its first message, #4). */
    refreshKey?: unknown;
    /** Resolve workspace event references into narrow delta projections and patch
     * this tree instead of re-reading the full workspace (UX-12 mobile tail). */
    deltaSync?: boolean;
    /** Called after a delta lands so the shell may refresh sibling projections
     * such as the task queue without coupling them to the nav tree. */
    onWorkspaceChange?: (change: WorkspaceChange) => void;
}) {
    // Projects remains the structural default. Recent is a read-only current-first
    // selection lens whose rows spell out their roots; it never hosts workstream
    // commands or drag/drop targets.
    const [facet, setFacet] = createSignal<Facet>("projects");
    const [query, setQuery] = createSignal("");
    const [searchOpen, setSearchOpen] = createSignal(false);
    const [filterOpen, setFilterOpen] = createSignal(false);
    const [filterPage, setFilterPage] = createSignal<"root" | "status" | "grouping">("root");
    const [grouping, setGroupingSignal] = createSignal<ProjectLens>(readStoredChoice(GROUPING_KEY, ["chats", "archetype"], "chats"));
    const [projectStatus, setProjectStatus] = createSignal<ProjectStatus>(readStoredChoice(STATUS_KEY, ["active", "archived", "all"], "active"));
    // The nav's initial/repair read uses the workspace **freshness carriage** (ADR
    // 0037), never a bare value. Desktop refreshKey bumps still re-read it; mobile
    // routine events take the delta path below. `fresh` is surfaced so a stale tree
    // is never shown as current.
    const [carriage, { refetch }] = createResource(
        () => [props.refreshKey] as const,
        () => props.api.getWorkspaceCarriage(),
    );
    const [deltaFreshness, setDeltaFreshness] = createSignal<ProjectionCarriage<WorkspaceDelta>["freshness"] | null>(null);
    // Reconcile each refetch into a store, keyed by `id`, instead of swapping in the
    // fresh JSON wholesale (round-13 flakiness fix). The fetcher returns brand-new
    // objects every refetch; a reference-keyed `<For>` would destroy and re-create
    // every chat row, so a click that lands during a refetch (which fires on each
    // workspace event) hits a detached node and is silently lost — the "click the
    // chat twice" bug. Reconciling preserves node identity for unchanged rows, so
    // the row under the pointer stays put.
    const [store, setStore] = createStore<{ tree: Workspace | null }>({ tree: null });
    createEffect(() => {
        // Reading an errored resource RETHROWS the fetcher's failure. Letting that
        // escape the effect abandons the store on `null`, so `tree()` stays
        // undefined and the nav sits on "loading…" with nothing that can clear it
        // — the read never runs again unless a workspace event bumps `refreshKey`,
        // and at boot there are no events yet. Keep the last good tree instead and
        // let the render surface the failure.
        if (carriage.error) return;
        const v = carriage()?.value;
        if (v) setDeltaFreshness(null);
        setStore("tree", v ? reconcile(v, { key: "id" }) : null);
    });
    const tree = () => store.tree ?? undefined;
    // Same rethrow hazard: a bare `carriage()` here would throw straight through
    // the freshness banner's render.
    const fresh = () => deltaFreshness() ?? (carriage.error ? undefined : carriage()?.freshness);

    // The co-resident control plane binds its port *after* the shell opens the
    // webview (measured on the desktop build: ~1s warm, over 5s on a cold state
    // root), so the nav's first read can lose that race and fail with a bare
    // connection refusal. The event stream already treats availability as
    // something to wait for rather than an outcome; the initial projection read
    // is the one path that did not, which turned a few seconds of startup into a
    // permanently empty navigator. Retry on the same bounded schedule, then leave
    // the honest retry control for anything that outlives it.
    const INITIAL_READ_DELAYS_MS = [250, 500, 1_000, 2_000, 5_000];
    let initialReadFailures = 0;
    let initialReadTimer: ReturnType<typeof setTimeout> | undefined;
    onCleanup(() => {
        if (initialReadTimer !== undefined) clearTimeout(initialReadTimer);
    });
    createEffect(() => {
        if (!carriage.error || store.tree) {
            // A good read (or a tree we can still show) ends the wait and re-arms
            // it for the next cold start.
            if (!carriage.error) initialReadFailures = 0;
            return;
        }
        if (initialReadFailures >= INITIAL_READ_DELAYS_MS.length) return;
        const delay = INITIAL_READ_DELAYS_MS[initialReadFailures];
        initialReadFailures += 1;
        if (initialReadTimer !== undefined) clearTimeout(initialReadTimer);
        initialReadTimer = setTimeout(() => void refetch(), delay);
    });

    // Mobile resolves the reference-only SSE one event at a time. Serializing the
    // queue prevents a slower, older response from overwriting a newer patch; each
    // delta removes the referenced record globally before inserting the server's
    // current parent nodes. A failed delta falls back to one honest full refresh.
    createEffect(() => {
        if (!props.deltaSync) return;
        if (!props.api.subscribeWorkspace || !props.api.getWorkspaceDeltaCarriage) return;
        let active = true;
        let queue = Promise.resolve();
        let opened = false;
        const stop = props.api.subscribeWorkspace((change) => {
            queue = queue
                .then(async () => {
                    if (!active) return;
                    if (!tree()) {
                        await refetch();
                    } else {
                        const delta = await props.api.getWorkspaceDeltaCarriage!(change);
                        if (!active) return;
                        setStore("tree", reconcile(applyWorkspaceDelta(tree()!, delta.value), { key: "id" }));
                        setDeltaFreshness(delta.freshness);
                    }
                    props.onWorkspaceChange?.(change);
                })
                .catch(async () => {
                    if (!active) return;
                    await refetch();
                    props.onWorkspaceChange?.(change);
                });
        }, () => {
            if (!opened) {
                opened = true;
                return;
            }
            // Workspace events are references, not a replay log. A full
            // projection read repairs anything missed while disconnected.
            queue = queue.then(async () => {
                if (active) await refetch();
            });
        });
        onCleanup(() => {
            active = false;
            stop();
        });
    });

    // A filter/search box spanning all facets (navigation.md B2). The match/filter
    // doctrine ("a node shows iff it or a descendant matches") lives in the pure
    // state/facet-filter reducers; the renderers below just bind the live query().
    // Mark the matched substring in a surviving row so a filtered list shows *why*
    // each row stayed (#6 round-9): on "mail", both "Marketing" and "Email helper"
    // survive (one as an ancestor of the hit), but only the literal match gets
    // bolded, so the eye lands on the real reason. Empty/no-match ⇒ plain text.
    const mark = (label: string) => {
        const m = markMatch(label, query());
        if (!m) return label;
        return (
            <>
                {m.pre}
                <mark class="search-hit">{m.match}</mark>
                {m.post}
            </>
        );
    };
    const searching = () => isSearching(query());

    // The chat-log relevance tier (SEARCH-1): the server's `GET /search` finds the
    // chats whose *content* matches, which we merge into the title-filtered tree so
    // a chat surfaces even when only its transcript (not its title) mentions the
    // query. `contentMatches` maps a hit chat id → a snippet of the match (shown as
    // a sublabel); `contentHits` is just its id set, fed to the filter predicates.
    // Debounced + min-2-chars so a fast typist doesn't fan out a fold-per-keystroke.
    const [contentMatches, setContentMatches] = createSignal<Map<string, string>>(new Map());
    const contentHits = createMemo(() => new Set(contentMatches().keys()));
    createEffect(() => {
        const q = query().trim();
        if (q.length < 2) {
            setContentMatches(new Map());
            return;
        }
        let cancelled = false;
        const handle = setTimeout(() => {
            void props.api
                .search(q)
                .then((hits) => {
                    if (!cancelled) setContentMatches(new Map(hits.map((h) => [h.id, h.snippet])));
                })
                .catch(() => {
                    // A failed content search must not blank the title tier — just
                    // drop content hits; the tree still filters on titles.
                    if (!cancelled) setContentMatches(new Map());
                });
        }, 250);
        onCleanup(() => {
            cancelled = true;
            clearTimeout(handle);
        });
    });

    // For a parent node: keep it if its own label matches, else keep only the
    // descendants that match — by title or content (so search narrows into a group,
    // surfacing content-only hits, never hides a hit).
    const chatsFor = <T extends { title: string; id?: EngagementId; archived?: boolean }>(label: string, chats: T[]) =>
        childrenFor(label, chats.filter((chat) => !chat.archived), query(), contentHits());
    const activeChatCount = (chats: readonly { archived?: boolean }[]) => chats.filter((chat) => !chat.archived).length;

    const [menu, setMenu] = createSignal<MenuState | null>(null);
    // Row-tool reveal driven by pointer EVENTS, not CSS :hover (ADR 0112).
    // Chrome on Linux/Wayland can desync its hover flag from style resolution
    // (element.matches(':hover') true while :hover rules never apply — observed
    // live 2026-07-28); pointerenter/leave keep firing in that state, so a
    // class toggle stays reliable where the pseudo-class silently isn't.
    const [hotRow, setHotRow] = createSignal<string | null>(null);
    const setGrouping = (value: ProjectLens) => {
        setGroupingSignal(value);
        try { window.localStorage?.setItem(GROUPING_KEY, value); } catch { /* session-only preference */ }
        setFilterOpen(false);
    };
    const setStatus = (value: ProjectStatus) => {
        setProjectStatus(value);
        try { window.localStorage?.setItem(STATUS_KEY, value); } catch { /* session-only preference */ }
        setFilterOpen(false);
    };
    // Current-first rank for the flat `chats` lens, derived from the same server
    // projection Recent renders; chats absent from it sink to the end in tree order.
    const recentRank = createMemo(() => new Map((tree()?.recent ?? []).map((c, i) => [c.id, i] as const)));
    // Collapsed tree groups (project / archetype ids). Click a node's ▾/▸ icon to
    // fold its children; local UI state, like facet/selection.
    const [collapsed, setCollapsed] = createSignal<Set<string>>(new Set());
    const isCollapsed = (id: string) => collapsed().has(id);
    const toggleCollapse = (id: string) =>
        setCollapsed((s) => {
            const next = new Set(s);
            if (next.has(id)) next.delete(id);
            else next.add(id);
            return next;
        });
    // inline editor: creating or renaming a named tree node.
    const [editing, setEditing] = createSignal<
        | { kind: "new-project" }
        | { kind: "rename-archetype"; id: ArchetypeId }
        | { kind: "rename-project"; id: ProjectId }
        | { kind: "rename-chat"; id: EngagementId }
        | { kind: "new-workstream"; placementId: PlacementId }
        | { kind: "new-workstream-from-chat"; placementId: PlacementId; chat: EngagementId }
        | null
    >(null);
    // A workstream promotion is explicit but deserves a compact, non-modal guard.
    // This is presentation state only: the control plane still owns all merge gates.
    const [confirmingMerge, setConfirmingMerge] = createSignal<WorkstreamId | null>(null);
    const [draggingChat, setDraggingChat] = createSignal<DraggableChat | null>(null);
    const mainDropTarget = "main" as const;
    const [dropTarget, setDropTarget] = createSignal<WorkstreamId | typeof mainDropTarget | null>(null);
    const [dragPointer, setDragPointer] = createSignal({ x: 0, y: 0 });
    let pointerDrag: {
        chat: DraggableChat;
        x: number;
        y: number;
    } | null = null;
    const cancelMergeOnOutsideClick = (event: MouseEvent) => {
        if (
            confirmingMerge() &&
            !(event.target instanceof Element && event.target.closest(".ws-merge"))
        ) {
            setConfirmingMerge(null);
        }
    };
    document.addEventListener("click", cancelMergeOnOutsideClick);
    const trackPointerDrag = (event: PointerEvent) => {
        const candidate = pointerDrag;
        if (
            candidate &&
            event.buttons !== 0 &&
            Math.hypot(event.clientX - candidate.x, event.clientY - candidate.y) > 8
        ) {
            setDraggingChat(candidate.chat);
            setDragPointer({ x: event.clientX, y: event.clientY });
        }
    };
    const finishPointerDrag = () => {
        // Solid delegates pointer handlers at `document`. Defer cleanup until those
        // handlers have seen the release over a workstream header.
        queueMicrotask(() => {
            pointerDrag = null;
            setDraggingChat(null);
            setDropTarget(null);
        });
    };
    document.addEventListener("pointermove", trackPointerDrag);
    document.addEventListener("pointerup", finishPointerDrag);
    onCleanup(() => {
        document.removeEventListener("click", cancelMergeOnOutsideClick);
        document.removeEventListener("pointermove", trackPointerDrag);
        document.removeEventListener("pointerup", finishPointerDrag);
    });
    const [editText, setEditText] = createSignal("");
    const [newAgentOpen, setNewAgentOpen] = createSignal(false);
    const [newAgentName, setNewAgentName] = createSignal("");
    const [newAgentKind, setNewAgentKind] = createSignal<AgentKind>("work");
    const [creatingAgent, setCreatingAgent] = createSignal(false);
    const [createAgentError, setCreateAgentError] = createSignal("");

    // The "add a method" picker (#1): from a project, choose *which* archetype to
    // install on it, rather than the app silently placing an arbitrary one. (The
    // reverse "place this archetype on a project" direction was retired by ADR 0045
    // — an archetype is usable in Personal with no placement.)
    const [picker, setPicker] = createSignal<
        { dir: "to-project"; pid: ProjectId; projectName: string } | null
    >(null);
    const [pickerQuery, setPickerQuery] = createSignal("");
    const [targetChoice, setTargetChoice] = createSignal<
        | { kind: "chat"; pid: ProjectId; placementId: PlacementId; targets: WorkTargetNode[]; selected: readonly WorkTargetId[] }
        | { kind: "revise"; chatId: EngagementId; targets: WorkTargetNode[]; selected: readonly { targetId: WorkTargetId; participation: "read-only" | "writable" }[] }
        | null
    >(null);

    // Per-placement config-only customization (placement.md): a small editor over a
    // placement's `.agent-config.json` overlay + project notes — tweak a method for one
    // client without forking. Loaded on open, written via the InstanceState reducer.
    const [configFor, setConfigFor] = createSignal<{ placementId: PlacementId; name: string } | null>(null);
    const [cfgConfig, setCfgConfig] = createSignal("");
    const [cfgNotes, setCfgNotes] = createSignal("");
    const [cfgStatus, setCfgStatus] = createSignal("");
    async function openConfig(placementId: PlacementId, name: string) {
        setConfigFor({ placementId, name });
        setCfgConfig("");
        setCfgNotes("");
        setCfgStatus("loading…");
        try {
            const { config, notes } = await props.api.getPlacementConfig(placementId);
            setCfgConfig(config);
            setCfgNotes(notes);
            setCfgStatus("");
        } catch (e) {
            setCfgStatus(e instanceof Error ? e.message : String(e));
        }
    }
    async function saveConfig() {
        const f = configFor();
        if (!f) return;
        // Config overlay must be valid JSON (empty = no overlay) so a run never reads a
        // broken `.agent-config.json`.
        if (cfgConfig().trim()) {
            try {
                JSON.parse(cfgConfig());
            } catch {
                setCfgStatus("config must be valid JSON (or empty)");
                return;
            }
        }
        try {
            await props.api.setPlacementConfig(f.placementId, cfgConfig().trim(), cfgNotes());
            setConfigFor(null);
            await refetch();
            props.onStatus(`customized ${f.name}`);
        } catch (e) {
            setCfgStatus(e instanceof Error ? e.message : String(e));
        }
    }

    // The C1 pivot index: archetype id → the placements (project + lineage) of it,
    // so an archetype node can list "everywhere it is placed".
    const placementsOf = createMemo(() => {
        const t = tree();
        const idx = new Map<string, { project: string; placementId: PlacementId }[]>();
        if (!t) return idx;
        for (const p of t.projects) {
            for (const pl of p.placements) {
                const list = idx.get(pl.archetypeId) ?? [];
                list.push({ project: p.name, placementId: pl.placementId });
                idx.set(pl.archetypeId, list);
            }
        }
        return idx;
    });

    // Whether a node has anything to fold. The ▾/▸ caret promises collapsible
    // children (#2 round-9); on a method with no chats and nowhere placed it
    // expanded to nothing, so the caret lied. Render a real caret only when there
    // are children, and a fixed-width spacer otherwise so labels stay aligned.
    const archetypeHasChildren = (a: { id: string; chats: { archived?: boolean }[] }) =>
        activeChatCount(a.chats) > 0 || (placementsOf().get(a.id)?.length ?? 0) > 0;
    const caret = (id: string, hasChildren: boolean) =>
        hasChildren ? (
            <span class="node-icon" onClick={(e) => { e.stopPropagation(); toggleCollapse(id); }}>
                {isCollapsed(id) ? "▸" : "▾"}
            </span>
        ) : (
            <span class="node-icon node-icon-empty" aria-hidden="true" />
        );

    async function withRefresh(action: () => Promise<unknown>, ok: string) {
        try {
            await action();
            props.onStatus(ok);
        } catch (e) {
            props.onStatus(e instanceof Rejected ? e.reason : String(e));
        } finally {
            // The mobile delta subscriber receives the mutation's reference and
            // patches the tree. Other consumers retain the immediate full refresh.
            if (!props.deltaSync) await refetch();
        }
    }

    function startEdit(kind: ReturnType<typeof editing>, initial = "") {
        setEditText(initial);
        setEditing(kind);
    }

    function openCreateAgent() {
        setEditing(null);
        setNewAgentName("");
        setNewAgentKind("work");
        setCreateAgentError("");
        setNewAgentOpen(true);
    }

    async function submitNewAgent(event: SubmitEvent) {
        event.preventDefault();
        const name = newAgentName().trim();
        if (!name || creatingAgent()) return;
        const kind = newAgentKind();
        setCreatingAgent(true);
        setCreateAgentError("");
        try {
            await props.api.createArchetype(name, kind);
        } catch (error) {
            setCreateAgentError(error instanceof Rejected ? error.reason : String(error));
            setCreatingAgent(false);
            return;
        }
        setNewAgentOpen(false);
        setCreatingAgent(false);
        props.onStatus(`${kind === "panel" ? "Panel agent" : "Agent"} "${name}" created`);
        if (!props.deltaSync) {
            try {
                await refetch();
            } catch (error) {
                props.onStatus(`Agent created, but Workshop could not refresh: ${String(error)}`);
            }
        }
    }

    function createAgentKeyDown(event: KeyboardEvent & { currentTarget: HTMLFormElement }) {
        if (event.key === "Escape" && !creatingAgent()) {
            event.preventDefault();
            setNewAgentOpen(false);
        }
        if (event.key !== "Tab") return;
        const controls = [...event.currentTarget.querySelectorAll<HTMLElement>("button:not(:disabled), input:not(:disabled)")];
        const first = controls[0];
        const last = controls.at(-1);
        if (event.shiftKey && document.activeElement === first) {
            event.preventDefault();
            last?.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
            event.preventDefault();
            first?.focus();
        }
    }

    async function commitEdit() {
        const e = editing();
        const text = editText().trim();
        setEditing(null);
        if (!e || !text) return;
        switch (e.kind) {
            case "new-project":
                return withRefresh(() => props.api.createProject(text), `project "${text}" created`);
            case "rename-archetype":
                return withRefresh(() => props.api.renameArchetype(e.id, text), "renamed");
            case "rename-project":
                return withRefresh(() => props.api.renameProject(e.id, text), "renamed");
            case "rename-chat":
                return withRefresh(() => props.api.renameChat(e.id, text), "renamed");
            case "new-workstream":
                // Workstreams (WS-F): a named shared auto-sync line in this placement.
                return createNamedWorkstream(e.placementId, text);
            case "new-workstream-from-chat":
                // Create + join in one step (WS-H): the line is born on the chat's exact
                // workspace root with the chat already a member, so it is visible and
                // non-empty from the start.
                return createNamedWorkstream(e.placementId, text, e.chat);
        }
    }

    // --- workstreams (WS-F): create, membership, promote/archive ---
    async function joinWs(wsId: WorkstreamId, chat: EngagementId) {
        await withRefresh(() => props.api.joinWorkstream(wsId, chat), "joined the workstream — its turns now auto-sync");
    }
    async function leaveWs(wsId: WorkstreamId, chat: EngagementId) {
        await withRefresh(() => props.api.leaveWorkstream(wsId, chat), "left the workstream — back on the mainline");
    }
    async function promoteWs(wsId: WorkstreamId) {
        await withRefresh(() => props.api.promoteWorkstream(wsId), "collaboration promoted into Main — target settlement remains separate");
    }
    async function settleWsTarget(ws: WorkstreamNode, target: WorkTargetNode, act: "apply" | "publish" | "release") {
        await withRefresh(
            () => props.api.settleWorkstreamTarget(ws.id, target.id, act, ws.promotionManifestRef ?? undefined),
            `${target.name}: ${act} settlement requested`,
        );
    }
    function requestPromoteWs(wsId: WorkstreamId) {
        if (confirmingMerge() !== wsId) {
            setConfirmingMerge(wsId);
            props.onStatus("click Confirm merge to integrate this workstream into Main");
            return;
        }
        setConfirmingMerge(null);
        void promoteWs(wsId);
    }
    function draggedChatFrom(event: DragEvent) {
        const held = draggingChat();
        const encoded = event.dataTransfer?.getData("application/x-gaugedesk-chat");
        let chat = held;
        if (!chat && encoded) {
            try {
                const parsed: unknown = JSON.parse(encoded);
                if (
                    typeof parsed === "object" &&
                    parsed !== null &&
                    typeof (parsed as { id?: unknown }).id === "string"
                ) {
                    const source = parsed as { id: string; workspaceRoot?: string; workstream?: string | null; rehomeBlocked?: boolean };
                    chat = {
                        id: source.id as EngagementId,
                        title: source.id,
                        workspaceRoot: (source.workspaceRoot ?? "") as WorkspaceRootId,
                        workstream: source.workstream as WorkstreamId | null | undefined,
                        rehomeBlocked: source.rehomeBlocked ?? true,
                    };
                }
            } catch {
                // A foreign or malformed drag is not a membership command.
            }
        }
        return chat;
    }
    function dropChatOnWorkstream(event: DragEvent, destination: WorkstreamNode) {
        event.preventDefault();
        transferChatToWorkstream(draggedChatFrom(event), destination);
    }
    function transferChatToWorkstream(
        chat: DraggableChat | null,
        destination: WorkstreamNode,
    ) {
        const allowed = canDropOnWorkstream(chat, destination);
        pointerDrag = null;
        setDraggingChat(null);
        setDropTarget(null);
        if (!allowed || !chat) return;
        void joinWs(destination.id, chat.id);
    }
    function transferChatToMain(
        chat: DraggableChat | null,
        root: WorkspaceRootId | undefined,
    ) {
        pointerDrag = null;
        setDraggingChat(null);
        setDropTarget(null);
        // Main is a chat's existing placement mainline. Leaving keeps the server as
        // authority for membership and re-homing rather than inventing a client-side
        // "main" workstream id.
        if (!canDropOnMain(chat, root) || !chat?.workstream) return;
        void leaveWs(chat.workstream, chat.id);
    }
    function canDropOnWorkstream(chat: DraggableChat | null, destination: WorkstreamNode) {
        return canTransferToWorkstream(chat, destination);
    }
    function canDropOnMain(
        chat: DraggableChat | null,
        root: WorkspaceRootId | undefined,
    ) {
        return canTransferToMain(chat, root);
    }
    async function archiveWs(wsId: WorkstreamId) {
        await withRefresh(() => props.api.archiveWorkstream(wsId), "workstream archived — its chats are back on the mainline");
    }

    async function forkChatWithRetry(chat: { id: EngagementId; workspaceRoot: WorkspaceRootId }): Promise<EngagementId> {
        try {
            return await props.api.forkChat(chat.id);
        } catch (error) {
            if (!String(error).includes("historical-home-closed")) throw error;
            const destinations = (tree()?.workstreams ?? []).filter((workstream) =>
                workstream.status === "active" && workstream.workspaceRoot === chat.workspaceRoot);
            const answer = window.prompt(
                `That historical workstream is archived. Choose a current destination:\n0. Main\n${destinations.map((workstream, index) => `${index + 1}. ${workstream.name}`).join("\n")}`,
                "0",
            );
            if (answer === null) throw error;
            const choice = Number(answer.trim());
            if (choice === 0) return props.api.forkChat(chat.id, { kind: "main" });
            const destination = destinations[choice - 1];
            if (!destination) throw new Error("no valid fork destination was selected");
            return props.api.forkChat(chat.id, { kind: "workstream", workstream_id: destination.id });
        }
    }

    // An EDIT chat is rooted on an archetype (improve the method).
    async function newEditChat(archetypeId: ArchetypeId) {
        await withRefresh(async () => {
            const id = await props.api.createChatUnderArchetype(archetypeId, "edit chat");
            props.onSelect(id);
        }, "editing this Agent");
    }
    // A WORK chat is rooted on a placement (do the job).
    function targetsForPlacement(placementId: PlacementId): WorkTargetNode[] {
        const workspace = tree();
        if (!workspace) return [];
        const authoring = workspace.archetypes.find((archetype) => archetype.instanceId === placementId);
        const targetIds = authoring
            ? [authoring.authoringTargetId]
            : workspace.projects
                  .flatMap((project) => project.placements)
                  .find((placement) => placement.placementId === placementId)?.targetIds ?? [];
        return targetIds
            .map((id) => workspace.workTargets.find((target) => target.id === id))
            .filter((target): target is WorkTargetNode => !!target && target.status === "available" && target.capabilities.read);
    }

    async function newWorkChat(pid: ProjectId, placementId: PlacementId, targetIds?: readonly WorkTargetId[]) {
        const targets = targetsForPlacement(placementId);
        if (!targetIds && targets.length > 1) {
            setTargetChoice({ kind: "chat", pid, placementId, targets, selected: [] });
            return;
        }
        const selected = targetIds ?? (targets.length === 1 ? [targets[0].id] : []);
        if (selected.length === 0) {
            props.onStatus("no available work target can be read");
            return;
        }
        await withRefresh(async () => {
            const id = await props.api.createChatUnderPlacement(pid, placementId, "new chat", selected);
            props.onSelect(id);
        }, "new work chat");
    }

    async function createNamedWorkstream(placementId: PlacementId, name: string, joinChat?: EngagementId) {
        await withRefresh(async () => {
            const ws = await props.api.createWorkstream(placementId, name);
            if (joinChat) await props.api.joinWorkstream(ws.id, joinChat);
        }, `workstream "${name}" created`);
    }

    function toggleTarget(target: WorkTargetNode) {
        const choice = targetChoice();
        if (!choice) return;
        if (choice.kind === "revise") {
            const current = choice.selected.find((member) => member.targetId === target.id);
            const selected = current
                ? current.participation === "read-only" && target.capabilities.propose
                    ? choice.selected.map((member) => member.targetId === target.id ? { ...member, participation: "writable" as const } : member)
                    : choice.selected.filter((member) => member.targetId !== target.id)
                : [...choice.selected, { targetId: target.id, participation: "read-only" as const }];
            setTargetChoice({ ...choice, selected });
            return;
        }
        const selected = choice.selected.includes(target.id)
            ? choice.selected.filter((id) => id !== target.id)
            : [...choice.selected, target.id];
        setTargetChoice({ ...choice, selected });
    }
    function targetChoiceParticipation(
        choice: NonNullable<ReturnType<typeof targetChoice>>,
        targetId: WorkTargetId,
    ): "read-only" | "writable" | null {
        if (choice.kind === "chat") return choice.selected.includes(targetId) ? "writable" : null;
        return choice.selected.find((member) => member.targetId === targetId)?.participation ?? null;
    }

    async function confirmTargetChoice() {
        const choice = targetChoice();
        if (!choice || choice.selected.length === 0) return;
        setTargetChoice(null);
        if (choice.kind === "chat") {
            await newWorkChat(choice.pid, choice.placementId, choice.selected);
        } else {
            await withRefresh(
                () => props.api.reviseChatTargets(choice.chatId, choice.selected),
                "chat target set revised for the next turn",
            );
        }
    }

    function reviseTargets(chat: { id: EngagementId; placement?: PlacementId | null; targets?: readonly { targetId: WorkTargetId; participation: "read-only" | "writable" }[] }) {
        if (!chat.placement) return;
        setTargetChoice({
            kind: "revise",
            chatId: chat.id,
            targets: targetsForPlacement(chat.placement),
            selected: (chat.targets ?? []).map((target) => ({ targetId: target.targetId, participation: target.participation })),
        });
    }
    function settleChatTargetChanges(chat: { id: EngagementId; targets?: readonly { targetId: WorkTargetId; participation: "read-only" | "writable" }[] }) {
        const members = (chat.targets ?? []).flatMap((member) => {
            if (member.participation !== "writable") return [];
            const target = tree()?.workTargets.find((candidate) => candidate.id === member.targetId);
            const act: "apply" | "publish" | "release" | null = target?.capabilities.apply ? "apply"
                : target?.capabilities.publish ? "publish"
                : target?.capabilities.release ? "release"
                : null;
            return act ? [{ target_id: member.targetId, act }] : [];
        });
        if (members.length === 0) {
            props.onStatus("no writable chat target has an apply, publish, or release capability");
            return;
        }
        void withRefresh(
            () => props.api.settleChatTargets(chat.id, members),
            "started settlement for every writable target candidate",
        );
    }
    // USE an archetype with no placement ceremony (ADR 0045/0036): a work chat in
    // the explicit Personal project. The server finds/creates its placement.
    async function useArchetype(archetypeId: ArchetypeId) {
        await withRefresh(async () => {
            const id = await props.api.useArchetype(archetypeId, "new chat");
            props.onSelect(id);
        }, "new work chat");
    }

    function openMenu(e: MouseEvent, items: MenuState["items"]) {
        e.preventDefault();
        e.stopPropagation();
        setMenu({ x: e.clientX, y: e.clientY, items });
    }

    // Open the row menu from a left-click control (the ⋯ button, ADR 0112).
    // Anchored under the button, and deferred a tick: the menu's own
    // document-level dismiss listener would otherwise see the very click that
    // opened it (right-click opens on `contextmenu`, so it never had this race).
    function openMenuAt(anchor: HTMLElement, items: MenuState["items"]) {
        const r = anchor.getBoundingClientRect();
        window.setTimeout(() => setMenu({ x: r.left, y: r.bottom + 4, items }), 0);
    }

    function deleteChat(id: EngagementId) {
        void withRefresh(async () => {
            await props.api.deleteChat(id);
            props.onChatRemoved(id);
        }, "chat deleted");
    }

    function organizeChat(id: EngagementId, change: { archived?: boolean; pinned?: boolean }) {
        void withRefresh(async () => {
            await props.api.organizeChat(id, change);
            if (change.archived) props.onChatRemoved(id);
        }, change.archived === true ? "chat archived" : change.archived === false ? "chat restored" : change.pinned ? "chat pinned" : "chat unpinned");
    }

    const editingIs = (kind: string, id: string) => {
        const e = editing();
        return !!e && e.kind === kind && "id" in e && e.id === id;
    };

    // The inline name editor for create/rename. A placeholder tells a first-timer
    // exactly what to do (type a name, Enter to confirm, Esc to cancel) — a bare
    // empty box was a dead end (#7).
    const renameInput = (placeholder = "name…") => (
        <input
            class="inline-edit"
            // autofocus alone is unreliable when the field is inserted by a click
            // that doesn't carry focus in (#smaller); focus it explicitly on mount.
            // Select the existing text on open (#smaller round-9) so a rename can be
            // typed straight over — the familiar convention — instead of forcing the
            // user to hand-clear the old name first. A fresh "+ create" opens empty,
            // so select() is a harmless no-op there.
            ref={(el) => queueMicrotask(() => { el.focus(); el.select(); })}
            aria-label={placeholder}
            placeholder={placeholder}
            value={editText()}
            onInput={(ev) => setEditText(ev.currentTarget.value)}
            onBlur={() => void commitEdit()}
            onClick={(ev) => ev.stopPropagation()}
            onKeyDown={(ev) => {
                if (ev.key === "Enter") commitEdit();
                if (ev.key === "Escape") setEditing(null);
            }}
        />
    );

    // --- shared create affordances (consistency across every facet) ---
    // One button look (`.create-btn`) and one row container (`.action-row`) for every
    // "+ create" action — same size/colour/padding, grouped on a single row at the top
    // of a facet or right under a container's title. `createBtn` is the atom; `wsCreate`
    // pairs the "+ workstream" button with its inline name editor for a placement target.
    type BtnOpts = { testid?: string; wsRoot?: PlacementId; data?: string; title?: string };
    const createBtn = (label: string, onClick: () => void, opts?: BtnOpts) => (
        <button
            type="button"
            class="create-btn"
            data-testid={opts?.testid}
            data-ws-new={opts?.wsRoot}
            data-create={opts?.data}
            title={opts?.title}
            onClick={(e) => { e.stopPropagation(); onClick(); }}
        >
            {label}
        </button>
    );
    // The workstream naming editor, rendered just below the row whose menu started
    // it. `placementId` is the line's home (a project's general placement, a
    // deliberate placement, or an archetype's authoring instance). The old chip-row
    // "+ workstream" button retired into the row menus (ADR 0112).
    const wsEditorFor = (placementId: PlacementId) => (
        <Show when={editing()?.kind === "new-workstream" && (editing() as { placementId?: PlacementId }).placementId === placementId}>
            <div class="tree-leaf ws-new-inline">{renameInput("name this workstream, then Enter")}</div>
        </Show>
    );

    // A container row keeps its direct create action and an anchored menu.
    // Right-click opens the same full action list.
    const rowActions = (opts: {
        primary?: { icon: IconName; title: string; aria: string; data?: string; plus?: boolean; run: () => void };
        secondary?: { icon: IconName; title: string; aria: string; plus?: boolean; run: () => void };
        menuIcon?: IconName;
        menuPlus?: boolean;
        menuAria: string;
        menuItems: () => MenuState["items"];
    }) => (
        <span class="row-actions">
            <Show when={opts.primary} keyed>
                {(primary) => (
                    <button
                        type="button"
                        class="row-act"
                        data-create={primary.data}
                        title={primary.title}
                        aria-label={primary.aria}
                        onClick={(e) => { e.stopPropagation(); primary.run(); }}
                    >
                        <Icon name={primary.icon} class="icon" />
                        {/* The corner "+" marks creation; edit (pencil) is not a create. */}
                        <Show when={primary.plus}>
                            <i class="row-act-plus" aria-hidden="true">+</i>
                        </Show>
                    </button>
                )}
            </Show>
            <Show when={opts.secondary} keyed>
                {(secondary) => (
                    <button type="button" class="row-act" title={secondary.title} aria-label={secondary.aria}
                        onClick={(e) => { e.stopPropagation(); secondary.run(); }}>
                        <Icon name={secondary.icon} class="icon" />
                        <Show when={secondary.plus}><i class="row-act-plus" aria-hidden="true">+</i></Show>
                    </button>
                )}
            </Show>
            <button
                type="button"
                class="row-act"
                data-row-menu
                title="More actions"
                aria-label={opts.menuAria}
                onClick={(e) => { e.stopPropagation(); openMenuAt(e.currentTarget, opts.menuItems()); }}
            >
                <Icon name={opts.menuIcon ?? "kebab"} class="icon" />
                <Show when={opts.menuPlus}><i class="row-act-plus" aria-hidden="true">+</i></Show>
            </button>
        </span>
    );

    // --- node renderers ---

    // The project row's menu (shared by right-click and the row's ⋯ button).
    // Under the `chats` lens it adds "new chat with <archetype>" per deliberate
    // placement (ADR 0112: archetype choice stays reachable without switching
    // lens) and the lens flip itself.
    type ProjectNode = Workspace["projects"][number];
    // The project's zero-setup chat: its visible general placement when one
    // exists, else (Personal) the hidden default placement the server resolves
    // (ADR 0036 — the same path as the empty composer's "just start typing").
    const canStartProjectChat = (p: ProjectNode) =>
        p.isPersonal || p.placements.some((pl) => pl.isDefault);
    async function newProjectChat(p: ProjectNode) {
        const home = p.placements.find((pl) => pl.isDefault);
        if (home) return newWorkChat(p.id, home.placementId);
        if (!p.isPersonal) return;
        await withRefresh(async () => {
            const eng = await props.api.createEngagement();
            props.onSelect(eng.id);
        }, "new chat");
    }
    const projectMenuItems = (p: ProjectNode): MenuState["items"] => {
        if (p.product?.kind === "tutorials") return [
            { label: "open tutorials", run: () => props.onOpenTutorials?.(p.id) },
            ...(props.onOpenProjectTasks ? [{ label: "tasks…", hint: "Open your tutorial tasks", run: () => props.onOpenProjectTasks?.(p.id, p.name) }] : []),
        ];
        const home = p.placements.find((pl) => pl.isDefault)?.placementId;
        const lens = grouping();
        return [
            ...(home ? [
                { label: "new workstream", icon: "child-branch" as const, hint: "Create a shared auto-sync line in this project", run: () => startEdit({ kind: "new-workstream", placementId: home }) },
            ] : []),
            ...(lens === "chats"
                ? p.placements
                    .filter((pl) => !pl.isDefault && pl.kind === "work")
                    .map((pl) => ({
                        label: `new chat with ${pl.archetypeName}`,
                        hint: "Start a chat rooted on this Agent's placement in this project",
                        run: () => void newWorkChat(p.id, pl.placementId),
                    }))
                : []),
            { label: "add an Agent", icon: "robot" as const, run: () => openAddMethod(p.id, p.name) },
            ...(props.onAttachTarget ? [
                { label: "attach Git repository…", hint: "Use its native Git history and explicit apply lifecycle", run: () => props.onAttachTarget?.(p.id, p.name, "external-vcs" as const) },
                { label: "attach folder…", hint: "Fingerprint the folder and compare before every write", run: () => props.onAttachTarget?.(p.id, p.name, "external-folder" as const) },
            ] : []),
            { label: "project settings…", hint: "Manage work, Agents, model access, and—outside Personal—sharing", run: () => props.onOpenProjectHome(p.id, p.name) },
            // Tasks is new work, not one of the doors project settings absorbed,
            // so it stays its own entry. Model access and sharing are deliberately
            // absent: they moved inside project settings, and a second door to a
            // surface that has moved is worse than no door.
            ...(props.onOpenProjectTasks ? [{ label: "tasks…", hint: "Open the project’s task backlog, including unassigned work", run: () => props.onOpenProjectTasks?.(p.id, p.name) }] : []),
            ...(p.isPersonal ? [] : [
                { label: "rename", run: () => startEdit({ kind: "rename-project", id: p.id }, p.name) },
                { label: "delete", danger: true, confirmHint: projectBlastRadius(p), run: () => void withRefresh(() => props.api.deleteProject(p.id), "project deleted") },
            ]),
        ];
    };

    // A placement row's menu (shared by right-click and the row's ⋯ button).
    const placementMenuItems = (p: ProjectNode, pl: ProjectNode["placements"][number]): MenuState["items"] => pl.kind === "panel" ? [
        ...(props.onOpenPanelAgent ? [{ label: "open", hint: "Open this placement: its pinned contract, Preview, and deployments", run: () => {
            const agent = tree()?.archetypes.find((candidate) => candidate.id === pl.archetypeId);
            if (agent) props.onOpenPanelAgent?.(agent, p);
        } }] : []),
        ...(props.onDeployPlacement && pl.panelProfile ? [{
            label: pl.deployments.length ? "manage deployments…" : "deploy…",
            hint: "Publish this pinned Panel-agent version for this project",
            run: () => props.onDeployPlacement?.({
                projectId: p.id,
                projectName: p.name,
                placementId: pl.placementId,
                archetypeName: pl.archetypeName,
                version: pl.version,
                profile: pl.panelProfile!,
                deployments: pl.deployments,
            }),
        }] : []),
        ...(props.onOpenInbox ? [{ label: "inbox", hint: "Review public output held by this project's gate", run: () => props.onOpenInbox?.(p.id, p.name) }] : []),
        ...(pl.upgradeAvailable ? [{ label: "upgrade to latest", run: () => void withRefresh(() => props.api.upgradePlacement(pl.placementId), "upgraded to the latest version") }] : []),
        { label: "remove from project", danger: true, run: () => void withRefresh(() => props.api.removePlacement(p.id, pl.placementId), "removed") },
    ] : [
        { label: "new chat", hint: "Start a new chat on this placement", run: () => newWorkChat(p.id, pl.placementId) },
        { label: "new workstream", hint: "Create a shared auto-sync line for chats here to collaborate on", run: () => startEdit({ kind: "new-workstream", placementId: pl.placementId }) },
        { label: "edit", run: () => newEditChat(pl.archetypeId) },
        { label: "customize…", hint: "Tweak this method for this project — config + notes, no fork (placement.md)", run: () => void openConfig(pl.placementId, `${pl.archetypeName} · ${p.name}`) },
        ...(pl.pending
            ? [{ label: "accept", hint: "Approve this Agent so it can host work chats (APPROVE-1)", run: () => void withRefresh(() => props.api.acceptPlacement(pl.placementId), "placement accepted") }]
            : []),
        ...(pl.upgradeAvailable
            ? [{ label: "upgrade to latest", hint: `Take the newer published version (v${pl.currentVersion}) of this Agent`, run: () => void withRefresh(() => props.api.upgradePlacement(pl.placementId), "upgraded to the latest version") }]
            : []),
        { label: "remove from project", danger: true, run: () => void withRefresh(() => props.api.removePlacement(p.id, pl.placementId), "removed") },
    ];

    const panelPlacementRow = (p: ProjectNode, pl: ProjectNode["placements"][number]) => (
        <div class="tree-subgroup" data-placement={pl.placementId}>
            <div
                class="tree-node placement"
                classList={{ "row-hot": hotRow() === pl.placementId }}
                onPointerEnter={() => setHotRow(pl.placementId)}
                onPointerLeave={() => setHotRow((value) => value === pl.placementId ? null : value)}
                role="treeitem"
                tabindex="0"
                aria-label={`Panel agent ${pl.archetypeName} on ${p.name}`}
                title="Open this placement: pinned contract, Preview, deployments, Inbox"
                onClick={() => {
                    const agent = tree()?.archetypes.find((candidate) => candidate.id === pl.archetypeId);
                    if (agent) props.onOpenPanelAgent?.(agent, p);
                }}
                onKeyDown={(event) => {
                    if (event.key !== "Enter" && event.key !== " ") return;
                    event.preventDefault();
                    const agent = tree()?.archetypes.find((candidate) => candidate.id === pl.archetypeId);
                    if (agent) props.onOpenPanelAgent?.(agent, p);
                }}
                onContextMenu={(event) => openMenu(event, placementMenuItems(p, pl))}
            >
                <AgentKindMark kind="panel" />
                <span class="node-label" data-lineage-archetype={pl.archetypeId}>{mark(pl.archetypeName)}</span>
                <Show when={pl.upgradeAvailable}><button
                    class="upgrade-badge"
                    data-upgrade-available={pl.placementId}
                    title={`v${pl.version} → v${pl.currentVersion} available — click to upgrade`}
                    onClick={(event) => {
                        event.stopPropagation();
                        void withRefresh(() => props.api.upgradePlacement(pl.placementId), "upgraded to the latest version");
                    }}
                >update available</button></Show>
                {rowActions({
                    primary: props.onOpenPanelAgent ? {
                        icon: "panel",
                        title: "Open this Panel agent placement",
                        aria: `open ${pl.archetypeName}`,
                        data: "open-panel-agent",
                        run: () => {
                            const agent = tree()?.archetypes.find((candidate) => candidate.id === pl.archetypeId);
                            if (agent) props.onOpenPanelAgent?.(agent, p);
                        },
                    } : undefined,
                    menuAria: `actions for ${pl.archetypeName} on ${p.name}`,
                    menuItems: () => placementMenuItems(p, pl),
                })}
            </div>
        </div>
    );

    // A Workshop archetype row's menu (shared by right-click and the ⋯ button).
    type ArchetypeNode = Workspace["archetypes"][number];
    const archetypeMenuItems = (a: ArchetypeNode): MenuState["items"] => [
        ...(a.kind === "work"
            ? [{ label: "test in a chat", icon: "eye" as const, hint: "Try this Agent in a Personal work chat", run: () => void useArchetype(a.id) }]
            : props.onOpenPanelAgent
                ? [{ label: "open Preview", icon: "eye" as const, hint: "Open this Panel agent: its edit chat, public contract, and Preview", run: () => props.onOpenPanelAgent?.(a) }]
                : []),
        { label: "new authoring chat", icon: "page-edit", hint: "Open a chat to edit what this Agent does — you review every change before it's kept", run: () => newEditChat(a.id) },
        { label: "new workstream", icon: "child-branch", hint: "Create a shared auto-sync line over this Agent's edit chats", run: () => startEdit({ kind: "new-workstream", placementId: a.instanceId }) },
        { label: "settings", run: () => props.onOpenArchetypeSettings(a.id, a.name, a.kind) },
        { label: "publish a new version", hint: "Make this the current version — placements of it get an upgrade-available notice (UX-9)", run: () => void withRefresh(() => props.api.publishArchetype(a.id), "published a new version") },
        ...(a.kind === "work" ? [{ label: "copy as Panel agent", run: () => void withRefresh(() => props.api.copyAgentAsPanel(a.id), "Panel agent created") }] : []),
        { label: "fork", run: () => void withRefresh(() => props.api.forkArchetype(a.id), "Agent forked") },
        ...(a.forkedFrom
            ? [{ label: "pull updates from source", hint: `Merge improvements from “${a.forkedFromName ?? "the source"}” into this fork (ADR 0038)`, run: () => void withRefresh(() => props.api.pullFromSource(a.id), "pulled updates from the source") }]
            : []),
        { label: "rename", run: () => startEdit({ kind: "rename-archetype", id: a.id }, a.name) },
        ...(a.isDefault
            ? []
            : [{ label: "delete", danger: true, run: () => void withRefresh(() => props.api.deleteArchetype(a.id), "Agent deleted") }]),
    ];

    // The flat `chats` lens body (ADR 0112, NAVLENS-1): every work chat in the
    // project, current-first, the archetype surviving as a quiet row tag on
    // chats from deliberate placements. Selection/creation only — no group
    // headers, no drag sources; join/leave stays in each row's menu, scoped to
    // the chat's own root's lines.
    const flatProjectChats = (p: ProjectNode) => {
        const rank = recentRank();
        const rows = p.placements
            .flatMap((pl) => chatsFor(`${p.name} ${pl.archetypeName}`, pl.chats).map((chat) => ({ chat, pl })))
            .sort((a, b) =>
                (rank.get(a.chat.id) ?? Number.MAX_SAFE_INTEGER) - (rank.get(b.chat.id) ?? Number.MAX_SAFE_INTEGER));
        const projectWorkstreams = (tree()?.workstreams ?? []).filter((workstream) =>
            workstream.projectId === p.id);
        if (rows.length === 0) return <div class="status">no chats yet — start one from the row above</div>;
        return chatGroups(rows.map(({ chat }) => chat), projectWorkstreams);
    };

    // In Agent view, each placement owns its chat rows. A project workstream may
    // include chats from several placements, so show that line under every
    // participating Agent and under its owner even when it is empty.
    const placementChats = (p: ProjectNode, pl: ProjectNode["placements"][number]) => {
        const rank = recentRank();
        const chats = [...chatsFor(`${p.name} ${pl.archetypeName}`, pl.chats)]
            .sort((a, b) => (rank.get(a.id) ?? Number.MAX_SAFE_INTEGER) - (rank.get(b.id) ?? Number.MAX_SAFE_INTEGER));
        const workstreams = (tree()?.workstreams ?? []).filter((ws) =>
            ws.projectId === p.id && (ws.placementId === pl.placementId || chats.some((chat) => chat.workstream === ws.id)));
        return chats.length > 0 || workstreams.length > 0 ? chatGroups(chats, workstreams, true) : null;
    };

    // The structural chat-leaf renderer for Projects and Workshop.
    // One element ⇒ one behavior: select+focus on click, the same rename/delete
    // context menu, the same active styling + kind badge. `meta` is an optional
    // right-aligned lineage label when a rooted tree needs one.
    // A still-unnamed chat carries a generic placeholder title until its first
    // message renames it (#5). Render those as "Untitled" with a 1-based ordinal so
    // two un-started chats never read identically in the same list. A user-chosen
    // title always wins. The placeholder→display logic is shared (state/chat-title)
    // so the tree, All-chats, the chat-lane header, and the TASKS bar all agree (#4).
    // A still-unnamed chat reads "Untitled · {tag}", where the tag is a STABLE
    // token derived from the chat id (round-11 #6) — not its position in the list,
    // which drifts as chats are added/removed. The same chat keeps the same label
    // forever, in every facet. `displayChatTitle` ignores the tag once the chat has
    // a real (user/auto) title, so we can always pass it.
    const displayTitle = (chat: { title: string; id: EngagementId }): string =>
        displayChatTitle(chat.title, untitledTag(chat.id));

    const chatRow = (
        chat: { id: EngagementId; title: string; kind: "edit" | "work"; archived?: boolean; pinned?: boolean; workstream?: WorkstreamId | null; placement?: PlacementId | null; workspaceRoot: WorkspaceRootId; targets?: readonly { targetId: WorkTargetId; name: string; participation: "read-only" | "writable" }[]; rehomeBlocked: boolean; changes?: boolean; conflict?: boolean },
        meta?: string,
        // The placement's workstreams (WS-F), present only in the Projects facet, so a
        // work chat's menu can offer join/leave and its row can badge membership.
        workstreams?: WorkstreamNode[],
        // A flat lens (ADR 0112) is selection-only: rows are not drag sources there,
        // matching Recent — membership changes go through the row menu instead.
        dragSource = true,
        // Recent stays a flat current-first lens, but uses this same canonical
        // chat row and menu. Lineage is presentation context, not another row kind.
        recentLineageLabel?: string,
        nestedUnderAgent = false,
        archivedList = false,
    ) => (
        <Show when={archivedList ? chat.archived : !chat.archived}>
        <>
        <div
            class="tree-leaf chat-item"
            classList={{
                active: props.selected === chat.id,
                dragging: draggingChat()?.id === chat.id,
                "recent-chat-item": Boolean(recentLineageLabel),
                "agent-child": nestedUnderAgent || (chat.kind === "edit" && facet() === "library"),
            }}
            data-chat={chat.id}
            data-recent-chat={recentLineageLabel ? chat.id : undefined}
            data-kind={chat.kind}
            data-mode={chat.kind}
            draggable={dragSource}
            // Keyboard/screen-reader reachable (#4 round-5): the tree rows were plain
            // clickable <div>s with no role/tabindex, so a keyboard or SR user could
            // reach the three facet tabs and the search box and then hit a wall —
            // they couldn't open a single chat. A nested <button> would be invalid
            // here (the row already contains badges and a rename input), so we use the
            // standard tree pattern: role="treeitem" + tabindex + Enter/Space activate.
            role="treeitem"
            tabindex="0"
            aria-label={`open chat ${displayTitle(chat)}${recentLineageLabel ? ` — ${recentLineageLabel}` : ""}${chat.targets?.length ? ` — ${chat.targets.map((target) => `${target.name}${target.participation === "read-only" ? " (read-only)" : ""}`).join(" + ")}` : ""}`}
            title={[recentLineageLabel, chat.targets?.map((target) => `${target.name}${target.participation === "read-only" ? " (read-only)" : ""}`).join(" + "), forkSource(chat.title) ? `Copy of ${forkSource(chat.title)}` : undefined].filter(Boolean).join(" · ")}
            onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    props.onSelect(chat.id);
                }
            }}
            onClick={() => props.onSelect(chat.id)}
            onPointerDown={(event) => {
                if (!dragSource || event.button !== 0) return;
                pointerDrag = {
                    chat: {
                        id: chat.id,
                        title: displayTitle(chat),
                        workspaceRoot: chat.workspaceRoot,
                        workstream: chat.workstream,
                        rehomeBlocked: chat.rehomeBlocked,
                    },
                    x: event.clientX,
                    y: event.clientY,
                };
            }}
            onDragStart={(event) => {
                if (!dragSource) { event.preventDefault(); return; }
                setDraggingChat({
                    id: chat.id,
                    title: displayTitle(chat),
                    workspaceRoot: chat.workspaceRoot,
                    workstream: chat.workstream,
                    rehomeBlocked: chat.rehomeBlocked,
                });
                event.dataTransfer?.setData("text/plain", chat.id);
                event.dataTransfer?.setData(
                    "application/x-gaugedesk-chat",
                    JSON.stringify({ id: chat.id, workspaceRoot: chat.workspaceRoot, workstream: chat.workstream, rehomeBlocked: chat.rehomeBlocked }),
                );
                if (event.dataTransfer) event.dataTransfer.effectAllowed = "move";
            }}
            onDrag={(event) => {
                if (draggingChat() && (event.clientX !== 0 || event.clientY !== 0)) {
                    setDragPointer({ x: event.clientX, y: event.clientY });
                }
            }}
            onDragEnd={() => {
                pointerDrag = null;
                setDropTarget(null);
                // Chromium can dispatch dragend immediately before drop while the
                // delegated Solid handler is still queued. Keep the in-process
                // payload through that turn; a completed drop clears it directly.
                window.setTimeout(() => setDraggingChat(null), 0);
            }}
            onContextMenu={(e) =>
                // A chat's kind (edit/work) is fixed at creation by its root
                // (ADR 0035) — no mid-life toggle.
                openMenu(e, chat.archived ? [
                    { label: "restore", run: () => organizeChat(chat.id, { archived: false }) },
                    { label: "delete permanently", danger: true, confirmHint: "Erases this chat's transcript and unique workspace content", run: () => deleteChat(chat.id) },
                ] : [
                    { label: chat.pinned ? "unpin" : "pin", run: () => organizeChat(chat.id, { pinned: !chat.pinned }) },
                    { label: "archive", run: () => organizeChat(chat.id, { archived: true }) },
                    {
                        label: "fork",
                        run: () =>
                            void withRefresh(async () => {
                                const fid = await forkChatWithRetry(chat);
                                props.onSelect(fid);
                            }, "chat forked"),
                    },
                    { label: "fork tree", hint: "Show this chat's fork lineage (UX-8)", run: () => props.onOpenForkTree(chat.id) },
                    // Workstream membership (WS-F): only settled chats may re-home,
                    // and only among lines carrying the exact same workspace root.
                    ...(!chat.rehomeBlocked && chat.workstream
                        ? [{
                            label: "leave workstream",
                            hint: "Stop auto-syncing — go back to the project mainline",
                            run: () => void leaveWs(chat.workstream!, chat.id),
                        }]
                        : []),
                    ...(workstreams ?? [])
                        // Only lines this chat can join: settled, active, not current, and
                        // carrying exactly the same immutable workspace-root identity.
                        .filter((w) => !chat.rehomeBlocked && w.status === "active" && w.id !== chat.workstream && w.workspaceRoot === chat.workspaceRoot)
                        .map((w) => ({
                            label: `join "${w.name}"`,
                            hint: "Greedily auto-sync this chat's work into the shared line",
                            run: () => void joinWs(w.id, chat.id),
                        })),
                    ...(chat.rehomeBlocked
                        ? [
                            ...(chat.kind === "work" ? [{
                                label: "settle target changes",
                                hint: "Preflight every writable target before applying the chat's immutable change set",
                                run: () => settleChatTargetChanges(chat),
                            }] : []),
                            {
                                label: "settle changes before moving",
                                hint: "Finish, repair, review, or discard this candidate before changing lines",
                                run: () => props.onStatus("this chat has active or unsettled changes and cannot move yet"),
                            },
                        ]
                        : []),
                    ...(chat.kind === "work" && !chat.rehomeBlocked && chat.placement
                        ? [{
                            label: "change targets…",
                            hint: "Add, remove, or change read-only/writable participation before the next turn",
                            run: () => reviseTargets(chat),
                        }]
                        : []),
                    // Start a fresh shared line from this chat (WS-H): works in any facet,
                    // resolving the placement to the chat's own home. Offered when the chat
                    // has a known placement and isn't already on a workstream.
                    ...(!chat.rehomeBlocked && chat.placement && !chat.workstream
                        ? [{
                            label: "new workstream",
                            hint: "Start a shared auto-sync line here and put this chat on it",
                            run: () => startEdit({ kind: "new-workstream-from-chat", placementId: chat.placement!, chat: chat.id }),
                        }]
                        : []),
                    { label: "rename", run: () => startEdit({ kind: "rename-chat", id: chat.id }, chat.title) },
                ])
            }
        >
            <StatusGem
                kind={chat.kind}
                base={nestedUnderAgent || (chat.kind === "edit" && facet() === "library")
                    ? "child-connector"
                    : chat.kind === "edit" && tree()?.archetypes.some((a) => a.kind === "panel" && a.chats.some((c) => c.id === chat.id))
                        ? "panel"
                        : "chat-bubble"}
                tone={props.runToneOf?.(chat.id)}
                conflict={chat.conflict}
            />
            <Show
                when={editingIs("rename-chat", chat.id)}
                fallback={
                    <span class="leaf-label leaf-label-inline">
                        <Show when={forkSource(chat.title)}>
                            {(src) => (
                                <span class="leaf-fork" data-fork-source={src()} title={`Copy of ${src()}`} aria-label={`Copy of ${src()}`}>↳</span>
                            )}
                        </Show>
                        <span class="leaf-title">{mark(displayTitle(chat))}</span>
                        <Show when={searching() && contentMatches().get(chat.id) ? undefined : recentLineageLabel}>
                            {(lineage) => (
                                <span class="leaf-context" data-recent-lineage={chat.id} title={lineage()}>
                                    {mark(lineage())}
                                </span>
                            )}
                        </Show>
                        <Show when={!recentLineageLabel && (chat.targets?.length ?? 0) > 1 && !(searching() && contentMatches().get(chat.id))}>
                            <span class="leaf-context" data-chat-target-count={chat.targets?.length} title={chat.targets?.map((target) => `${target.name}${target.participation === "read-only" ? " (read-only)" : ""}`).join(" + ")}>
                                {(chat.targets ?? []).map((target) =>
                                    `${target.name}${target.participation === "read-only" ? " (read-only)" : ""}`,
                                ).join(" + ")}
                            </span>
                        </Show>
                        {/* Chat-log hit (SEARCH-1): when this row surfaced because the
                            query matched its transcript, show a one-line snippet of the
                            match so the row tells you *why* it stayed — the matched term
                            bolded, like a title hit. */}
                        <Show when={searching() && contentMatches().get(chat.id)}>
                            {(snip) => (
                                <span
                                    class="leaf-context leaf-snippet"
                                    data-snippet={chat.id}
                                    title="matched in this chat's content"
                                >
                                    {mark(snip())}
                                </span>
                            )}
                        </Show>
                    </span>
                }
            >
                {renameInput()}
            </Show>
            <Show when={meta}>
                <span class="leaf-meta" title={`runs the ${meta} Agent`}>{meta}</span>
            </Show>
            <span class="chat-hover-actions">
                <Show when={!chat.archived} fallback={<button type="button" title="Restore chat" aria-label={`Restore ${displayTitle(chat)}`} onClick={(e) => { e.stopPropagation(); organizeChat(chat.id, { archived: false }); }}><Icon name="archive" /></button>}>
                    <button type="button" data-pinned={chat.pinned || undefined} title={chat.pinned ? "Unpin chat" : "Pin chat"} aria-label={`${chat.pinned ? "Unpin" : "Pin"} ${displayTitle(chat)}`} onClick={(e) => { e.stopPropagation(); organizeChat(chat.id, { pinned: !chat.pinned }); }}><Icon name="pin" /></button>
                    <button type="button" title="Archive chat" aria-label={`Archive ${displayTitle(chat)}`} onClick={(e) => { e.stopPropagation(); organizeChat(chat.id, { archived: true }); }}><Icon name="archive" /></button>
                </Show>
            </span>
            <Show when={chat.conflict || chat.changes}>
                <span class="nav-vcs-state" classList={{ conflict: chat.conflict }}
                    title={chat.conflict ? "VCS conflict — resolve changes" : "VCS changes pending"}
                    aria-label={chat.conflict ? "VCS conflict" : "VCS changes pending"}>
                    <Icon name={chat.conflict ? "conflict" : "git-branch"} />
                </span>
            </Show>
        </div>
        {/* Create-a-workstream-from-this-chat (WS-H): the cross-cutting way to start a
            shared line without picking a root — the placement resolves to the chat's own
            home, and the chat joins immediately, so the new line is never an invisible
            empty group. The naming input renders right under the row. */}
        <Show when={(() => { const e = editing(); return e?.kind === "new-workstream-from-chat" && e.chat === chat.id; })()}>
            <div class="tree-leaf ws-new-inline">{renameInput("name this workstream, then Enter")}</div>
        </Show>
        </>
        </Show>
    );

    // Group a chat list by workstream (WS-F): when a named line is active, `Main` is
    // the first header, followed by active named workstreams (name + member count +
    // promote/archive). Without a named line, mainline chats stay ungrouped and quiet.
    // The browse pane groups chats by workstream in each rooted facet. `rootInstanceId`
    // (a placement or an archetype's authoring instance) shows the `+ workstream` create
    // affordance. Each group supplies only its root's workstreams to chatRow, so
    // cross-root destinations never become commands.
    const chatGroups = (
        chats: { id: EngagementId; title: string; kind: "edit" | "work"; workstream?: WorkstreamId | null; placement?: PlacementId | null; workspaceRoot: WorkspaceRootId; targets?: readonly { targetId: WorkTargetId; name: string; participation: "read-only" | "writable" }[]; rehomeBlocked: boolean; changes?: boolean; conflict?: boolean }[],
        workstreams: WorkstreamNode[],
        nestedUnderAgent = false,
    ) => {
        const { groups, main, ungrouped } = groupChatsByWorkstream(chats, workstreams);
        const joinTargets = workstreams;
        return (
            <>
                <Show when={main !== null}>
                    <div
                        class="ws-group"
                        data-main-workstream
                        classList={{ "drop-eligible": canDropOnMain(draggingChat(), draggingChat()?.workspaceRoot) }}
                    >
                        <div
                            class="ws-label"
                            data-main-workstream
                            classList={{
                                "drop-eligible": canDropOnMain(draggingChat(), draggingChat()?.workspaceRoot),
                                "drop-target": dropTarget() === mainDropTarget,
                            }}
                            title="The default workstream. Named workstreams branch from this line."
                            onDragOver={(event) => {
                                event.preventDefault();
                                if (canDropOnMain(draggingChat(), draggingChat()?.workspaceRoot) && event.dataTransfer) {
                                    event.dataTransfer.dropEffect = "move";
                                }
                            }}
                            onDragEnter={() => {
                                if (canDropOnMain(draggingChat(), draggingChat()?.workspaceRoot)) setDropTarget(mainDropTarget);
                            }}
                            onDragLeave={() => {
                                if (dropTarget() === mainDropTarget) setDropTarget(null);
                            }}
                            onDrop={(event) => {
                                const chat = draggedChatFrom(event);
                                event.preventDefault();
                                transferChatToMain(chat, chat?.workspaceRoot);
                            }}
                            onPointerUp={(event) => {
                                const candidate = pointerDrag;
                                if (
                                    candidate &&
                                    Math.hypot(event.clientX - candidate.x, event.clientY - candidate.y) > 8
                                ) {
                                    transferChatToMain(candidate.chat, candidate.chat.workspaceRoot);
                                }
                            }}
                        >
                            <span class="ws-badge" aria-hidden="true">
                                <Icon name="git-branch" />
                            </span>
                            <span class="ws-label-name">Main</span>
                            <Show when={canDropOnMain(draggingChat(), draggingChat()?.workspaceRoot)}>
                                <span class="ws-drop-hint">
                                    {dropTarget() === mainDropTarget ? "Release to move to Main" : "Drop chat on Main"}
                                </span>
                            </Show>
                            <span
                                class="ws-label-count"
                                title={`${main!.length} chat${main!.length === 1 ? "" : "s"} on the main workstream`}
                            >
                                {main!.length}
                            </span>
                        </div>
                        <div class="ws-members">
                            <For each={main!}>
                                {(c) => chatRow(c, undefined, joinTargets, true, undefined, nestedUnderAgent)}
                            </For>
                        </div>
                    </div>
                </Show>
                <For each={groups}>
                    {(g) => (
                        <div
                            class="ws-group"
                            data-workstream={g.ws.id}
                            classList={{ "drop-eligible": canDropOnWorkstream(draggingChat(), g.ws) }}
                        >
                            {/* The shared line is a lightweight grouping label, not a
                                node peer of placements. Merge is a discoverable,
                                double-click-confirmed integration action; archive stays
                                contextual and separately confirmed. */}
                            <div
                                class="ws-label"
                                data-workstream={g.ws.id}
                                classList={{
                                    "drop-eligible": canDropOnWorkstream(draggingChat(), g.ws),
                                    "drop-target": dropTarget() === g.ws.id,
                                }}
                                title="A shared auto-sync line — member chats sync into it automatically. Right-click for actions."
                                onContextMenu={(e) =>
                                    openMenu(e, [
                                        {
                                            label: "promote into mainline",
                                            hint: "Bring this line's settled work into the project mainline (explicit)",
                                            run: () => void promoteWs(g.ws.id),
                                        },
                                        {
                                            label: "archive",
                                            danger: true,
                                            hint: "Close this line — its chats return to the mainline",
                                            run: () => void archiveWs(g.ws.id),
                                        },
                                    ])
                                }
                                onDragOver={(event) => {
                                    // Always accept the drag event so a drop can inspect the
                                    // payload below; only a same-placement payload is acted on.
                                    event.preventDefault();
                                    const chat = draggingChat();
                                    if (canDropOnWorkstream(chat, g.ws)) {
                                        if (event.dataTransfer) event.dataTransfer.dropEffect = "move";
                                    }
                                }}
                                onDragEnter={() => {
                                    const chat = draggingChat();
                                    if (canDropOnWorkstream(chat, g.ws)) {
                                        setDropTarget(g.ws.id);
                                    }
                                }}
                                onDragLeave={() => {
                                    if (dropTarget() === g.ws.id) setDropTarget(null);
                                }}
                                onDrop={(event) => dropChatOnWorkstream(event, g.ws)}
                                onPointerUp={(event) => {
                                    const candidate = pointerDrag;
                                    if (
                                        candidate &&
                                        Math.hypot(event.clientX - candidate.x, event.clientY - candidate.y) > 8
                                    ) {
                                        transferChatToWorkstream(candidate.chat, g.ws);
                                    }
                                }}
                            >
                                <span class="ws-badge" aria-hidden="true">
                                    <Icon name="git-branch" />
                                </span>
                                <span class="ws-label-name">{mark(g.ws.name)}</span>
                                <span class="ws-status" data-collaboration-status={g.ws.collaboration}>
                                    collaboration: {g.ws.collaboration}
                                </span>
                                <span class="ws-status" data-settlement-status={g.ws.targetSettlement}>
                                    targets: {g.ws.targetSettlement}
                                </span>
                                <Show when={canDropOnWorkstream(draggingChat(), g.ws)}>
                                    <span class="ws-drop-hint">
                                        {dropTarget() === g.ws.id ? "Release to move" : "Drop chat here"}
                                    </span>
                                </Show>
                                <span
                                    class="ws-label-count"
                                    title={`${g.chats.length} chat${g.chats.length === 1 ? "" : "s"} on this line`}
                                >
                                    {g.chats.length}
                                </span>
                                <button
                                    type="button"
                                    class="ws-merge"
                                    classList={{ confirming: confirmingMerge() === g.ws.id }}
                                    title={confirmingMerge() === g.ws.id
                                        ? "Click again to merge this workstream into Main"
                                        : "Merge this workstream into Main"}
                                    onClick={(e) => {
                                        e.stopPropagation();
                                        requestPromoteWs(g.ws.id);
                                    }}
                                >
                                    {confirmingMerge() === g.ws.id ? "Confirm merge" : "Merge"}
                                </button>
                            </div>
                            <div class="ws-members">
                                <For each={g.chats}>
                                    {(c) => chatRow(c, undefined, joinTargets, true, undefined, nestedUnderAgent)}
                                </For>
                            </div>
                        </div>
                    )}
                </For>
                <Show when={main === null}>
                    <For each={ungrouped}>{(c) => chatRow(c, undefined, joinTargets, true, undefined, nestedUnderAgent)}</For>
                </Show>
                <For each={workstreams.filter((workstream) =>
                    workstream.status === "promoted" && workstream.promotionManifestRef !== null)}>
                    {(workstream) => (
                        <div class="ws-settlement" data-promoted-workstream={workstream.id}>
                            <div class="ws-label">
                                <span class="ws-label-name">{workstream.name}</span>
                                <span class="ws-status" data-collaboration-status={workstream.collaboration}>
                                    collaboration: promoted
                                </span>
                                <span class="ws-status" data-settlement-status={workstream.targetSettlement}>
                                    target settlement: {workstream.targetSettlement}
                                </span>
                            </div>
                            <For each={workstream.promotionTargets}>
                                {(targetId) => {
                                    const target = () => tree()?.workTargets.find((candidate) => candidate.id === targetId);
                                    const member = () => workstream.targetSettlementMembers.find((candidate) => candidate.targetId === targetId);
                                    const declaration = () => workstream.targetSettlementDeclaration;
                                    return (
                                        <div class="target-settlement-row" data-settlement-target={targetId}>
                                            <span>{target()?.name ?? targetId}</span>
                                            <span>{member()?.phase ?? "not requested"}</span>
                                            <Show when={!member() && target()?.capabilities.apply}>
                                                <button type="button" onClick={() => void settleWsTarget(workstream, target()!, "apply")}>Apply</button>
                                            </Show>
                                            <Show when={!member() && target()?.capabilities.publish}>
                                                <button type="button" onClick={() => void settleWsTarget(workstream, target()!, "publish")}>Publish</button>
                                            </Show>
                                            <Show when={!member() && target()?.capabilities.release}>
                                                <button type="button" onClick={() => void settleWsTarget(workstream, target()!, "release")}>Release</button>
                                            </Show>
                                            <Show when={declaration() && member()?.phase === "unknown"}>
                                                <button type="button" onClick={() => void withRefresh(
                                                    () => props.api.queryTargetSettlementMember(declaration()!, member()!.memberId),
                                                    "queried the target authority",
                                                )}>Query outcome</button>
                                            </Show>
                                            <Show when={declaration() && member()?.phase === "failed"}>
                                                <button type="button" onClick={() => void withRefresh(
                                                    () => props.api.retryTargetSettlementMember(declaration()!, member()!.memberId),
                                                    "retried the proven no-effect target act",
                                                )}>Retry</button>
                                            </Show>
                                            <Show when={declaration() && (member()?.phase === "pending" || member()?.phase === "preflight-passed")}>
                                                <button type="button" onClick={() => void withRefresh(
                                                    () => props.api.cancelTargetSettlement(declaration()!, "cancelled from the workstream settlement panel"),
                                                    "cancelled not-started target acts",
                                                )}>Cancel pending</button>
                                                <button type="button" onClick={() => {
                                                    const later = window.prompt("Later declaration id and member id, separated by a space");
                                                    const [laterDeclarationId, laterMemberId] = later?.trim().split(/\s+/, 2) ?? [];
                                                    if (!laterDeclarationId || !laterMemberId) return;
                                                    void withRefresh(
                                                        () => props.api.supersedeTargetSettlementMember(declaration()!, member()!.memberId, laterDeclarationId, laterMemberId),
                                                        "superseded the not-started target act",
                                                    );
                                                }}>Supersede…</button>
                                            </Show>
                                        </div>
                                    );
                                }}
                            </For>
                            <Show when={workstream.targetSettlementDeclaration}>
                                {(declarationId) => (
                                    <div class="target-settlement-recovery" data-settlement-recovery={declarationId()}>
                                        <button type="button" onClick={() => void withRefresh(
                                            () => props.api.getTargetSettlement(declarationId()),
                                            "refreshed durable settlement diagnostics",
                                        )}>Refresh diagnostics</button>
                                        <Show when={workstream.targetSettlement === "partially-applied"}>
                                            <button type="button" onClick={() => {
                                                const raw = window.prompt("Forward-repair links, one per line: original receipt | later declaration | later member | later receipt");
                                                if (raw === null) return;
                                                const links = raw.split("\n").map((line) => line.split("|").map((value) => value.trim())).filter((parts) => parts.some(Boolean));
                                                if (links.length === 0 || links.some((parts) => parts.length !== 4 || parts.some((part) => !part))) return;
                                                void withRefresh(
                                                    () => props.api.compensateTargetSettlement(declarationId(), links.map((parts) => ({
                                                        original_receipt_ref: parts[0]!,
                                                        compensation_declaration_id: parts[1]!,
                                                        compensation_member_id: parts[2]!,
                                                        compensation_receipt_ref: parts[3]!,
                                                    }))),
                                                    "recorded authenticated forward-repair links",
                                                );
                                            }}>Record compensation…</button>
                                        </Show>
                                        <Show when={workstream.targetSettlement === "partially-applied" || workstream.targetSettlement === "reconciliation-required"}>
                                            <button type="button" onClick={() => {
                                                const reason = window.prompt("Why is this partial settlement being abandoned?");
                                                if (!reason?.trim()) return;
                                                void withRefresh(
                                                    () => props.api.abandonTargetSettlement(declarationId(), reason.trim()),
                                                    "partial settlement abandoned with durable reason",
                                                );
                                            }}>Abandon partial…</button>
                                        </Show>
                                    </div>
                                )}
                            </Show>
                        </div>
                    )}
                </For>
            </>
        );
    };

    return (
        <div class="facet-browser" classList={{ "dragging-workstream": !!draggingChat() }}>
            <div class="facets" role="tablist" aria-label="Browse by">
                <For each={FACETS}>
                    {(f) => (
                        <button
                            type="button"
                            class="facet"
                            role="tab"
                            aria-selected={facet() === f.id}
                            data-facet={f.id}
                            classList={{ active: facet() === f.id }}
                            onClick={() => { setFacet(f.id); setFilterOpen(false); }}
                        >
                            {f.label}
                        </button>
                    )}
                </For>
                {/* Freshness caveat (ADR 0037): the tree is never shown as current
                    when its carriage is not `live` — an explicit "stale, tap to
                    refresh", never a silent stale view. */}
                <Show when={fresh() && fresh()!.marker !== "live"}>
                    <button
                        type="button"
                        class="facet-stale"
                        data-facet-freshness={fresh()!.marker}
                        title={fresh()!.repairHint ?? "refresh"}
                        onClick={() => void refetch()}
                    >
                        {fresh()!.marker} ↻
                    </button>
                </Show>
            </div>
            <div class="facet-toolbar" data-facet-toolbar={facet()}>
                <Show when={facet() === "projects"}>
                    {createBtn("+ project", () => { setStatus("active"); startEdit({ kind: "new-project" }); }, { title: "Create a new project" })}
                </Show>
                <Show when={facet() === "library"}>
                    {createBtn("+ agent", openCreateAgent, { title: "Create an Agent or Panel agent" })}
                </Show>
                <Show when={facet() === "recent"}><span class="facet-toolbar-spacer" /></Show>
                <button type="button" class="facet-toolbar-icon" classList={{ active: searchOpen() }}
                    title={searchOpen() ? "Close search" : "Search"} aria-label={searchOpen() ? "Close search" : "Search"}
                    aria-expanded={searchOpen()} onClick={() => {
                        if (searchOpen()) setQuery("");
                        setSearchOpen(!searchOpen());
                    }}><Icon name="search" /></button>
                <Show when={facet() === "projects"}>
                    <button type="button" class="facet-toolbar-icon" classList={{ active: filterOpen() || grouping() !== "chats" || projectStatus() !== "active" }}
                        data-project-filter title="Filter projects" aria-label="Filter projects" aria-haspopup="menu"
                        aria-expanded={filterOpen()} onClick={() => { setFilterPage("root"); setFilterOpen((value) => !value); }}>
                        <Icon name="sliders" />
                    </button>
                </Show>
                <Show when={filterOpen() && facet() === "projects"}>
                    <div class="facet-filter-backdrop" onClick={() => setFilterOpen(false)} />
                    <div class="facet-filter-menu" role="menu" aria-label="Projects filter" onKeyDown={(event) => event.key === "Escape" && setFilterOpen(false)}>
                        <Show when={filterPage() === "root"}>
                            <button type="button" role="menuitem" onClick={() => setFilterPage("status")}>
                                <span>Status</span><span>{projectStatus() === "active" ? "Active" : projectStatus() === "archived" ? "Archived" : "All"}</span><Icon name="chevron" />
                            </button>
                            <button type="button" role="menuitem" onClick={() => setFilterPage("grouping")}>
                                <span>Group by</span><span>{grouping() === "chats" ? "Recent activity" : "Agent"}</span><Icon name="chevron" />
                            </button>
                        </Show>
                        <Show when={filterPage() === "status"}>
                            <button type="button" class="facet-filter-back" onClick={() => setFilterPage("root")}>‹ Status</button>
                            <For each={(["active", "archived", "all"] as const)}>{(choice) =>
                                <button type="button" role="menuitemradio" aria-checked={projectStatus() === choice} onClick={() => setStatus(choice)}>
                                    <span>{choice === "active" ? "Active" : choice === "archived" ? "Archived" : "All"}</span><span>{projectStatus() === choice ? "✓" : ""}</span>
                                </button>
                            }</For>
                        </Show>
                        <Show when={filterPage() === "grouping"}>
                            <button type="button" class="facet-filter-back" onClick={() => setFilterPage("root")}>‹ Group by</button>
                            <For each={(["chats", "archetype"] as const)}>{(choice) =>
                                <button type="button" role="menuitemradio" aria-checked={grouping() === choice} onClick={() => setGrouping(choice)}>
                                    <span>{choice === "chats" ? "Recent activity" : "Agent view"}</span><span>{grouping() === choice ? "✓" : ""}</span>
                                </button>
                            }</For>
                        </Show>
                    </div>
                </Show>
            </div>
            <Show when={searchOpen()}>
                <div class="facet-search-row">
                    <input class="facet-search" data-testid="facet-search" aria-label="Search projects, Agents, and chats"
                        placeholder="Search projects, Agents, chats…" value={query()}
                        ref={(element) => queueMicrotask(() => element.focus())}
                        onInput={(event) => setQuery(event.currentTarget.value)}
                        onKeyDown={(event) => { if (event.key === "Escape") { setQuery(""); setSearchOpen(false); } }} />
                    <Show when={query()}><button type="button" class="facet-search-clear" data-testid="facet-search-clear"
                        title="Clear search" aria-label="Clear search" onClick={() => setQuery("")}>✕</button></Show>
                </div>
            </Show>

            <Show
                when={navLoadState({ errored: !!carriage.error, hasTree: !!tree() }) !== "error"}
                fallback={<LoadError what="the navigator" onRetry={() => void refetch()} />}
            >
            <Show when={tree()} fallback={<div class="status">loading…</div>}>
                {(t) => (
                    <>
                        {/* RECENT — current-first chats only. This is a flat
                            navigation lens, not a root or a workstream surface: no
                            group headers, create controls, or drag targets. Chat
                            actions still use the canonical row menu. */}
                        <Show when={facet() === "recent"}>
                            <div class="recent-chat-list" data-recent-list role="tree">
                                <For
                                    each={t().recent.filter((chat) => {
                                        const lineage = recentLineage(chat, t().projects, t().workstreams);
                                        return recentVisible(chat, lineage, query(), contentHits());
                                    })}
                                    fallback={<div class="status">no recent chats</div>}
                                >
                                    {(chat) => chatRow(
                                        chat,
                                        undefined,
                                        t().workstreams.filter((workstream) => workstream.workspaceRoot === chat.workspaceRoot),
                                        false,
                                        recentLineage(chat, t().projects, t().workstreams),
                                    )}
                                </For>
                            </div>
                        </Show>

                        {/* PROJECTS — the default facet: project → placements → work chats. */}
                        <Show when={facet() === "projects"}>
                            <Show when={editing()?.kind === "new-project"}>
                                <div class="tree-leaf">{renameInput("name this project, then Enter")}</div>
                            </Show>
                            <Show when={projectStatus() !== "archived" && t().recent.some((chat) => chat.pinned && !chat.archived)}>
                                <section class="chat-collection" aria-label="Pinned chats">
                                    <div class="chat-collection-heading"><Icon name="pin" /> Pinned</div>
                                    <For each={t().recent.filter((chat) => chat.pinned && !chat.archived && recentVisible(chat, recentLineage(chat, t().projects, t().workstreams), query(), contentHits()))}>
                                        {(chat) => chatRow(chat, undefined, undefined, false, recentLineage(chat, t().projects, t().workstreams))}
                                    </For>
                                </section>
                            </Show>
                            <Show when={projectStatus() === "archived" || (projectStatus() === "all" && t().recent.some((chat) => chat.archived))}>
                                <section class="chat-collection" aria-label="Archived chats">
                                    <div class="chat-collection-heading"><Icon name="archive" /> Archived <span>{t().recent.filter((chat) => chat.archived).length}</span></div>
                                    <For each={t().recent.filter((chat) => chat.archived && recentVisible(chat, recentLineage(chat, t().projects, t().workstreams), query(), contentHits()))}
                                        fallback={<div class="status">no archived chats</div>}>
                                        {(chat) => chatRow(chat, undefined, undefined, false, recentLineage(chat, t().projects, t().workstreams), false, true)}
                                    </For>
                                </section>
                            </Show>
                            <Show when={projectStatus() !== "archived"}>
                            <For
                                each={t().projects.filter((p) => projectVisible(p, query(), contentHits()))}
                                fallback={<div class="status">no projects</div>}
                            >
                                {(p) => (
                                    <div class="tree-group" data-project={p.id}>
                                        <div
                                            class="tree-node project"
                                            classList={{ "row-hot": hotRow() === p.id }}
                                            onPointerEnter={() => setHotRow(p.id)}
                                            onPointerLeave={() => setHotRow((v) => (v === p.id ? null : v))}
                                            role="treeitem"
                                            tabindex="0"
                                            aria-expanded={!isCollapsed(p.id)}
                                            aria-label={`project ${p.name}`}
                                            onKeyDown={(e) => {
                                                if (e.key === "Enter" || e.key === " ") { e.preventDefault(); p.product?.kind === "tutorials" ? props.onOpenTutorials?.(p.id) : toggleCollapse(p.id); }
                                            }}
                                            onClick={() => { if (p.product?.kind === "tutorials") props.onOpenTutorials?.(p.id); }}
                                            onContextMenu={(e) => openMenu(e, projectMenuItems(p))}
                                        >
                                            {caret(p.id, true)}
                                            <span class="project-kind-mark" title={p.product?.kind === "tutorials" ? "GaugeWright tutorials" : "Project"} aria-label="Project"><Icon name="folder-open" /></span>
                                            <Show
                                                when={editingIs("rename-project", p.id)}
                                                fallback={<span class="node-label">{mark(p.name)}</span>}
                                            >
                                                {renameInput()}
                                            </Show>
                                            {rowActions({
                                                primary: p.product?.kind !== "tutorials" && canStartProjectChat(p)
                                                    ? {
                                                        icon: "chat-bubble",
                                                        plus: true,
                                                        title: "Start a new chat in this project",
                                                        aria: `new chat in ${p.name}`,
                                                        data: "new-project-chat",
                                                        run: () => void newProjectChat(p),
                                                    }
                                                    : undefined,
                                                secondary: {
                                                    icon: "robot",
                                                    plus: true,
                                                    title: "Add an Agent to this project",
                                                    aria: `add an Agent to ${p.name}`,
                                                    run: () => openAddMethod(p.id, p.name),
                                                },
                                                menuAria: `actions for project ${p.name}`,
                                                menuItems: () => projectMenuItems(p),
                                            })}
                                        </div>
                                        <Show when={!isCollapsed(p.id)}>
                                        <Show when={p.product?.kind === "tutorials"}>
                                            <button type="button" class="tree-leaf" data-tutorial-file="basics.whip" onClick={() => props.onOpenTutorials?.(p.id)}>
                                                basics.whip <span class="muted">by GaugeWright</span>
                                            </button>
                                        </Show>
                                        {/* The flat `chats` lens (ADR 0112, default): every work chat
                                            in the project, current-first, archetype as a row tag. The
                                            workstream naming editor still renders here — the menu's
                                            "new workstream" targets the general placement. */}
                                        <Show when={p.product?.kind !== "tutorials" && grouping() === "chats"}>
                                            {(() => {
                                                const home = p.placements.find((pl) => pl.isDefault);
                                                return <Show when={home}>{wsEditorFor(home!.placementId)}</Show>;
                                            })()}
                                            <div class="project-home" data-project-home={p.id} data-project-lens="chats">
                                                {flatProjectChats(p)}
                                            </div>
                                            <Show when={p.placements.some((placement) => placement.kind === "panel")}>
                                                <div class="panel-agent-list" role="group" aria-label="Panel agents">
                                                    <For each={p.placements.filter((placement) =>
                                                        placement.kind === "panel"
                                                        && placementVisible(p.name, placement, query(), contentHits()))}>
                                                        {(placement) => panelPlacementRow(p, placement)}
                                                    </For>
                                                </div>
                                            </Show>
                                        </Show>
                                        <Show when={p.product?.kind !== "tutorials" && grouping() === "archetype"}>
                                        {/* A chat appears under the Agent placement that created it.
                                            The built-in Default placement is visible in this lens so
                                            its chats have an Agent row too. */}
                                        <For
                                            each={p.placements.filter((pl) => placementVisible(p.name, pl, query(), contentHits()))}
                                        >
                                            {(pl) => (
                                                <div class="tree-subgroup" data-placement={pl.placementId}>
                                                    <div
                                                        class="tree-node placement"
                                                        classList={{ "row-hot": hotRow() === pl.placementId }}
                                                        onPointerEnter={() => setHotRow(pl.placementId)}
                                                        onPointerLeave={() => setHotRow((v) => (v === pl.placementId ? null : v))}
                                                        role="treeitem"
                                                        tabindex="0"
                                                        aria-expanded={pl.kind === "work" && activeChatCount(pl.chats) > 0 ? !isCollapsed(pl.placementId) : undefined}
                                                        aria-label={
                                                            pl.kind === "panel"
                                                                ? `Panel agent ${pl.archetypeName} on ${p.name}`
                                                                : activeChatCount(pl.chats) > 0
                                                                ? `Agent ${pl.archetypeName} on ${p.name} — open its chats`
                                                                : `Agent ${pl.archetypeName} on ${p.name} — start a chat`
                                                        }
                                                        title={pl.kind === "panel" ? "Open this placement: pinned contract, Preview, deployments, Inbox" : activeChatCount(pl.chats) > 0 ? "open this Agent's chats" : "start a chat with this Agent"}
                                                        // Clicking the row is the obvious "start working" path: with no
                                                        // chats yet it opens a new work chat; otherwise it reveals the
                                                        // existing ones (the `+ chat` button always adds another).
                                                        onClick={() =>
                                                            pl.kind === "panel"
                                                                ? (() => {
                                                                    const agent = t().archetypes.find((candidate) => candidate.id === pl.archetypeId);
                                                                    if (agent) props.onOpenPanelAgent?.(agent, p);
                                                                })()
                                                                : activeChatCount(pl.chats) > 0
                                                                ? toggleCollapse(pl.placementId)
                                                                : void newWorkChat(p.id, pl.placementId)
                                                        }
                                                        onKeyDown={(e) => {
                                                            if (e.key === "Enter" || e.key === " ") {
                                                                e.preventDefault();
                                                                if (pl.kind === "panel") {
                                                                    const agent = t().archetypes.find((candidate) => candidate.id === pl.archetypeId);
                                                                    if (agent) props.onOpenPanelAgent?.(agent, p);
                                                                } else if (activeChatCount(pl.chats) > 0) toggleCollapse(pl.placementId);
                                                                else void newWorkChat(p.id, pl.placementId);
                                                            }
                                                        }}
                                                        onContextMenu={(e) => openMenu(e, placementMenuItems(p, pl))}
                                                    >
                                                        {caret(pl.placementId, pl.kind === "work" && activeChatCount(pl.chats) > 0)}
                                                        <AgentKindMark kind={pl.kind} />
                                                        {/* Just the method name here (round-6 #6): this row is
                                                            already nested under its project, so the "· project"
                                                            half of the old lineage was redundant noise. Keep a
                                                            stable hook for the pivot via the data attribute. */}
                                                        <span class="node-label" data-lineage-archetype={pl.archetypeId} title="the Agent this placement runs">{mark(pl.archetypeName)}</span>
                                                        {/* This placement carries client-specific config/notes
                                                            (config-only customization, no fork). */}
                                                        <Show when={pl.hasConfig}>
                                                            <span class="cfg-badge" data-placement-customized={pl.placementId} title="Customized for this project (config + notes, no fork)">customized</span>
                                                        </Show>
                                                        {/* APPROVE-1: this placement is pending approval — click to accept
                                                            it (the owner's second act), after which it can host work chats. */}
                                                        <Show when={pl.pending}>
                                                            <button
                                                                class="pending-badge"
                                                                data-placement-pending={pl.placementId}
                                                                title="Pending approval — click to accept so this Agent can host work chats"
                                                                onClick={(e) => { e.stopPropagation(); void withRefresh(() => props.api.acceptPlacement(pl.placementId), "placement accepted"); }}
                                                            >
                                                                pending — accept
                                                            </button>
                                                        </Show>
                                                        {/* UX-9: a newer archetype version is published — a notice,
                                                            not an action (manual by default, ADR 0063). Click to take
                                                            the upgrade. */}
                                                        <Show when={pl.upgradeAvailable}>
                                                            <button
                                                                class="upgrade-badge"
                                                                data-upgrade-available={pl.placementId}
                                                                title={`v${pl.version} → v${pl.currentVersion} available — click to upgrade`}
                                                                onClick={(e) => { e.stopPropagation(); void withRefresh(() => props.api.upgradePlacement(pl.placementId), "upgraded to the latest version"); }}
                                                            >
                                                                update available
                                                            </button>
                                                        </Show>
                                                        {rowActions({
                                                            primary: pl.kind === "work" ? {
                                                                icon: "chat-bubble",
                                                                plus: true,
                                                                title: "Start a new chat with this Agent",
                                                                aria: `new chat with ${pl.archetypeName}`,
                                                                data: "new-placement-chat",
                                                                run: () => void newWorkChat(p.id, pl.placementId),
                                                            } : props.onOpenPanelAgent ? {
                                                                icon: "panel",
                                                                title: "Open this Panel agent placement",
                                                                aria: `open ${pl.archetypeName}`,
                                                                data: "open-panel-agent",
                                                                run: () => {
                                                                    const agent = t().archetypes.find((candidate) => candidate.id === pl.archetypeId);
                                                                    if (agent) props.onOpenPanelAgent?.(agent, p);
                                                                },
                                                            } : undefined,
                                                            menuAria: `actions for ${pl.archetypeName} on ${p.name}`,
                                                            menuItems: () => placementMenuItems(p, pl),
                                                        })}
                                                    </div>
                                                    <Show when={pl.kind === "work" && !isCollapsed(pl.placementId)}>
                                                        {wsEditorFor(pl.placementId)}
                                                        {placementChats(p, pl)}
                                                    </Show>
                                                </div>
                                            )}
                                        </For>
                                        </Show>
                                        </Show>
                                    </div>
                                )}
                            </For>
                            </Show>
                        </Show>

                        {/* LIBRARY — archetypes (the methods) → edit chats. */}
                        <Show when={facet() === "library"}>
                            <For
                                each={t().archetypes.filter((a) => archetypeVisible(a, query(), contentHits()))}
                                fallback={<div class="status">no Agents yet</div>}
                            >
                                {(a) => (
                                    <div class="tree-group" data-archetype={a.id}>
                                        <div
                                            class="tree-node archetype"
                                            classList={{ "row-hot": hotRow() === a.id }}
                                            onPointerEnter={() => setHotRow(a.id)}
                                            onPointerLeave={() => setHotRow((v) => (v === a.id ? null : v))}
                                            role="treeitem"
                                            tabindex="0"
                                            aria-expanded={archetypeHasChildren(a) ? !isCollapsed(a.id) : undefined}
                                            aria-label={`${a.kind === "panel" ? "Panel agent" : "Agent"} ${a.name}`}
                                            title={`Open ${a.name} settings`}
                                            onClick={() => {
                                                if (!editingIs("rename-archetype", a.id)) props.onOpenArchetypeSettings(a.id, a.name, a.kind);
                                            }}
                                            onKeyDown={(e) => {
                                                if (e.key !== "Enter" && e.key !== " ") return;
                                                e.preventDefault();
                                                props.onOpenArchetypeSettings(a.id, a.name, a.kind);
                                            }}
                                            onContextMenu={(e) => openMenu(e, archetypeMenuItems(a))}
                                        >
                                            {caret(a.id, archetypeHasChildren(a))}
                                            <AgentKindMark kind={a.kind} settings />
                                            <Show
                                                when={editingIs("rename-archetype", a.id)}
                                                fallback={<span class="node-label">{mark(a.name)}</span>}
                                            >
                                                {renameInput()}
                                            </Show>
                                            {rowActions({
                                                menuAria: `actions for Agent ${a.name}`,
                                                menuIcon: "plus",
                                                menuItems: () => archetypeMenuItems(a),
                                            })}
                                        </div>
                                        <Show when={!isCollapsed(a.id)}>
                                        {/* Fork lineage (ADR 0038): a fork shows its source so you know it
                                            tracks an upstream method — "pull updates from source" (its menu)
                                            merges the source's improvements down. */}
                                        <Show when={a.forkedFrom}>
                                            <div class="fork-lineage muted" data-forked-from={a.forkedFrom!}>
                                                ↰ forked from {a.forkedFromName ?? "another method"}
                                            </div>
                                        </Show>
                                        {/* Workshop is where you EDIT and TEST a method: edit is the row's
                                            primary action; test and the shared-line create live in the row
                                            menu (ADR 0112) — several edit chats can be open at once, and
                                            the merge model keeps them in sync. */}
                                        {wsEditorFor(a.instanceId)}
                                        {/* The method's edit chats, grouped by workstream (WS-F). */}
                                        {chatGroups(chatsFor(a.name, a.chats), a.workstreams)}
                                        </Show>
                                    </div>
                                )}
                            </For>
                        </Show>

                    </>
                )}
            </Show>

            <Show when={newAgentOpen()}>
                <div class="modal-overlay" data-create-agent onClick={() => { if (!creatingAgent()) setNewAgentOpen(false); }}>
                    <form
                        class="modal create-agent-dialog"
                        role="dialog"
                        aria-modal="true"
                        aria-labelledby="create-agent-title"
                        onClick={(event) => event.stopPropagation()}
                        onKeyDown={createAgentKeyDown}
                        onSubmit={(event) => void submitNewAgent(event)}
                    >
                        <div class="modal-head">
                            <div>
                                <span class="create-agent-eyebrow">Workshop</span>
                                <h3 id="create-agent-title">Create an agent</h3>
                            </div>
                            <button type="button" class="create-agent-close" aria-label="Close" disabled={creatingAgent()} onClick={() => setNewAgentOpen(false)}>×</button>
                        </div>
                        <p class="create-agent-intro">Choose where this agent will work. You can shape its behavior after creating it.</p>
                        <div class="create-agent-kinds" role="group" aria-label="Agent type">
                            <button type="button" class="create-agent-kind" classList={{ selected: newAgentKind() === "work" }} aria-pressed={newAgentKind() === "work"} disabled={creatingAgent()} onClick={() => setNewAgentKind("work")}>
                                <strong>Agent</strong>
                                <span>Works with you in project chats</span>
                            </button>
                            <button type="button" class="create-agent-kind" classList={{ selected: newAgentKind() === "panel" }} aria-pressed={newAgentKind() === "panel"} disabled={creatingAgent()} onClick={() => setNewAgentKind("panel")}>
                                <strong>Panel agent</strong>
                                <span>Runs in an embeddable panel</span>
                            </button>
                        </div>
                        <label class="create-agent-name">
                            <span>Name</span>
                            <input
                                ref={(element) => queueMicrotask(() => element.focus())}
                                value={newAgentName()}
                                onInput={(event) => { setNewAgentName(event.currentTarget.value); setCreateAgentError(""); }}
                                placeholder="Give this agent a name"
                                autocomplete="off"
                                disabled={creatingAgent()}
                                required
                            />
                        </label>
                        <Show when={createAgentError()}><p class="create-agent-error" role="alert">{createAgentError()}</p></Show>
                        <div class="create-agent-actions">
                            <button type="button" disabled={creatingAgent()} onClick={() => setNewAgentOpen(false)}>Cancel</button>
                            <button type="submit" class="create-agent-submit" disabled={!newAgentName().trim() || creatingAgent()}>
                                {creatingAgent() ? "Creating…" : `Create ${newAgentKind() === "panel" ? "Panel agent" : "agent"}`}
                            </button>
                        </div>
                    </form>
                </div>
            </Show>
            </Show>

            <ContextMenu menu={menu()} onClose={() => setMenu(null)} />
            <Show when={draggingChat()}>
                {(chat) => (
                    <div
                        class="ws-drag-ghost"
                        classList={{ blocked: chat().rehomeBlocked }}
                        aria-hidden="true"
                        style={{ left: `${dragPointer().x + 14}px`, top: `${dragPointer().y + 14}px` }}
                    >
                        <Icon name="robot" />
                        <span>{chat().rehomeBlocked ? `${chat().title} · settle changes before moving` : chat().title}</span>
                    </div>
                )}
            </Show>

            {/* Per-placement customization (placement.md): config-only tweaks for one
                project/client — a `.agent-config.json` overlay + notes, applied to new
                chats here, without forking the shared method. Closes on backdrop / Escape. */}
            <Show when={configFor()}>
                {(f) => (
                    <div class="modal-overlay" data-placement-config onClick={() => setConfigFor(null)}>
                        <div class="modal" onClick={(e) => e.stopPropagation()} onKeyDown={(e) => e.key === "Escape" && setConfigFor(null)}>
                            <div class="modal-head">
                                <h3>Customize “{f().name}”</h3>
                                <button type="button" onClick={() => setConfigFor(null)}>close</button>
                            </div>
                            <p class="muted">
                                Config-only — tweaks this method for this project without forking it. Applies to new chats here; the shared method is untouched.
                            </p>
                            <label class="cfg-field">
                                <span>Config overlay (JSON) — overrides the method's defaults</span>
                                <textarea
                                    data-cfg-config
                                    rows={5}
                                    spellcheck={false}
                                    disabled={cfgStatus() === "loading…"}
                                    value={cfgConfig()}
                                    onInput={(e) => setCfgConfig(e.currentTarget.value)}
                                    placeholder={'{ "model": "claude-opus-4-8" }'}
                                />
                            </label>
                            <label class="cfg-field">
                                <span>Project notes — context fed to the method on every chat here</span>
                                <textarea
                                    data-cfg-notes
                                    rows={5}
                                    disabled={cfgStatus() === "loading…"}
                                    value={cfgNotes()}
                                    onInput={(e) => setCfgNotes(e.currentTarget.value)}
                                    placeholder="e.g. AcmeCo prefers terse, formal output; never mention competitors."
                                />
                            </label>
                            <div class="modal-actions">
                                <button
                                    type="button"
                                    class="create-btn"
                                    data-cfg-save
                                    disabled={cfgStatus() === "loading…"}
                                    onClick={() => void saveConfig()}
                                >Save</button>
                            </div>
                            <p class="status" data-cfg-status>{cfgStatus()}</p>
                        </div>
                    </div>
                )}
            </Show>

            <Show when={targetChoice()}>
                {(choice) => (
                    <div class="modal-overlay" data-target-picker onClick={() => setTargetChoice(null)}>
                        <div
                            class="modal place-picker"
                            role="dialog"
                            aria-modal="true"
                            aria-label="Choose work target"
                            onClick={(e) => e.stopPropagation()}
                            onKeyDown={(e) => e.key === "Escape" && setTargetChoice(null)}
                        >
                            <div class="modal-head">
                                <h3>{choice().kind === "chat" ? "Choose one or more targets" : "Change chat targets"}</h3>
                                <button onClick={() => setTargetChoice(null)}>close</button>
                            </div>
                            <p class="status" style={{ margin: "0 0 8px" }}>
                                Each target keeps its own basis, permissions, diff, and settlement status.
                            </p>
                            <div class="picker-list">
                                <For each={choice().targets}>
                                    {(target) => (
                                        <button
                                            type="button"
                                            class="picker-row target-picker-row"
                                            data-target-choice={target.id}
                                            aria-pressed={targetChoiceParticipation(choice(), target.id) !== null}
                                            onClick={() => toggleTarget(target)}
                                        >
                                            <span>{choice().kind === "chat"
                                                ? targetChoiceParticipation(choice(), target.id) ? "✓ " : ""
                                                : targetChoiceParticipation(choice(), target.id) === "writable" ? "✎ "
                                                : targetChoiceParticipation(choice(), target.id) === "read-only" ? "◉ " : ""}{target.name}</span>
                                            <small>
                                                {target.capabilities.propose ? "writable" : "read-only"} · {target.kind} · {target.concurrency}
                                                {target.concurrency === "compare-before-write-weak" ? " (no multi-writer guarantee)" : ""}
                                                {` · ${target.currentBasis ?? "basis unavailable"}`}
                                            </small>
                                        </button>
                                    )}
                                </For>
                            </div>
                            <div class="modal-actions">
                                <button type="button" onClick={() => setTargetChoice(null)}>Cancel</button>
                                <button
                                    type="button"
                                    data-create-multi-target-chat
                                    disabled={choice().selected.length === 0}
                                    onClick={() => void confirmTargetChoice()}
                                >
                                    {choice().kind === "chat" ? "Start chat with" : "Save"} {choice().selected.length || "selected"} target{choice().selected.length === 1 ? "" : "s"}
                                </button>
                            </div>
                        </div>
                    </div>
                )}
            </Show>

            {/* The place picker (#1): pick the other end of a placement. From a
                project you choose an archetype; from an archetype you choose a project.
                One screen, with a "create new" row so an empty library is not a
                dead end. Closes on backdrop click / Escape. */}
            <Show when={picker()}>
                {(pk) => (
                    <div class="modal-overlay" data-place-picker onClick={() => setPicker(null)}>
                        <div
                            class="modal place-picker"
                            onClick={(e) => e.stopPropagation()}
                            onKeyDown={(e) => e.key === "Escape" && setPicker(null)}
                        >
                            <div class="modal-head">
                                <h3>{pickerTitle(pk())}</h3>
                                <button onClick={() => setPicker(null)}>close</button>
                            </div>
                            <p class="status" style={{ margin: "0 0 8px" }}>
                                {pk().dir === "to-project"
                                    ? "Choose an Agent to install on this project."
                                    : "Choose a project for this Agent."}
                            </p>
                            <input
                                class="picker-search"
                                autofocus
                                data-picker-search
                                aria-label={pk().dir === "to-project" ? "Find an Agent to add" : "Find a project for this Agent"}
                                placeholder={pk().dir === "to-project" ? "find an Agent…" : "find a project…"}
                                value={pickerQuery()}
                                onInput={(e) => setPickerQuery(e.currentTarget.value)}
                            />
                            <div class="picker-list" data-picker-list>
                                {/* Method side: choose which library method to install. */}
                                <Show when={pk().dir === "to-project" ? pk() : null} keyed>
                                    {(p) => p.dir === "to-project" && (
                                        <>
                                            <For
                                                each={(tree()?.archetypes ?? []).filter((a) =>
                                                    a.name.toLowerCase().includes(pickerQuery().trim().toLowerCase()),
                                                )}
                                                fallback={<div class="status">No Agents yet — create one in the Workshop first.</div>}
                                            >
                                                {(a) => (
                                                    <button
                                                        type="button"
                                                        class="picker-row"
                                                        data-picker-archetype={a.id}
                                                        onClick={() => placeChosen(p.pid, a)}
                                                    >
                                                        {a.name} <span class="muted">· {a.kind === "panel" ? "Panel agent" : "Agent"}</span>
                                                    </button>
                                                )}
                                            </For>
                                            {/* Empty-library escape hatch: jump to the Workshop to
                                                define a new Agent, so the picker is never a dead end. */}
                                            <button
                                                type="button"
                                                class="picker-row picker-create"
                                                data-picker-create
                                                onClick={() => { setPicker(null); setFacet("library"); openCreateAgent(); }}
                                            >
                                                + create a new Agent
                                            </button>
                                        </>
                                    )}
                                </Show>
                            </div>
                        </div>
                    </div>
                )}
            </Show>
        </div>
    );

    function pickerTitle(p: NonNullable<ReturnType<typeof picker>>): string {
        return `Add an Agent to ${p.projectName}`;
    }

    // Open the picker to add a method to a project (#1) — the user chooses *which*
    // method, rather than the app silently placing an arbitrary one. (The reverse
    // "place this archetype on a project" direction was retired by ADR 0045: an
    // archetype is usable in Personal with no placement, so the only deliberate
    // placement left is adding a method into a specific named project, from here.)
    function openAddMethod(pid: ProjectId, projectName: string) {
        setPickerQuery("");
        setPicker({ dir: "to-project", pid, projectName });
    }
    // Commit a placement once a method is chosen, then close the picker.
    async function placeChosen(pid: ProjectId, agent: Workspace["archetypes"][number]) {
        setPicker(null);
        await withRefresh(async () => {
            const recipient = agent.kind === "panel" && agent.panelProfile?.collection
                ? await props.api.ensureCollectionRecipient?.(`${pid}-${agent.id}`)
                : undefined;
            await props.api.placeArchetype(pid, agent.id, recipient);
        }, `placed ${agent.name}`);
    }
}
