/**
 * The facet browser (`navigation.md` B2, ADR 0035/0036): the nav is
 * **project-first** — facets **Recent | Projects | Library**, defaulting to
 * Projects. It renders a projection (`GET /workspace`) and submits commands; it
 * never owns truth (`INV-5`).
 *
 * The model (ADR 0035): an **archetype** is the reusable, named behaviour shown
 * in the Library (the UI calls it an "archetype" throughout); a
 * **placement** is an archetype installed on a **project** (Projects) — what you
 * chat with to do work. A chat's **kind** is its ROOT, fixed at creation: rooted
 * on an archetype ⇒ an **edit** chat; rooted on a placement ⇒ a **work** chat.
 * There is no mode toggle. The default "Personal" project is explicit (ADR 0097).
 *
 * The archetype↔placement relation is many-to-many and navigable **both ways**
 * (the C1 pivot): a placement shows its archetype's name as lineage, and an
 * archetype lists everywhere it is placed.
 */

import { createEffect, createMemo, createResource, createSignal, For, onCleanup, Show, type JSX } from "solid-js";
import { createStore, reconcile } from "solid-js/store";
import {
    Rejected,
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
import { Icon } from "./icons";
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

/** A project's child grouping (ADR 0112, NAVLENS-1): `chats` renders the
 *  project's work chats flat and current-first (the default); `archetype`
 *  renders the structural placement view where workstream headers, drag, and
 *  Merge live. Local UI state, persisted per project. */
type ProjectLens = "chats" | "archetype";
const LENS_KEY = "ui.navLens";

function readStoredLenses(): Record<string, ProjectLens> {
    try {
        const raw = window.localStorage?.getItem(LENS_KEY);
        if (!raw) return {};
        const parsed = JSON.parse(raw) as Record<string, unknown>;
        return Object.fromEntries(
            Object.entries(parsed).filter(([, v]) => v === "chats" || v === "archetype"),
        ) as Record<string, ProjectLens>;
    } catch {
        return {};
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
    if (methods > 0) parts.push(`${methods} archetype${methods === 1 ? "" : "s"}`);
    if (chats > 0) parts.push(`${chats} chat${chats === 1 ? "" : "s"}`);
    return `also removes ${parts.join(" and ")} — this can't be undone`;
}

const FACETS: { id: Facet; label: string }[] = [
    { id: "recent", label: "Recent" },
    { id: "projects", label: "Projects" },
    { id: "library", label: "Library" },
];

export interface FacetBrowserApi {
    getWorkspaceCarriage(): Promise<ProjectionCarriage<Workspace>>;
    /** Mobile's ADR 0037 reference resolver. Optional because the desktop shell
     * keeps its existing full-refresh policy; `deltaSync` requires both methods. */
    getWorkspaceDeltaCarriage?(change: WorkspaceChange): Promise<ProjectionCarriage<WorkspaceDelta>>;
    subscribeWorkspace?(onChange: (change: WorkspaceChange) => void): () => void;
    search(query: string): Promise<SearchHit[]>;
    getPlacementConfig(placementId: PlacementId): Promise<{ config: string; notes: string }>;
    setPlacementConfig(placementId: PlacementId, config: string, notes: string): Promise<void>;
    createArchetype(name: string): Promise<ArchetypeId>;
    createProject(name: string): Promise<ProjectId>;
    renameArchetype(id: ArchetypeId, name: string): Promise<void>;
    renameProject(id: ProjectId, name: string): Promise<void>;
    renameChat(id: EngagementId, title: string): Promise<void>;
    createWorkstream(placementId: PlacementId, name: string, targetId: WorkTargetId): Promise<WorkstreamNode>;
    joinWorkstream(ws: WorkstreamId, chat: EngagementId): Promise<void>;
    leaveWorkstream(ws: WorkstreamId, chat: EngagementId): Promise<void>;
    promoteWorkstream(ws: WorkstreamId): Promise<void>;
    archiveWorkstream(ws: WorkstreamId): Promise<void>;
    createChatUnderArchetype(archetypeId: ArchetypeId, title: string): Promise<EngagementId>;
    createChatUnderPlacement(pid: ProjectId, placementId: PlacementId, title: string, targetId: WorkTargetId): Promise<EngagementId>;
    useArchetype(archetypeId: ArchetypeId, title: string): Promise<EngagementId>;
    createEngagement(): Promise<Engagement>;
    deleteChat(id: EngagementId): Promise<void>;
    forkChat(id: EngagementId): Promise<EngagementId>;
    deleteProject(id: ProjectId): Promise<void>;
    upgradePlacement(placementId: PlacementId): Promise<number>;
    acceptPlacement(placementId: PlacementId): Promise<void>;
    removePlacement(pid: ProjectId, placementId: PlacementId): Promise<void>;
    publishArchetype(id: ArchetypeId, autoUpgrade?: boolean): Promise<{ version: number; autoUpgraded: number }>;
    forkArchetype(id: ArchetypeId, name?: string): Promise<ArchetypeId>;
    pullFromSource(id: ArchetypeId): Promise<void>;
    deleteArchetype(id: ArchetypeId): Promise<void>;
    placeArchetype(pid: ProjectId, archetypeId: ArchetypeId): Promise<PlacementId>;
}

export function FacetBrowser(props: {
    api: FacetBrowserApi;
    selected: EngagementId | null;
    onSelect: (id: EngagementId) => void;
    onOpenArchetypeSettings: (id: ArchetypeId, name: string) => void;
    /** Open the per-project Engagement pane (hand off / share a project, FED-7). */
    onOpenEngagement: (id: ProjectId, name: string) => void;
    onOpenModelAccess: (id: ProjectId, name: string) => void;
    onOpenProjectHome: (id: ProjectId, name: string) => void;
    /** Hand the exact tested placement to the managed website-deployment flow. */
    onDeployPlacement?: (selection: {
        projectId: ProjectId;
        projectName: string;
        placementId: PlacementId;
        archetypeName: string;
        reviewChatId?: EngagementId;
    }) => void;
    onAttachTarget?: (id: ProjectId, name: string, kind: "external-vcs" | "external-folder") => void;
    onOpenForkTree: (chat: EngagementId) => void;
    onChatDeleted: (id: EngagementId) => void;
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
        const v = carriage()?.value;
        if (v) setDeltaFreshness(null);
        setStore("tree", v ? reconcile(v, { key: "id" }) : null);
    });
    const tree = () => store.tree ?? undefined;
    const fresh = () => deltaFreshness() ?? carriage()?.freshness;

    // Mobile resolves the reference-only SSE one event at a time. Serializing the
    // queue prevents a slower, older response from overwriting a newer patch; each
    // delta removes the referenced record globally before inserting the server's
    // current parent nodes. A failed delta falls back to one honest full refresh.
    createEffect(() => {
        if (!props.deltaSync) return;
        if (!props.api.subscribeWorkspace || !props.api.getWorkspaceDeltaCarriage) return;
        let active = true;
        let queue = Promise.resolve();
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
    const chatsFor = <T extends { title: string; id?: EngagementId }>(label: string, chats: T[]) =>
        childrenFor(label, chats, query(), contentHits());

    const [menu, setMenu] = createSignal<MenuState | null>(null);
    // Row-tool reveal driven by pointer EVENTS, not CSS :hover (ADR 0112).
    // Chrome on Linux/Wayland can desync its hover flag from style resolution
    // (element.matches(':hover') true while :hover rules never apply — observed
    // live 2026-07-28); pointerenter/leave keep firing in that state, so a
    // class toggle stays reliable where the pseudo-class silently isn't.
    const [hotRow, setHotRow] = createSignal<string | null>(null);
    // Per-project lens (ADR 0112): which facet organizes a project's children.
    const [lenses, setLenses] = createSignal<Record<string, ProjectLens>>(readStoredLenses());
    const lensOf = (id: ProjectId): ProjectLens => lenses()[id] ?? "chats";
    const setLens = (id: ProjectId, lens: ProjectLens) =>
        setLenses((m) => {
            const next = { ...m, [id]: lens };
            try {
                window.localStorage?.setItem(LENS_KEY, JSON.stringify(next));
            } catch {
                /* storage unavailable — the lens lives for this session only */
            }
            return next;
        });
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
    // inline editor: creating or renaming a named node.
    const [editing, setEditing] = createSignal<
        | { kind: "new-archetype" }
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

    // The "add a method" picker (#1): from a project, choose *which* archetype to
    // install on it, rather than the app silently placing an arbitrary one. (The
    // reverse "place this archetype on a project" direction was retired by ADR 0045
    // — an archetype is usable in Personal with no placement.)
    const [picker, setPicker] = createSignal<
        { dir: "to-project"; pid: ProjectId; projectName: string } | null
    >(null);
    const [pickerQuery, setPickerQuery] = createSignal("");
    const [targetChoice, setTargetChoice] = createSignal<
        | { kind: "chat"; pid: ProjectId; placementId: PlacementId; targets: WorkTargetNode[] }
        | { kind: "workstream"; placementId: PlacementId; name: string; targets: WorkTargetNode[]; joinChat?: EngagementId }
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
    const archetypeHasChildren = (a: { id: string; chats: unknown[] }) =>
        a.chats.length > 0 || (placementsOf().get(a.id)?.length ?? 0) > 0;
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

    async function commitEdit() {
        const e = editing();
        const text = editText().trim();
        setEditing(null);
        if (!e || !text) return;
        switch (e.kind) {
            case "new-archetype":
                // "method" everywhere in the user-facing string (round-6 #3): the
                // create flow says "+ archetype" / "place this method" — the success
                // toast must not leak the implementation word "archetype".
                return withRefresh(() => props.api.createArchetype(text), `archetype "${text}" created`);
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
        await withRefresh(() => props.api.promoteWorkstream(wsId), "promoted the workstream into the mainline");
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

    // An EDIT chat is rooted on an archetype (improve the method).
    async function newEditChat(archetypeId: ArchetypeId) {
        await withRefresh(async () => {
            const id = await props.api.createChatUnderArchetype(archetypeId, "edit chat");
            props.onSelect(id);
        }, "editing this archetype");
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
            .filter((target): target is WorkTargetNode => !!target && target.status === "available" && target.capabilities.propose);
    }

    async function newWorkChat(pid: ProjectId, placementId: PlacementId, targetId?: WorkTargetId) {
        const targets = targetsForPlacement(placementId);
        const selected = targetId ? targets.find((target) => target.id === targetId) : targets[0];
        if (!targetId && targets.length > 1) {
            setTargetChoice({ kind: "chat", pid, placementId, targets });
            return;
        }
        if (!selected) {
            props.onStatus("no available work target can accept proposals");
            return;
        }
        await withRefresh(async () => {
            const id = await props.api.createChatUnderPlacement(pid, placementId, "new chat", selected.id);
            props.onSelect(id);
        }, "new work chat");
    }

    async function createNamedWorkstream(placementId: PlacementId, name: string, joinChat?: EngagementId) {
        const chatTarget = joinChat
            ? tree()?.recent.find((chat) => chat.id === joinChat)?.targetId
            : undefined;
        const targets = targetsForPlacement(placementId);
        const selected = chatTarget ? targets.find((target) => target.id === chatTarget) : targets[0];
        if (!chatTarget && targets.length > 1) {
            setTargetChoice({ kind: "workstream", placementId, name, targets, joinChat });
            return;
        }
        if (!selected) {
            props.onStatus("no available work target can host this workstream");
            return;
        }
        await withRefresh(async () => {
            const ws = await props.api.createWorkstream(placementId, name, selected.id);
            if (joinChat) await props.api.joinWorkstream(ws.id, joinChat);
        }, `workstream "${name}" created`);
    }

    async function chooseTarget(target: WorkTargetNode) {
        const choice = targetChoice();
        setTargetChoice(null);
        if (!choice) return;
        if (choice.kind === "chat") {
            await newWorkChat(choice.pid, choice.placementId, target.id);
            return;
        }
        await withRefresh(async () => {
            const ws = await props.api.createWorkstream(choice.placementId, choice.name, target.id);
            if (choice.joinChat) await props.api.joinWorkstream(ws.id, choice.joinChat);
        }, `workstream "${choice.name}" created`);
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
            props.onChatDeleted(id);
        }, "chat deleted");
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
            onBlur={commitEdit}
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

    // ADR 0112 (NAVLENS-2): a container row's actions — one primary icon act plus
    // a ⋯ button opening the row's context menu — revealed on row hover or
    // keyboard focus. Replaces the always-visible chip rows; right-click still
    // opens the same menu.
    const rowActions = (opts: {
        /** Extra control rendered before the buttons (the project lens chip). */
        lead?: JSX.Element;
        primary?: { icon: "robot" | "pencil"; title: string; aria: string; data?: string; run: () => void };
        menuAria: string;
        menuItems: () => MenuState["items"];
    }) => (
        <span class="row-actions">
            {opts.lead}
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
                        <Show when={primary.icon === "robot"}>
                            <i class="row-act-plus" aria-hidden="true">+</i>
                        </Show>
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
                <Icon name="kebab" class="icon" />
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
        const home = p.placements.find((pl) => pl.isDefault)?.placementId;
        const lens = lensOf(p.id);
        return [
            ...(canStartProjectChat(p) ? [
                { label: "new chat", hint: "Start a new chat in this project", run: () => void newProjectChat(p) },
            ] : []),
            ...(home ? [
                { label: "new workstream", hint: "Create a shared auto-sync line in this project", run: () => startEdit({ kind: "new-workstream", placementId: home }) },
            ] : []),
            ...(lens === "chats"
                ? p.placements
                    .filter((pl) => !pl.isDefault)
                    .map((pl) => ({
                        label: `new chat with ${pl.archetypeName}`,
                        hint: "Start a chat rooted on this archetype's placement in this project",
                        run: () => void newWorkChat(p.id, pl.placementId),
                    }))
                : []),
            {
                label: lens === "chats" ? "group by archetype" : "flat chats",
                hint: lens === "chats"
                    ? "Show this project's placements as structure (workstreams, drag, merge live there)"
                    : "Show this project's chats as one flat, current-first list",
                run: () => setLens(p.id, lens === "chats" ? "archetype" : "chats"),
            },
            { label: "add an archetype", run: () => openAddMethod(p.id, p.name) },
            ...(props.onAttachTarget ? [
                { label: "attach Git repository…", hint: "Use its native Git history and explicit apply lifecycle", run: () => props.onAttachTarget?.(p.id, p.name, "external-vcs" as const) },
                { label: "attach folder…", hint: "Fingerprint the folder and compare before every write", run: () => props.onAttachTarget?.(p.id, p.name, "external-folder" as const) },
            ] : []),
            { label: "project home…", hint: "Recent runs, outputs under review, and an audit rollup for this project", run: () => props.onOpenProjectHome(p.id, p.name) },
            { label: "model access…", hint: "Pin a per-project LLM provider key (overrides the account default)", run: () => props.onOpenModelAccess(p.id, p.name) },
            { label: "share & hand off…", run: () => props.onOpenEngagement(p.id, p.name) },
            ...(p.isPersonal ? [] : [
                { label: "rename", run: () => startEdit({ kind: "rename-project", id: p.id }, p.name) },
                { label: "delete", danger: true, confirmHint: projectBlastRadius(p), run: () => void withRefresh(() => props.api.deleteProject(p.id), "project deleted") },
            ]),
        ];
    };

    // A placement row's menu (shared by right-click and the row's ⋯ button).
    const placementMenuItems = (p: ProjectNode, pl: ProjectNode["placements"][number]): MenuState["items"] => [
        { label: "new chat", hint: "Start a new chat on this placement", run: () => newWorkChat(p.id, pl.placementId) },
        { label: "new workstream", hint: "Create a shared auto-sync line for chats here to collaborate on", run: () => startEdit({ kind: "new-workstream", placementId: pl.placementId }) },
        { label: "edit", run: () => newEditChat(pl.archetypeId) },
        { label: "customize…", hint: "Tweak this method for this project — config + notes, no fork (placement.md)", run: () => void openConfig(pl.placementId, `${pl.archetypeName} · ${p.name}`) },
        ...(props.onDeployPlacement
            ? [{
                label: "deploy to website…",
                hint: "Publish this tested agent as an embeddable panel",
                run: () => props.onDeployPlacement?.({
                    projectId: p.id,
                    projectName: p.name,
                    placementId: pl.placementId,
                    archetypeName: pl.archetypeName,
                    reviewChatId: pl.chats[0]?.id,
                }),
            }]
            : []),
        ...(pl.pending
            ? [{ label: "accept", hint: "Approve this archetype so it can host work chats (APPROVE-1)", run: () => void withRefresh(() => props.api.acceptPlacement(pl.placementId), "placement accepted") }]
            : []),
        ...(pl.upgradeAvailable
            ? [{ label: "upgrade to latest", hint: `Take the newer published version (v${pl.currentVersion}) of this archetype`, run: () => void withRefresh(() => props.api.upgradePlacement(pl.placementId), "upgraded to the latest version") }]
            : []),
        { label: "remove from project", danger: true, run: () => void withRefresh(() => props.api.removePlacement(p.id, pl.placementId), "removed") },
    ];

    // A Library archetype row's menu (shared by right-click and the ⋯ button).
    type ArchetypeNode = Workspace["archetypes"][number];
    const archetypeMenuItems = (a: ArchetypeNode): MenuState["items"] => [
        { label: "test", hint: "Try this method out — opens a chat that runs it (in your Personal space)", run: () => void useArchetype(a.id) },
        { label: "edit", hint: "Open a chat to edit what this archetype does — you review every change before it's kept", run: () => newEditChat(a.id) },
        { label: "new workstream", hint: "Create a shared auto-sync line over this method's edit chats", run: () => startEdit({ kind: "new-workstream", placementId: a.instanceId }) },
        { label: "settings", run: () => props.onOpenArchetypeSettings(a.id, a.name) },
        { label: "publish a new version", hint: "Make this the current version — placements of it get an upgrade-available notice (UX-9)", run: () => void withRefresh(() => props.api.publishArchetype(a.id), "published a new version") },
        { label: "fork", run: () => void withRefresh(() => props.api.forkArchetype(a.id), "archetype forked") },
        ...(a.forkedFrom
            ? [{ label: "pull updates from source", hint: `Merge improvements from “${a.forkedFromName ?? "the source"}” into this fork (ADR 0038)`, run: () => void withRefresh(() => props.api.pullFromSource(a.id), "pulled updates from the source") }]
            : []),
        { label: "rename", run: () => startEdit({ kind: "rename-archetype", id: a.id }, a.name) },
        ...(a.isDefault
            ? []
            : [{ label: "delete", danger: true, run: () => void withRefresh(() => props.api.deleteArchetype(a.id), "archetype deleted") }]),
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
        return (
            <For each={rows} fallback={<div class="status">no chats yet — start one from the row above</div>}>
                {({ chat, pl }) =>
                    chatRow(chat, pl.isDefault ? undefined : pl.archetypeName, pl.workstreams, false)}
            </For>
        );
    };

    // The structural chat-leaf renderer for Projects and Library.
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
        chat: { id: EngagementId; title: string; kind: "edit" | "work"; workstream?: WorkstreamId | null; placement?: PlacementId | null; workspaceRoot: WorkspaceRootId; rehomeBlocked: boolean; changes?: boolean; conflict?: boolean },
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
    ) => (
        <>
        <div
            class="tree-leaf chat-item"
            classList={{
                active: props.selected === chat.id,
                dragging: draggingChat()?.id === chat.id,
                "recent-chat-item": Boolean(recentLineageLabel),
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
            aria-label={`open chat ${displayTitle(chat)}${recentLineageLabel ? ` — ${recentLineageLabel}` : ""}`}
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
                openMenu(e, [
                    {
                        label: "fork",
                        run: () =>
                            void withRefresh(async () => {
                                const fid = await props.api.forkChat(chat.id);
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
                        ? [{
                            label: "settle changes before moving",
                            hint: "Finish, repair, review, or discard this candidate before changing lines",
                            run: () => props.onStatus("this chat has active or unsettled changes and cannot move yet"),
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
                    { label: "delete", danger: true, run: () => deleteChat(chat.id) },
                ])
            }
        >
            {/* Per-row status gem (WS-H): a robot glyph that doubles as
                the row's status light — quiet when idle, coloured working / needs-review /
                error. Its tooltip still distinguishes work and edit chats. It replaces the
                old standalone status dot and the "editing" badge;
                the change-count and conflict/sync lights wire in once the projection
                carries them (WS-H b/c). */}
            <StatusGem kind={chat.kind} tone={props.runToneOf?.(chat.id)} conflict={chat.conflict} />
            <Show
                when={editingIs("rename-chat", chat.id)}
                fallback={
                    <span class="leaf-label leaf-label-stack">
                        {/* The title is its own ellipsising line: the stack is a flex
                            column, where text-overflow can't reach a bare text child,
                            so a long title clipped mid-word with no "…" (round-11 #6). */}
                        <span class="leaf-title">{mark(displayTitle(chat))}</span>
                        <Show when={recentLineageLabel}>
                            {(lineage) => (
                                <span class="leaf-sub" data-recent-lineage={chat.id}>
                                    {mark(lineage())}
                                </span>
                            )}
                        </Show>
                        {/* Chat-log hit (SEARCH-1): when this row surfaced because the
                            query matched its transcript, show a one-line snippet of the
                            match so the row tells you *why* it stayed — the matched term
                            bolded, like a title hit. */}
                        <Show when={searching() && contentMatches().get(chat.id)}>
                            {(snip) => (
                                <span
                                    class="leaf-sub leaf-snippet"
                                    data-snippet={chat.id}
                                    title="matched in this chat's content"
                                >
                                    {mark(snip())}
                                </span>
                            )}
                        </Show>
                        {/* Fork lineage (#3): a "(fork)" chat is a flat sibling of its
                            source, indistinguishable but for the suffix. Show a quiet
                            "copy of {source}" sublabel so the relationship is legible. */}
                        <Show when={forkSource(chat.title)}>
                            {(src) => (
                                <span
                                    class="leaf-sub"
                                    data-fork-source={src()}
                                    title={`Forked from "${src()}" — its files and conversation history came along`}
                                >
                                    copy of {src()}
                                </span>
                            )}
                        </Show>
                    </span>
                }
            >
                {renameInput()}
            </Show>
            <Show when={meta}>
                <span class="leaf-meta" title={`runs the ${meta} archetype`}>{meta}</span>
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
    );

    // Group a chat list by workstream (WS-F): when a named line is active, `Main` is
    // the first header, followed by active named workstreams (name + member count +
    // promote/archive). Without a named line, mainline chats stay ungrouped and quiet.
    // The browse pane groups chats by workstream in each rooted facet. `rootInstanceId`
    // (a placement or an archetype's authoring instance) shows the `+ workstream` create
    // affordance. Each group supplies only its root's workstreams to chatRow, so
    // cross-root destinations never become commands.
    const chatGroups = (
        chats: { id: EngagementId; title: string; kind: "edit" | "work"; workstream?: WorkstreamId | null; placement?: PlacementId | null; workspaceRoot: WorkspaceRootId; rehomeBlocked: boolean; changes?: boolean; conflict?: boolean }[],
        workstreams: WorkstreamNode[],
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
                                {(c) => chatRow(c, undefined, joinTargets)}
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
                                    {(c) => chatRow(c, undefined, joinTargets)}
                                </For>
                            </div>
                        </div>
                    )}
                </For>
                <Show when={main === null}>
                    <For each={ungrouped}>{(c) => chatRow(c, undefined, joinTargets)}</For>
                </Show>
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
                            onClick={() => setFacet(f.id)}
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
            {/* Search with a clear control (#6 round-5): typing filters the tree,
                but there was no way to reset it short of selecting-and-deleting. */}
            <div class="facet-search-row">
                <input
                    class="facet-search"
                    data-testid="facet-search"
                    aria-label="Search projects, archetypes, and chats"
                    placeholder="search…"
                    value={query()}
                    onInput={(e) => setQuery(e.currentTarget.value)}
                    onKeyDown={(e) => e.key === "Escape" && setQuery("")}
                />
                <Show when={query()}>
                    <button
                        type="button"
                        class="facet-search-clear"
                        data-testid="facet-search-clear"
                        title="Clear search"
                        aria-label="Clear search"
                        onClick={() => setQuery("")}
                    >
                        ✕
                    </button>
                </Show>
            </div>

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
                                        t().workstreams.filter((workstream) => workstream.placementId === chat.placement),
                                        false,
                                        recentLineage(chat, t().projects, t().workstreams),
                                    )}
                                </For>
                            </div>
                        </Show>

                        {/* PROJECTS — the default facet: project → placements → work chats. */}
                        <Show when={facet() === "projects"}>
                            {/* Hide the create affordance while a search is active (#6
                                round-9): "+ project" rendered inside filtered results
                                read like a stray search hit. */}
                            <Show when={!searching()}>
                            <div class="action-row" data-actions="projects">
                                {createBtn("+ project", () => startEdit({ kind: "new-project" }), { title: "Create a new project" })}
                            </div>
                            </Show>
                            <Show when={editing()?.kind === "new-project"}>
                                <div class="tree-leaf">{renameInput("name this project, then Enter")}</div>
                            </Show>
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
                                                if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggleCollapse(p.id); }
                                            }}
                                            onContextMenu={(e) => openMenu(e, projectMenuItems(p))}
                                        >
                                            {caret(p.id, true)}
                                            <Show
                                                when={editingIs("rename-project", p.id)}
                                                fallback={<span class="node-label">{mark(p.name)}</span>}
                                            >
                                                {renameInput()}
                                            </Show>
                                            {rowActions({
                                                /* The lens flip (ADR 0112): revealed with the row's
                                                   other tools; the grouped structure itself is the
                                                   standing signal that a project is pivoted. */
                                                lead: (
                                                    <button
                                                        type="button"
                                                        class="lens-toggle"
                                                        data-lens-toggle={p.id}
                                                        data-lens={lensOf(p.id)}
                                                        title={lensOf(p.id) === "chats"
                                                            ? "Flat chats — click to group by archetype"
                                                            : "Grouped by archetype — click for flat chats"}
                                                        aria-label={`change how ${p.name} is grouped`}
                                                        onClick={(e) => { e.stopPropagation(); setLens(p.id, lensOf(p.id) === "chats" ? "archetype" : "chats"); }}
                                                    >
                                                        {lensOf(p.id) === "chats" ? "chats" : "by archetype"}
                                                    </button>
                                                ),
                                                primary: canStartProjectChat(p)
                                                    ? {
                                                        icon: "robot",
                                                        title: "Start a new chat in this project",
                                                        aria: `new chat in ${p.name}`,
                                                        data: "new-project-chat",
                                                        run: () => void newProjectChat(p),
                                                    }
                                                    : undefined,
                                                menuAria: `actions for project ${p.name}`,
                                                menuItems: () => projectMenuItems(p),
                                            })}
                                        </div>
                                        <Show when={!isCollapsed(p.id)}>
                                        {/* The flat `chats` lens (ADR 0112, default): every work chat
                                            in the project, current-first, archetype as a row tag. The
                                            workstream naming editor still renders here — the menu's
                                            "new workstream" targets the general placement. */}
                                        <Show when={lensOf(p.id) === "chats"}>
                                            {(() => {
                                                const home = p.placements.find((pl) => pl.isDefault);
                                                return <Show when={home}>{wsEditorFor(home!.placementId)}</Show>;
                                            })()}
                                            <div class="project-home" data-project-home={p.id} data-project-lens="chats">
                                                {flatProjectChats(p)}
                                            </div>
                                        </Show>
                                        <Show when={lensOf(p.id) === "archetype"}>
                                        {/* The structural `by archetype` lens: the project's general
                                            workspace first — its built-in general-assistant placement
                                            is implementation detail, never a node; its chats sit
                                            directly under the project. Deliberately placed archetypes
                                            appear as their own nodes below. */}
                                        {(() => {
                                            const generals = p.placements.filter((pl) => pl.isDefault);
                                            const home = generals[0];
                                            const homeChats = generals.flatMap((pl) => pl.chats);
                                            const homeWs = generals.flatMap((pl) => pl.workstreams);
                                            return (
                                                <Show when={home}>
                                                    {wsEditorFor(home!.placementId)}
                                                    <div class="project-home" data-project-home={p.id}>
                                                        {chatGroups(chatsFor(p.name, homeChats), homeWs)}
                                                    </div>
                                                </Show>
                                            );
                                        })()}
                                        <For
                                            each={p.placements.filter((pl) => !pl.isDefault && placementVisible(p.name, pl, query(), contentHits()))}
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
                                                        aria-expanded={pl.chats.length > 0 ? !isCollapsed(pl.placementId) : undefined}
                                                        aria-label={
                                                            pl.chats.length > 0
                                                                ? `archetype ${pl.archetypeName} on ${p.name} — open its chats`
                                                                : `archetype ${pl.archetypeName} on ${p.name} — start a chat`
                                                        }
                                                        title={pl.chats.length > 0 ? "open this archetype's chats" : "start a chat with this archetype"}
                                                        // Clicking the row is the obvious "start working" path: with no
                                                        // chats yet it opens a new work chat; otherwise it reveals the
                                                        // existing ones (the `+ chat` button always adds another).
                                                        onClick={() =>
                                                            pl.chats.length > 0
                                                                ? toggleCollapse(pl.placementId)
                                                                : void newWorkChat(p.id, pl.placementId)
                                                        }
                                                        onKeyDown={(e) => {
                                                            if (e.key === "Enter" || e.key === " ") {
                                                                e.preventDefault();
                                                                if (pl.chats.length > 0) toggleCollapse(pl.placementId);
                                                                else void newWorkChat(p.id, pl.placementId);
                                                            }
                                                        }}
                                                        onContextMenu={(e) => openMenu(e, placementMenuItems(p, pl))}
                                                    >
                                                        {caret(pl.placementId, pl.chats.length > 0)}
                                                        {/* Just the method name here (round-6 #6): this row is
                                                            already nested under its project, so the "· project"
                                                            half of the old lineage was redundant noise. Keep a
                                                            stable hook for the pivot via the data attribute. */}
                                                        <span class="node-label" data-lineage-archetype={pl.archetypeId} title="the archetype this placement runs">{mark(pl.archetypeName)}</span>
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
                                                                title="Pending approval — click to accept so this archetype can host work chats"
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
                                                            primary: {
                                                                icon: "robot",
                                                                title: "Start a new chat with this archetype",
                                                                aria: `new chat with ${pl.archetypeName}`,
                                                                data: "new-placement-chat",
                                                                run: () => void newWorkChat(p.id, pl.placementId),
                                                            },
                                                            menuAria: `actions for ${pl.archetypeName} on ${p.name}`,
                                                            menuItems: () => placementMenuItems(p, pl),
                                                        })}
                                                    </div>
                                                    <Show when={!isCollapsed(pl.placementId)}>
                                                        {wsEditorFor(pl.placementId)}
                                                        {/* Chats grouped by workstream (WS-F). */}
                                                        {chatGroups(
                                                            chatsFor(`${p.name} ${pl.archetypeName}`, pl.chats),
                                                            pl.workstreams,
                                                        )}
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

                        {/* LIBRARY — archetypes (the methods) → edit chats. */}
                        <Show when={facet() === "library"}>
                            <Show when={!searching()}>
                            {/* No facet-level "+ workstream" here: a workstream is a shared line
                                over one archetype's edit chats, so it lives per-archetype (below),
                                not at the Library root where there's no single target. */}
                            <div class="action-row" data-actions="library">
                                {createBtn("+ archetype", () => startEdit({ kind: "new-archetype" }), { title: "Create a new archetype" })}
                            </div>
                            </Show>
                            <Show when={editing()?.kind === "new-archetype"}>
                                <div class="tree-leaf">{renameInput("name this archetype, then Enter")}</div>
                            </Show>
                            <For
                                each={t().archetypes.filter((a) => archetypeVisible(a, query(), contentHits()))}
                                fallback={<div class="status">no archetypes yet</div>}
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
                                            aria-label={`archetype ${a.name}`}
                                            onKeyDown={(e) => {
                                                if ((e.key === "Enter" || e.key === " ") && archetypeHasChildren(a)) { e.preventDefault(); toggleCollapse(a.id); }
                                            }}
                                            onContextMenu={(e) => openMenu(e, archetypeMenuItems(a))}
                                        >
                                            {caret(a.id, archetypeHasChildren(a))}
                                            <Show
                                                when={editingIs("rename-archetype", a.id)}
                                                fallback={<span class="node-label">{mark(a.name)}</span>}
                                            >
                                                {renameInput()}
                                            </Show>
                                            {rowActions({
                                                primary: {
                                                    icon: "pencil",
                                                    title: "Open a chat to edit what this method does — every change is reviewed before it's kept",
                                                    aria: `edit ${a.name}`,
                                                    data: "edit-archetype",
                                                    run: () => newEditChat(a.id),
                                                },
                                                menuAria: `actions for archetype ${a.name}`,
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
                                        {/* Library is where you EDIT and TEST a method: edit is the row's
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
                                <h3>Choose files to work on</h3>
                                <button onClick={() => setTargetChoice(null)}>close</button>
                            </div>
                            <p class="status" style={{ margin: "0 0 8px" }}>
                                This placement can work on more than one independently versioned target.
                            </p>
                            <div class="picker-list">
                                <For each={choice().targets}>
                                    {(target) => (
                                        <button
                                            type="button"
                                            class="picker-row target-picker-row"
                                            data-target-choice={target.id}
                                            onClick={() => void chooseTarget(target)}
                                        >
                                            <span>{target.name}</span>
                                            <small>
                                                {target.kind} · {target.concurrency}
                                                {target.concurrency === "compare-before-write-weak" ? " (no multi-writer guarantee)" : ""}
                                                {` · ${target.currentBasis ?? "basis unavailable"}`}
                                            </small>
                                        </button>
                                    )}
                                </For>
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
                                    ? "Choose which archetype this project should work with."
                                    : "Choose which project to install this archetype on."}
                            </p>
                            <input
                                class="picker-search"
                                autofocus
                                data-picker-search
                                aria-label={pk().dir === "to-project" ? "Find an archetype to add" : "Find a project to place this archetype on"}
                                placeholder={pk().dir === "to-project" ? "find an archetype…" : "find a project…"}
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
                                                fallback={<div class="status">No archetypes yet — create one in the Library first.</div>}
                                            >
                                                {(a) => (
                                                    <button
                                                        type="button"
                                                        class="picker-row"
                                                        data-picker-archetype={a.id}
                                                        onClick={() => placeChosen(p.pid, a.id, a.name)}
                                                    >
                                                        {a.name}
                                                    </button>
                                                )}
                                            </For>
                                            {/* Empty-library escape hatch: jump to the Library to
                                                define a new method, so the picker is never a dead end. */}
                                            <button
                                                type="button"
                                                class="picker-row picker-create"
                                                data-picker-create
                                                onClick={() => { setPicker(null); setFacet("library"); startEdit({ kind: "new-archetype" }); }}
                                            >
                                                + create a new archetype
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
        return `Add an archetype to ${p.projectName}`;
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
    async function placeChosen(pid: ProjectId, archetypeId: ArchetypeId, label: string) {
        setPicker(null);
        await withRefresh(() => props.api.placeArchetype(pid, archetypeId), `placed ${label}`);
    }
}
