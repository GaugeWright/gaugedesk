/**
 * Session: the scoped context a panel renders against — the seam that makes the
 * workbench panels **context-portable** (EMBED-1; [ADR 0051] §3, "Context-portable
 * panels"). A panel reads its addressing, projections, and commands from the
 * injected Session, never from a desktop global, so the *same* panel mounts
 * unchanged against either the local desktop workspace (App.tsx builds a Session
 * over its signals) or a remote, scoped embedded session (a future `<gw-session>`
 * builds one over a scoped control plane).
 *
 * Projection-first (`INV-5`): a Session exposes *projections* (accessors) and a
 * scoped *transport* (commands), never authority. Nothing here writes truth; the
 * panels remain thin renderers.
 *
 * The interface grows one accessor at a time as each panel is migrated off
 * App.tsx props — it carries exactly what a context-portable panel needs, no more.
 */
import { createContext, useContext, type Accessor } from "solid-js";
import {
    type EngagementId,
    type FileEntry,
    type MergeAction,
    type MergePhase,
    type MergePreviewResult,
    type QuarantineIndex,
    type RegionResolution,
    type SaveBase,
    type SaveFileResult,
} from "@gaugewright/control-plane-client";
import { type Transcript } from "./transcript";
import { type ImageRef } from "./attachments";
import {
    type ComposerCapabilities,
    type ComposerRuntimeCommands,
} from "./session-composer-controller";

export interface SessionApi {
    getFile(id: EngagementId, path: string): Promise<string>;
    /** The project's quarantine index — provenance only, never payload
     *  (ADR 0110 §7). Optional: only a session that can review inbound material
     *  serves it. */
    listQuarantine?(project: string): Promise<QuarantineIndex>;
    /** One quarantined item's bytes, for a person to read. */
    readQuarantinedItem?(project: string, item: string): Promise<string>;
    /** Carry a reviewer's verdict to the project's gate, which is what rules
     *  (ADR 0117 §1). `chat` is the chat the review is acted from. */
    reviewQuarantinedItem?(
        project: string,
        item: string,
        chat: EngagementId,
        verdict: "keep" | "flag",
    ): Promise<{ workspacePath: string | null }>;
    /** `getFile` plus the cut the read serves (SUB-6 §12) — the base a
     *  cut-carrying save sends back. Optional: sessions without it fall
     *  back to content-based bases. */
    getFileWithCut?(
        id: EngagementId,
        path: string,
    ): Promise<{ content: string; cut: string | null }>;
    putFile(id: EngagementId, path: string, content: string): Promise<void>;
    /** Base-carrying save (SUB-6): merges concurrent changes through whip's
     *  engine; a real divergence resolves to a structured conflict payload.
     *  Fold-settled `resolutions` mint durable region memory. Optional —
     *  sessions without it fall back to the legacy putFile. */
    saveFile?(
        id: EngagementId,
        path: string,
        content: string,
        base: SaveBase,
        resolutions?: RegionResolution[],
    ): Promise<SaveFileResult>;
    /** Read-only save preview (the live fold, §12.3). Optional. */
    previewMerge?(
        id: EngagementId,
        path: string,
        draft: string,
        baseCut: string,
    ): Promise<MergePreviewResult>;
    getTree(id: EngagementId): Promise<FileEntry[]>;
    /** Audience chat index, present only on a public/audience control plane. */
    embedMyChats?(): Promise<{ chat: string; title: string }[]>;
    /** Whether this scoped public session has an authenticated audience. */
    readonly embedAudience?: boolean;
    /** Audience-scoped chat lifecycle commands. The environment swaps the
     * Session binding; the shared panels remain transport-agnostic. */
    embedOpenChat?(chat: string): Promise<void>;
    embedNewChat?(): Promise<void>;
    embedEraseChat?(chat: string): Promise<void>;
    /** The deployment's public embed config (EMBED-7 white-label). Optional: only a
     *  scoped embed session serves `/embed/config`; desktop sessions omit it. */
    embedGetConfig?(): Promise<{ white_label: boolean }>;
}

/** The provider-neutral live-turn vocabulary (ADR 0135; WhippleScript
 *  `spec/agent-harness.md` "Live Turn Observation"). One list, declared once:
 *  the panel's labels, the transport's frame validation, and every producer all
 *  derive from it, so a runtime state cannot be added in one place and silently
 *  go unrendered in another. */
export const TURN_ACTIVITIES = [
    "idle",
    "awaiting_model",
    "streaming_output",
    "running_tool",
    "compacting",
    "retrying",
    "settling",
    "stopping",
] as const;

export type TurnActivity = (typeof TURN_ACTIVITIES)[number];

/** One live-turn reading. `tool` is the tool's name while `state` is
 *  `running_tool` — the state alone would only say "something is happening",
 *  and the whole point of showing a long pause is saying what it is. */
export interface TurnObservation {
    readonly state: TurnActivity;
    readonly tool?: string;
}

/** The live-turn reading for an Environment whose runtime publishes no activity
 *  frames of its own — the desktop and Administration placements, which observe
 *  a turn through the busy flag and the transcript instead.
 *
 *  Every state here is read off something the transcript reduction already
 *  records, so this reports what those Environments genuinely see rather than
 *  standing in for the runtime's own observation. `openText` is non-null exactly
 *  while deltas append to an open line. A tool line whose `ok` is still unset is
 *  a tool that started and has not reported back — which is precisely a tool
 *  running, and it carries the name.
 *
 *  `compacting` is absent by necessity, not by choice: a local runtime does not
 *  tell the panel when it compacts, and there is nothing in the transcript to
 *  infer it from. Guessing would be worse than the honest `awaiting_model`. */
export function localTurnActivity(
    busy: Accessor<boolean>,
    transcript: Accessor<Transcript>,
): Accessor<TurnObservation> {
    return () => {
        if (!busy()) return { state: "idle" };
        const current = transcript();
        if (current.openText !== null) return { state: "streaming_output" };
        const lastTool = [...current.lines].reverse().find((line) => line.kind === "tool");
        if (lastTool?.tool && lastTool.tool.ok === undefined) {
            return { state: "running_tool", tool: lastTool.tool.name };
        }
        return { state: "awaiting_model" };
    };
}

export interface Session {
    /** The control-plane transport, already scoped to this session's backend. */
    readonly api: SessionApi;
    /** The engagement (chat) this session is bound to; null when none is open. */
    readonly engagementId: Accessor<EngagementId | null>;
    /** An opaque key that changes whenever this session's worktree mutates — the
     *  refetch trigger for worktree-derived projections (the desktop wires it to
     *  the per-turn `status` signal). */
    readonly worktreeRev: Accessor<unknown>;
    /** Cross-panel file selection within this session (the content-viewer target). */
    readonly selectedFile: Accessor<string | null>;
    readonly selectFile: (path: string | null) => void;
    /** Optional Environment-owned edit ceiling for virtual/special files. When
     *  present it narrows the shared editor; it never makes a normally protected
     *  package/control path writable. */
    readonly canEditFile?: (path: string) => boolean;
    /** Environment-specific explanation for a file refused by `canEditFile`. */
    readonly readOnlyFileReason?: (path: string) => string;

    /** Optional: the project whose quarantine index the content viewer shows,
     *  and the setter the top bar's inbound pill drives (ADR 0110 §7, GATE-6).
     *
     *  Deliberately *not* modelled as a `selectedFile` path. Quarantine is a path
     *  boundary no agent file store resolves into (ADR 0110 §1), and giving it a
     *  file-shaped address — even a virtual one — would put it in the same
     *  namespace the protection is stated over. It is its own surface because it
     *  is its own kind of thing: the reviewer's, never an agent's.
     *
     *  Absent in sessions with nothing to review: an embed reviews no inbound
     *  material, so the panel simply never shows the surface. */
    readonly reviewingProject?: Accessor<string | null>;
    readonly reviewProject?: (project: string | null) => void;

    // Engagement-scoped read projections (`INV-5`). The desktop exposes its existing
    // resources here; an embed exposes the same shapes over its scoped session.
    /** The engagement-vs-`main` diff (the merge-review surface), "" when none. */
    readonly diff: Accessor<string>;
    /** The merge lifecycle's current phase for this engagement, null when settled/none. */
    readonly mergePhase: Accessor<MergePhase | null>;
    /** Whether a `Rejected` merge isolated because of a git **conflict** (couldn't be merged)
     *  rather than a user discard — so the UI says "conflicted", not "you discarded". */
    readonly mergeConflicted: Accessor<boolean>;
    /** Whether this chat edits a reusable method ("edit") or does work ("work") —
     *  drives keep/kept vocabulary. */
    readonly chatKind: Accessor<"work" | "edit">;
    /** The method/archetype name behind this chat, for edit-chat phrasing ("" when unknown). */
    readonly methodName: Accessor<string>;

    /** This engagement's transcript projection: the durable snapshot of admitted
     *  records concatenated with the live SSE reduction of the in-progress turn
     *  (`transcript.ts`). A view, not truth (`INV-5`). */
    readonly transcript: Accessor<Transcript>;
    /** Whether this session is waiting on an admitted turn. Environments that
     *  can observe it expose the same shared working/composer presentation. */
    readonly busy: Accessor<boolean>;
    /** Ephemeral provider-neutral observation of the active turn. Durable
     * transcript and terminal output remain authoritative.
     *
     * Required, not optional: ADR 0135 makes this a shared-panel presentation
     * for every Environment, and an optional member is exactly how a producer
     * silently opts out while still typechecking. An Environment whose runtime
     * reports nothing finer than busy/idle says so by returning those two —
     * that is an honest answer, and omitting the member is not. */
    readonly turnActivity: Accessor<TurnObservation>;
    /** Explicit conversation commands admitted by this Environment. Audience is
     *  presentation identity, not a capability shortcut. */
    readonly composerCapabilities: Accessor<ComposerCapabilities>;
    /** Whether this Session can carry a standing command *right now*.
     *
     * The momentary companion to `composerCapabilities`, which is static: that
     * says which commands this Environment admits at all, this says whether the
     * transport can presently deliver one. A phone whose relay dropped still
     * admits `send` as a capability; it simply cannot issue one until the
     * connection returns.
     *
     * `false` refuses the send, and only the send. Drafting stays permitted —
     * composing while unable to deliver is exactly what an offline client is for
     * (`mobile-client.md`, "Connection, freshness, offline"), and the client
     * cannot manufacture truth by queueing a command it cannot carry (`INV-5`).
     * The Environment is responsible for saying *why* somewhere the reader can
     * see it (mobile's connection banner), so this never becomes a silently dead
     * control.
     *
     * Required, not optional, for the reason `turnActivity` is: an optional
     * member is how a producer whose transport genuinely can drop silently opts
     * out while still typechecking. An Environment whose transport is local and
     * always available answers `() => true`, and that is an honest answer. */
    readonly canCommand: Accessor<boolean>;
    /** Runtime-owned interactive command queue when this Environment can join
     * messages to a live turn. Absent environments retain local staging. */
    readonly composerRuntime?: ComposerRuntimeCommands;
    // Scoped commands + refetch (the panel issues; the session admits/refetches).
    /** Drive the merge lifecycle for this engagement (keep / discard / …). */
    readonly merge: (action: MergeAction) => void;
    /** Re-read content-derived projections after an in-panel save (diff + merge). */
    readonly onContentSaved: () => void;
    /** Send exactly one message and settle only when the authoritative turn has
     *  completed, failed, or been interrupted. Queue orchestration lives above
     *  this primitive in the shared composer controller.
     *
     *  `composedId` is the outbox id this message was composed under (ADR 0137
     *  §3). A Session whose transport can carry an idempotency key must send it,
     *  so that resending after an uncertain dispatch is answered rather than
     *  guessed. A Session that cannot may ignore it — but must not let one
     *  composed id become two turns. */
    readonly send: (
        text: string,
        images?: readonly ImageRef[],
        composedId?: string,
    ) => Promise<void>;
    /** Does {@link send} carry `composedId` through to a host that applies it at
     *  most once? Only then may an unsettled dispatch be recovered by resending
     *  it; otherwise the composer sets that message aside for a person. Absent
     *  means no — the guarantee has to be claimed, not assumed. */
    readonly appliesComposedIdOnce?: boolean;
    /** Cooperatively cancel the current durable turn. */
    readonly stop?: () => Promise<void>;
    /** Fork at an exact durable user/assistant boundary. Owner environments
     *  supply this; audience sessions intentionally omit it. */
    readonly forkAt?: (entryId: number) => void;
}

const SessionContext = createContext<Session>();

/**
 * Read the ambient Session. Fail-closed (`INV-20`): a panel mounted outside a
 * provider is a wiring bug, not a silent degrade — we throw rather than let a
 * panel fall back to a desktop global.
 */
export function useSession(): Session {
    const session = useContext(SessionContext);
    if (!session) {
        throw new Error(
            "useSession: no Session in context — a panel must be mounted under <SessionProvider>",
        );
    }
    return session;
}

/** Provide a Session to a panel subtree. */
export const SessionProvider = SessionContext.Provider;
