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
    type ComposerTurnOptions,
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
    /** Explicit conversation commands admitted by this Environment. Audience is
     *  presentation identity, not a capability shortcut. */
    readonly composerCapabilities: Accessor<ComposerCapabilities>;
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
     *  this primitive in the shared composer controller. */
    readonly send: (
        text: string,
        images?: readonly ImageRef[],
        options?: ComposerTurnOptions,
    ) => Promise<void>;
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
