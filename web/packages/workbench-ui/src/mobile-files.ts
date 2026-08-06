/**
 * The mobile **Files pane's** view-derived vocabulary (`mobile-client.md`,
 * MOB-015): the small, pure projections the {@link MobileFiles} island needs to
 * paint a worktree tree where **a handle's name is always visible but its
 * payload is not** (`INV-10`, mirrors `gaugedesk_core::resource_access`:
 * `name_visible()` is always true, `payload_accessible()` only once `Granted`).
 *
 * The island is a thin renderer; all the "what may I show?" decisions live here
 * as pure functions of the supplied file nodes, so this layer is testable
 * without a DOM (same split as the carousel: `carousel-view.ts` vs
 * `CarouselIsland.tsx`). The cardinal rule this module encodes: **holding a handle is
 * not holding the payload** — the tree lists every file by name, but a node's
 * content is openable only when its access phase grants the payload.
 */

// ----- Access phase (mirrors core `resource_access::AccessPhase`) -------------

/** The payload-access lifecycle of a file handle, mirroring the core reducer's
 *  `AccessPhase` (snake-cased on the wire). The *name* is visible in every
 *  phase; only `granted` admits the payload (`ACCESS_REQUIRES_GRANT`). */
export type AccessPhase =
    /** No access asked for yet — name only. */
    | "init"
    /** Access requested, awaiting approval — name only. */
    | "requested"
    /** Approved and not revoked — the only phase that admits the payload. */
    | "granted"
    /** Access was granted then withdrawn (future-only, `INV-18`) — name only. */
    | "revoked"
    /** Terminal: rejected, canceled, or expired — name only. */
    | "denied";

const ACCESS_PHASES: readonly AccessPhase[] = [
    "init",
    "requested",
    "granted",
    "revoked",
    "denied",
];

/** Whether a phase admits the *payload* (mirrors `AccessState::payload_accessible`:
 *  only a `Granted`, not-revoked state). The name is always visible regardless;
 *  this gate is solely about the content body. */
export function payloadAccessible(phase: AccessPhase): boolean {
    return phase === "granted";
}

// ----- File node --------------------------------------------------------------

/** One handle in the worktree as the Files pane sees it. The `name` (path) is
 *  always carried — a handle always names something — but the payload is gated
 *  behind {@link FileNode.access}. `protectedResource` flags a method/context
 *  resource whose payload is held behind a boundary even when nominally listed
 *  (the desktop 🔒, `INV-10`). */
export interface FileNode {
    /** The handle's path/name. Always shown — visibility ≠ access. */
    readonly path: string;
    /** Whether this is a directory (a grouping handle, no payload of its own). */
    readonly isDir: boolean;
    /** The payload-access phase of this handle. Directories carry `init`. */
    readonly access: AccessPhase;
    /** A protected method/context resource: its payload is boundary-held, so the
     *  lock shows even though the name is listed (`INV-10`). */
    readonly protectedResource: boolean;
}

// ----- Per-node presentation --------------------------------------------------

/** How a node is to be presented. `nameVisible` is always true (the whole point
 *  of this pane); `payloadOpenable` decides whether tapping the node may load
 *  content; `locked` paints the 🔒 affordance; `requestable` is true when the
 *  user could *ask* for the payload (a protected file not yet granted). */
export interface FilePresentation {
    readonly path: string;
    readonly isDir: boolean;
    /** Always `true` — a handle's name is shown in every phase. */
    readonly nameVisible: boolean;
    /** Whether tapping may open the payload (only a granted, non-dir handle). */
    readonly payloadOpenable: boolean;
    /** Whether to paint the lock affordance (a protected handle without payload). */
    readonly locked: boolean;
    /** Whether the user can request payload access for this handle (locked, and
     *  not already mid-request / terminally denied). */
    readonly requestable: boolean;
    /** A short, human caption for the access basis (drives an a11y label). */
    readonly accessLabel: string;
}

/** Human captions for the access basis, surfaced as the node's title/aria. */
const ACCESS_LABEL: Record<AccessPhase, string> = {
    init: "no access requested",
    requested: "access requested — awaiting approval",
    granted: "payload available",
    revoked: "access revoked",
    denied: "access denied",
};

/** Derive a node's presentation from its access phase. The name is always
 *  visible; the payload is openable only for a granted, non-directory handle; a
 *  protected handle without payload is locked, and lockable handles that are
 *  neither mid-request nor terminally denied are requestable. */
export function presentNode(node: FileNode): FilePresentation {
    const openable = !node.isDir && payloadAccessible(node.access);
    const locked = node.protectedResource && !openable;
    const requestable =
        locked && !node.isDir && node.access !== "requested" && node.access !== "denied";
    return {
        path: node.path,
        isDir: node.isDir,
        nameVisible: true,
        payloadOpenable: openable,
        locked,
        requestable,
        accessLabel: ACCESS_LABEL[node.access],
    };
}

// ----- Tree presentation ------------------------------------------------------

/** The Files pane's full view: every node's presentation in stable path order,
 *  so the island renders directories before their members and the same handle
 *  never appears twice. Sorting here (not in the island) keeps order testable. */
export function presentTree(nodes: readonly FileNode[]): FilePresentation[] {
    return [...nodes]
        .sort((a, b) => a.path.localeCompare(b.path))
        .map(presentNode);
}

// ----- Parse at the transport edge -------------------------------------------

function parsePhase(raw: unknown): AccessPhase {
    if (typeof raw === "string" && (ACCESS_PHASES as readonly string[]).includes(raw)) {
        return raw as AccessPhase;
    }
    throw new Error(`unknown AccessPhase: ${JSON.stringify(raw)}`);
}

/** Wire shape of a file node as emitted by the worktree projection. */
interface RawFileNode {
    path?: unknown;
    is_dir?: unknown;
    access?: unknown;
    protected?: unknown;
}

/** Parse a raw worktree node into a branded {@link FileNode}, defaulting the
 *  payload-access phase to `init` (name-only) when the wire omits it — the safe
 *  direction is *less* access, never more. */
export function parseFileNode(raw: RawFileNode): FileNode {
    if (typeof raw.path !== "string" || !raw.path) {
        throw new Error("FileNode missing non-empty path");
    }
    return {
        path: raw.path,
        isDir: raw.is_dir === true,
        access: raw.access == null ? "init" : parsePhase(raw.access),
        protectedResource: raw.protected === true,
    };
}
