/**
 * Pure projection helpers over the durable-resource list (RF-E1, m0-gate O-1/O-4).
 *
 * `GET /chats/:id/resources` returns every durable resource an engagement holds —
 * the method, attached context sources, and produced outputs — as handle +
 * metadata only (`INV-10`; the payload never travels in the listing). Two
 * first-run surfaces read this projection:
 *
 *   - the **context-sources panel** (O-1): the `context` (and `method`) resources
 *     the chat is working with, each with its availability and tombstone state;
 *   - the **output catalog** (O-4): the produced `output` resources, each with the
 *     review/export gating it must pass before it can leave.
 *
 * The components stay thin: every "is this available?", "what does its access read
 * as?", "which list does it belong in?" decision is a pure function here, unit-
 * tested without a DOM beside the package-owned workbench helpers.
 */

import type { AccessPhase, ExportPhase, ResourceKind, ResourceView, ReviewPhase } from "@gaugewright/control-plane-client";

// ----- Availability -----------------------------------------------------------

/** How a resource reads to the user, folding access phase + tombstone into one
 *  word the panel can render. A tombstoned resource is `erased` regardless of its
 *  access phase (the payload is gone, `INV-18`); otherwise availability follows
 *  the access lifecycle (only `Granted` resolves the payload, `INV-10`). */
export type Availability = "available" | "pending" | "blocked" | "erased";

/** Decide a resource's availability. Tombstone wins (the payload is gone); then a
 *  `Granted` access is `available`; `Revoked`/`Denied` are `blocked`; everything
 *  else (`Init`/`Requested`/unknown) is `pending` access. */
export function availabilityOf(r: ResourceView): Availability {
    if (r.tombstoned) return "erased";
    return availabilityOfAccess(r.access);
}

function availabilityOfAccess(access: AccessPhase): Availability {
    switch (access) {
        case "Granted":
            return "available";
        case "Revoked":
        case "Denied":
            return "blocked";
        default:
            return "pending";
    }
}

/** A short, human caption for an availability — for a tooltip / secondary line. */
export function availabilityLabel(a: Availability): string {
    switch (a) {
        case "available":
            return "available";
        case "pending":
            return "awaiting access";
        case "blocked":
            return "access blocked";
        case "erased":
            return "erased";
    }
}

// ----- Partitioning -----------------------------------------------------------

/** Whether a resource belongs in the context-sources panel: the `context` and
 *  `method` resources the chat works *from* (everything that is not an output). */
export function isContextSource(r: ResourceView): boolean {
    return r.kind !== "output";
}

/** Whether a resource belongs in the output catalog: the produced `output`s. */
export function isOutput(r: ResourceView): boolean {
    return r.kind === "output";
}

/** The context sources (context + method), stable order preserved. */
export function contextSources(resources: readonly ResourceView[]): ResourceView[] {
    return resources.filter(isContextSource);
}

/** The produced outputs, stable order preserved. */
export function outputs(resources: readonly ResourceView[]): ResourceView[] {
    return resources.filter(isOutput);
}

/** A short, human label for a resource kind (the panel's group heading / chip). */
export function kindLabel(kind: ResourceKind): string {
    switch (kind) {
        case "method":
            return "Agent";
        case "context":
            return "context";
        case "output":
            return "output";
        default:
            return kind || "resource";
    }
}

/** A compact, stable display name for a resource handle. We strip a known
 *  `out-`/`ctx-`/`chat-` prefix for legibility; if what remains is an **opaque
 *  hex handle** (a 40-char id is not a name), we show a short stable tag instead
 *  of headlining a scary raw id (round-12 A). A human-named handle passes through. */
export function resourceTitle(r: ResourceView): string {
    // Handle should be stripped even when nested, e.g. `out-chat-<hex>`.
    const stripped = r.id.replace(/^((out|ctx|chat)-)+/, "");
    const bare = stripped.replace(/-/g, "");
    if (bare.length >= 8 && /^[0-9a-f]+$/i.test(bare)) return bare.slice(0, 6);
    return stripped || r.id;
}

// ----- Review / export protection state, in plain words -----------------------

/** Plain-language for a resource's **review** phase, or `null` when nothing has
 *  happened yet (`Init`) — the availability chip already says "awaiting access",
 *  so a raw "review: Init" is noise, not information (round-12 A). */
export function reviewPhaseLabel(p: ReviewPhase | null | undefined): string | null {
    switch (p) {
        case "Proposed": return "awaiting review";
        case "Cleared": return "reviewed";
        case "Released": return "released";
        case "Withheld": return "held back";
        default: return null; // Init / unknown → nothing to say
    }
}

/** Plain-language for a resource's **export** phase, or `null` when not started. */
export function exportPhaseLabel(p: ExportPhase | null | undefined): string | null {
    switch (p) {
        case "Requested": return "send-out requested";
        case "Cleared": return "cleared to send out";
        case "Exported": return "sent out";
        default: return null;
    }
}

/** One plain status phrase for an output's protection state, preferring the later
 *  (export) stage when meaningful, else the review stage, else the baseline
 *  "not yet reviewed". Always a plain phrase — never a raw "review: Init" token,
 *  but never blank either: a produced output always shows where it stands. */
export function outputProtectionLabel(
    review: ReviewPhase | null | undefined,
    exp: ExportPhase | null | undefined,
): string {
    return exportPhaseLabel(exp) ?? reviewPhaseLabel(review) ?? "not yet reviewed";
}
