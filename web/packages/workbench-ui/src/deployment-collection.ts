/**
 * The Deploy Config collection rules (ADR 0109 §5–§7, GATE-8).
 *
 * Pure functions, separate from the panel, because two of them encode decisions
 * rather than mechanics and both deserve a test that survives a UI rewrite: a
 * deployment naming no recipient collects **nothing**, and a zero retention entry
 * must never publish as "expire immediately".
 */

import type { CollectionRecipient, PublicDeploymentCollection } from "@gaugewright/control-plane-client";

/** What the owner has entered on the collection fieldset. */
export interface CollectionDraft {
    readonly collecting: boolean;
    readonly paths: string;
    readonly transcript: boolean;
    readonly schemaRef: string;
    readonly recipientClass: string;
    readonly maxArtifactKb: number;
    readonly recipient: CollectionRecipient | null;
}

/** The declared paths, split on commas or newlines so either reads naturally. */
export function exportablePathsOf(paths: string): string[] {
    return paths
        .split(/[\n,]+/)
        .map((path) => path.trim())
        .filter(Boolean);
}

/**
 * The collection block to publish, or `undefined` for "collects nothing".
 *
 * `undefined` rather than a block with an empty recipient: the edge refuses a
 * reference whose class the release does not permit and has no ambient fallback,
 * so a half-filled block is a publish that fails late instead of a deployment
 * that plainly does not collect.
 */
export function collectionInputFrom(draft: CollectionDraft): PublicDeploymentCollection | undefined {
    if (!draft.collecting || !draft.recipient) return undefined;
    return {
        exportable_paths: exportablePathsOf(draft.paths),
        transcript_eligible: draft.transcript,
        schema_ref: draft.schemaRef.trim(),
        recipient_class: draft.recipientClass.trim(),
        max_artifact_bytes: Math.max(1, Math.round(draft.maxArtifactKb * 1024)),
        recipient_ref: draft.recipient.recipient_ref,
        recipient_public_keys: [draft.recipient.public_key_hex],
    };
}

/** Why this deployment cannot collect yet, in the owner's terms. "" when it can. */
export function collectionBlockerFor(draft: CollectionDraft): string {
    if (!draft.collecting) return "";
    if (!draft.recipient) return "Choose or create a recipient keyring first.";
    if (!draft.schemaRef.trim()) return "A collection needs the schema the release declares.";
    if (exportablePathsOf(draft.paths).length === 0) {
        // Zero paths is not "collect everything" — it is a collection that can
        // never contain anything, which is worth saying before publishing.
        return "Name at least one path, or nothing can leave the session.";
    }
    return "";
}

/**
 * Retention in the units the wire wants.
 *
 * Floored at one second: a zero or negative entry must not publish as "expire
 * immediately", which would silently destroy every session the moment it opened.
 */
export function retentionSeconds(
    idleHours: number,
    absoluteDays: number,
): { idle: number; absolute: number } {
    return {
        idle: Math.max(1, Math.round(idleHours * 3600)),
        absolute: Math.max(1, Math.round(absoluteDays * 86_400)),
    };
}
