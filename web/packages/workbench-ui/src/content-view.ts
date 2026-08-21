/**
 * Pure view-state for the {@link ContentViewer} (3rd column, `navigation.md`).
 * The component owns Solid signals and the DOM; this module owns the small
 * decisions about *what the merge phase means in plain words* and *when a
 * file-selection or phase change should retarget the viewer* — so they can be
 * unit-tested without rendering.
 *
 * Vocabulary is scope-specific (round-10 #3, MEMORY #10): in a **work** chat a
 * kept change merges into the project's shared copy; in an **improve** ("edit")
 * chat it updates a reusable *method* that then applies everywhere it runs, so
 * "the shared copy" there would be a category error.
 */

import type { MergePhase } from "@gaugewright/control-plane-client";

export type ChatKind = "work" | "edit";

/** The phases at which the worktree has truly settled — a repair/retry may have
 *  rewritten the files, so a viewer reading them should re-fetch (the `content`
 *  resource is keyed only on (id, file) and wouldn't otherwise notice). */
export function isSettledPhase(phase: MergePhase | null): boolean {
    return phase === "Rejected" || phase === "Advanced" || phase === "Integrated" || phase === "Idle";
}

/** Plain-language reading of "the change was kept". An improve chat names the
 *  method (when known) and states the broader scope; a work chat says it went
 *  into the shared copy. */
export function keptLabel(chatKind: ChatKind | undefined, methodName: string | undefined): string {
    if (chatKind !== "edit") return "Kept into the shared copy";
    const method = (methodName ?? "").trim();
    return method
        ? `Saved to the ${method} Agent — this now applies everywhere it's used`
        : "Saved to the Agent — this now applies everywhere it's used";
}

/** The merge phase in words the user can read. Falls back to the raw token for
 *  any unknown phase (the token also stays on `data-merge-phase` for tests). */
export function phaseLabel(
    phase: MergePhase,
    chatKind: ChatKind | undefined,
    methodName: string | undefined,
): string {
    switch (phase) {
        case "Idle":
            return "No changes to review yet";
        case "Merging":
            return "Checking the changes…";
        case "Advanced":
        case "Integrated":
            return keptLabel(chatKind, methodName);
        case "Repairing":
            return "Fixing up a conflict…";
        case "Rejected":
            return "You discarded these changes — nothing was kept";
        default:
            return phase;
    }
}

/** When a newly-selected file should drop the viewer into View. A pending change
 *  up for review surfaces as a "Clean" merge phase — we keep the user on that
 *  active "needs review" diff (round-7 #3) rather than yanking them to View; any
 *  other phase (no pending review) drops into View as a normal file pick. */
export function shouldShowViewOnSelect(phase: MergePhase | null): boolean {
    return phase !== "Clean";
}

/** The surface a chat should *open* on. The file **View** is the resting default;
 *  the **Changes** (diff) review surface leads only when a review is actually open
 *  — a finished turn awaiting keep/discard, which surfaces as a "Clean" merge
 *  phase. Re-evaluated per chat, so a chat with nothing to review opens on View
 *  instead of inheriting the previous chat's Changes tab. */
export function defaultContentMode(phase: MergePhase | null): "view" | "diff" {
    return phase === "Clean" ? "diff" : "view";
}
