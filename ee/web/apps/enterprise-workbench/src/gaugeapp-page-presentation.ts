/**
 * Page freshness is server evidence, not interface copy. Healthy evidence stays
 * quiet; only states that need the person's attention earn space in the title.
 */
export function pageFreshnessCaveat(freshness: string): string | null {
    const state = freshness.trim().toLowerCase();
    if (state.includes("not-connected")) return "Not connected";
    if (state.includes("unavailable")) return "Temporarily unavailable";
    if (state.includes("stale") || state.includes("unreconciled")) return "May be out of date";
    return null;
}
