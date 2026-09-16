/**
 * What the navigator owes the person for a given read outcome.
 *
 * Kept beside the component rather than inside it (as `facet-filter.ts` is) so
 * the "never hang on loading…" contract is testable without pulling the Solid
 * store into the test environment.
 *
 * The rule the nav got wrong: a read that *failed* with nothing cached is a
 * retryable error, not a spinner — a spinner promises work in flight, and after
 * a failed read there is none. A tree we already hold still beats both, even
 * when a later refetch failed; the freshness banner is what says it may be
 * stale.
 */

export type NavLoadState = "ready" | "loading" | "error";

export function navLoadState(input: { errored: boolean; hasTree: boolean }): NavLoadState {
    if (input.hasTree) return "ready";
    return input.errored ? "error" : "loading";
}
