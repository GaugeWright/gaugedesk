/**
 * One canonical chat title, everywhere (#4 round-4). A brand-new chat is created
 * with a generic placeholder ("new chat", "edit chat", …) and named by the
 * server after its first turn. Until then we must NOT show the raw placeholder — it leaks the
 * same "new chat" string into three surfaces (tree, chat header, TASKS pill) that
 * round 3 only de-placeholdered in the nav. This module is the single source of
 * truth for both "is this a placeholder?" and "what do we show instead?", so the
 * tree, All-chats, the chat-lane header, and the TASKS bar all agree.
 */

/** The generic titles a chat carries before automatic or manual naming. */
export const PLACEHOLDER_TITLES = new Set([
    "new chat",
    "edit chat",
]);

/** True when a title is a system placeholder (never user-chosen). */
export function isPlaceholderTitle(title: string | null | undefined): boolean {
    return PLACEHOLDER_TITLES.has((title ?? "").trim().toLowerCase());
}

/**
 * The title to display. A user-chosen title always wins; an un-started chat reads
 * "Untitled" (with a disambiguating tag when one is supplied, so two un-started
 * chats in the same list never read identically). The tag may be a number or a
 * stable string token (see {@link untitledTag}); pass a *stable* one so a chat's
 * label doesn't drift as the list changes (round-11 #6).
 */
export function displayChatTitle(
    title: string | null | undefined,
    tag?: string | number,
): string {
    const t = (title ?? "").trim();
    if (t && !isPlaceholderTitle(t)) return t;
    return tag !== undefined && tag !== "" ? `Untitled · ${tag}` : "Untitled";
}

/**
 * A short, **stable** disambiguator for an unnamed chat, derived from its id — not
 * its position in the list. A positional ordinal drifts (an "Untitled · 2" becomes
 * "· 4" when earlier chats are added/removed, round-11 #6); a token from the id is
 * the same for a given chat forever. Returns the last 4 id characters, upper-cased.
 */
export function untitledTag(id: string | null | undefined): string {
    const s = String(id ?? "").replace(/^chat[-:]/i, "");
    return s.slice(-4).toUpperCase();
}
