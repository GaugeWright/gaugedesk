/**
 * The Deploy Config origin allowlist (`experience/deployments.md`, PANEL-11).
 *
 * A public deployment admits a visitor only when the request's `Origin` equals
 * one entry of its allowlist exactly, so an apex domain and its `www` form are
 * two entries and a site served from both carries both. The panel edits that
 * list as one origin per line; these two functions are the whole translation,
 * kept out of the panel so the property the fix rests on — what an active
 * deployment admits is exactly what a republish sends back — is pinned by a
 * test that survives a UI rewrite.
 *
 * Nothing here decides what an origin is. The publisher refuses anything that
 * is not an exact HTTPS origin, and the panel shows its message unchanged.
 */

/** Render an admitted allowlist as the draft the owner edits: one origin per line. */
export function originsDraftFrom(origins: readonly string[]): string {
    return origins.join("\n");
}

/** Read the owner's draft back into the list to publish. Surrounding whitespace
 *  and blank lines are editing noise, not origins, and a repeated entry is kept
 *  once in first-seen order. An emptied draft yields no origins at all, which the
 *  publisher refuses rather than admitting a blank. */
export function originsFromDraft(draft: string): string[] {
    const origins: string[] = [];
    for (const line of draft.split(/\r?\n/)) {
        const origin = line.trim();
        if (origin && !origins.includes(origin)) origins.push(origin);
    }
    return origins;
}
