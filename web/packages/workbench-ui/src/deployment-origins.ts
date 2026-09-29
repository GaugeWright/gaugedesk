/**
 * The Deploy Config origin allowlist (`experience/deployments.md`, PANEL-11).
 *
 * A public deployment admits a visitor only when the request's `Origin` equals
 * one entry of its allowlist exactly, so an apex domain and its `www` form are
 * two entries and a site served from both carries both. The panel edits that
 * list as a list: it loads the admitted origins as they are, adds one entry at a
 * time, and publishes the list it holds. These functions are the whole of what
 * happens to an entry on the way in, kept out of the panel so the property the
 * fix rests on — what an active deployment admits is exactly what a republish
 * sends back — is pinned by a test that survives a UI rewrite.
 *
 * The publisher still decides what an origin is and refuses anything that is not
 * an exact HTTPS origin. Reading what the owner typed as one is only so that a
 * bare host or a pasted page address does not come back as a refusal.
 */

/** The exact HTTPS origin the owner meant, or why what they typed is not one. A
 *  bare host is read as HTTPS, and a path or trailing slash is dropped, because a
 *  visitor's browser sends only the origin. */
export function normalizeOrigin(input: string): { origin: string } | { error: string } {
    const trimmed = input.trim();
    if (!trimmed) return { error: "Enter a website address." };
    const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
    let url: URL;
    try {
        url = new URL(withScheme);
    } catch {
        return { error: `“${trimmed}” isn't a website address.` };
    }
    if (url.protocol !== "https:") return { error: "The website must use https://." };
    if (!url.hostname.includes(".")) return { error: `“${trimmed}” isn't a website address.` };
    return { origin: url.origin };
}

/** Add one origin, keeping the list's order and each origin once. */
export function withOrigin(origins: readonly string[], origin: string): string[] {
    return origins.includes(origin) ? [...origins] : [...origins, origin];
}

/** The `www.` form of an apex origin, or the apex of a `www.` one: the entry an
 *  owner most often forgets, since the edge compares origins exactly. */
export function wwwCounterpart(origin: string): string | null {
    const url = new URL(origin);
    const host = url.hostname;
    const port = url.port ? `:${url.port}` : "";
    if (host.startsWith("www.")) return `${url.protocol}//${host.slice(4)}${port}`;
    if (host.split(".").length === 2) return `${url.protocol}//www.${host}${port}`;
    return null;
}
