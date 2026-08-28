/**
 * Pure search/filter reducers for the FacetBrowser tree (`navigation.md` B2,
 * E-10). The browser is a thin renderer: this module owns the "what survives a
 * search, and why" decisions so they can be unit-tested without Solid signals or
 * the DOM.
 *
 * The governing rule (navigation.md B2): an empty query shows everything;
 * otherwise **a node shows iff it — or a descendant — matches**. A parent kept
 * only as an ancestor of a hit narrows to just the matching descendants, so
 * search drills *into* a group rather than hiding the hit underneath it.
 *
 * A chat matches on its **title** (the pure label tier, computed here) *or* its
 * **content** (the chat-log tier): the `contentHits` set carries the chat ids the
 * server's `GET /search` found in the transcript (SEARCH-1). Within a group, title
 * hits rank above content-only hits (`navigation.md` "Search scope and relevance").
 */

/** Does a single label match the active query? Empty/whitespace query ⇒ always
 *  (everything shows); otherwise a case-insensitive substring test. */
export function hit(label: string, query: string): boolean {
    const q = query.trim().toLowerCase();
    return q === "" || label.toLowerCase().includes(q);
}

/** Is a search actually narrowing the tree (a non-empty query)? */
export function searching(query: string): boolean {
    return query.trim() !== "";
}

/** The pieces of a label split around the first match, for highlighting the
 *  literal hit in a surviving row (the bolded `<mark>`). Returns null when there
 *  is no query or the label doesn't itself contain the query — i.e. the row
 *  survived only as an ancestor of a deeper hit, so nothing in it is bolded. */
export interface MatchSplit {
    readonly pre: string;
    readonly match: string;
    readonly post: string;
}
export function markMatch(label: string, query: string): MatchSplit | null {
    const q = query.trim();
    if (!q) return null;
    const i = label.toLowerCase().indexOf(q.toLowerCase());
    if (i < 0) return null;
    return { pre: label.slice(0, i), match: label.slice(i, i + q.length), post: label.slice(i + q.length) };
}

/** The empty content-hit set — the default when no content search is active, so
 *  the predicates reduce to pure title matching. */
const NO_CONTENT: ReadonlySet<string> = new Set();

/** Does a chat match — by its title (label tier) or by its content (the chat-log
 *  tier, i.e. its id is in the server's `contentHits` set)? */
function chatLabelMatches(c: { title: string; targets?: readonly { name: string }[] }, query: string): boolean {
    return hit(c.title, query) || (c.targets ?? []).some((target) => hit(target.name, query));
}

export function chatMatches(c: { title: string; id?: string; targets?: readonly { name: string }[] }, query: string, contentHits: ReadonlySet<string> = NO_CONTENT): boolean {
    return chatLabelMatches(c, query) || (c.id !== undefined && contentHits.has(c.id));
}

/** The matching children of a narrowed group, **title hits first** then
 *  content-only hits (each keeping original order) — so the strongest signal leads
 *  the group (`navigation.md` "Search scope and relevance"). */
function ranked<T extends { title: string; id?: string; targets?: readonly { name: string }[] }>(children: readonly T[], query: string, contentHits: ReadonlySet<string>): T[] {
    const titled = children.filter((c) => chatLabelMatches(c, query));
    const contentOnly = children.filter((c) => !chatLabelMatches(c, query) && c.id !== undefined && contentHits.has(c.id));
    return [...titled, ...contentOnly];
}

/** For a parent node kept by the search: if the parent's own label matches, keep
 *  every child (the group matched as a whole); otherwise keep only the children
 *  that match — by title or content — title hits first (narrow into the group). */
export function childrenFor<T extends { title: string; id?: string; targets?: readonly { name: string }[] }>(parentLabel: string, children: readonly T[], query: string, contentHits: ReadonlySet<string> = NO_CONTENT): T[] {
    return hit(parentLabel, query) ? [...children] : ranked(children, query, contentHits);
}

// --- tree-level visibility (a node shows iff it or a descendant matches) ---

export interface FilterChat {
    readonly title: string;
    /** The chat id, used to test membership in the content-hit set. Optional so
     *  pure title-only callers (and tests) need not supply it. */
    readonly id?: string;
    readonly targets?: readonly { name: string }[];
}
export interface FilterPlacement {
    readonly archetypeName: string;
    readonly chats: readonly FilterChat[];
}
export interface FilterProject {
    readonly name: string;
    readonly placements: readonly FilterPlacement[];
}
export interface FilterArchetype {
    readonly name: string;
    readonly chats: readonly FilterChat[];
}

/** A placement survives iff the owning project matches, the placement's archetype
 *  name matches, or one of its chats matches (title or content). */
export function placementVisible(projectName: string, pl: FilterPlacement, query: string, contentHits: ReadonlySet<string> = NO_CONTENT): boolean {
    return hit(projectName, query) || hit(pl.archetypeName, query) || pl.chats.some((c) => chatMatches(c, query, contentHits));
}

/** A project survives iff its own name matches or any of its placements survive. */
export function projectVisible(p: FilterProject, query: string, contentHits: ReadonlySet<string> = NO_CONTENT): boolean {
    return hit(p.name, query) || p.placements.some((pl) => placementVisible(p.name, pl, query, contentHits));
}

/** A library archetype survives iff its name matches or any of its chats match
 *  (title or content). */
export function archetypeVisible(a: FilterArchetype, query: string, contentHits: ReadonlySet<string> = NO_CONTENT): boolean {
    return hit(a.name, query) || a.chats.some((c) => chatMatches(c, query, contentHits));
}

/** The compact lineage shown by the read-only Recent lens. Work chats name both
 * their project and archetype; edit chats name their archetype. A named
 * workstream is appended, while the implicit Main line stays quiet. */
export function recentLineage(
    chat: { kind: "edit" | "work"; archetype: string; placement?: string | null; workstream?: string | null },
    projects: readonly { name: string; placements: readonly { placementId: string }[] }[],
    workstreams: readonly { id: string; name: string }[],
): string {
    const project = chat.kind === "work"
        ? projects.find((p) => p.placements.some((pl) => pl.placementId === chat.placement))?.name
        : undefined;
    const root = project ? `${project} · ${chat.archetype}` : chat.archetype;
    const line = chat.workstream
        ? workstreams.find((ws) => ws.id === chat.workstream)?.name
        : undefined;
    return line ? `${root} · ${line}` : root;
}

/** A Recent row matches its title, its displayed lineage, or a server-projected
 * content hit. This keeps search useful without reconstructing rooted groups. */
export function recentVisible(
    chat: { title: string; id?: string; targets?: readonly { name: string }[] },
    lineage: string,
    query: string,
    contentHits: ReadonlySet<string> = NO_CONTENT,
): boolean {
    return chatLabelMatches(chat, query) || hit(lineage, query) || (chat.id !== undefined && contentHits.has(chat.id));
}

/** Group "All chats" by their owning archetype, after dropping rows that match
 *  neither the chat title nor the archetype label (so empty groups disappear).
 *  Preserves first-seen order of both groups and chats within a group. */
export interface RecentChat extends FilterChat {
    readonly archetype: string;
}
export interface ChatGroup<T extends RecentChat> {
    readonly archetype: string;
    readonly chats: T[];
}
export function groupChatsByArchetype<T extends RecentChat>(recent: readonly T[], query: string, contentHits: ReadonlySet<string> = NO_CONTENT): ChatGroup<T>[] {
    // Title hits first, then content-only hits, so each group leads with its
    // strongest signal; an archetype-label match keeps all of that archetype's chats.
    const titled = recent.filter((c) => hit(c.title, query) || hit(c.archetype, query));
    const contentOnly = recent.filter((c) => !(hit(c.title, query) || hit(c.archetype, query)) && c.id !== undefined && contentHits.has(c.id));
    const kept = [...titled, ...contentOnly];
    const groups = new Map<string, T[]>();
    for (const c of kept) {
        const g = groups.get(c.archetype) ?? [];
        g.push(c);
        groups.set(c.archetype, g);
    }
    return [...groups.entries()].map(([archetype, chats]) => ({ archetype, chats }));
}

/** Whether the "All chats" list spans more than one archetype — the only case
 *  where a per-archetype section header is worth showing (otherwise it's the same
 *  word on every group). */
export function lineageVaries(recent: readonly RecentChat[]): boolean {
    return new Set(recent.map((c) => c.archetype)).size > 1;
}
