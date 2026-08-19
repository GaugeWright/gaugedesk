/**
 * Make fork lineage legible (round-8 #3).
 *
 * A forked chat is created (by the backend) with a "(fork)" suffix on its title —
 * e.g. "hello kitt (fork)". In the tree it then sits as a flat sibling of its
 * source, distinguished ONLY by that suffix, so "hello kitt" and "hello kitt
 * (fork)" look like coincidental name-twins: nothing shows one is a branch of the
 * other, or what carried over (files and — since ADR 0141 — the conversation
 * history up to the fork point; forks made before that carry files only).
 *
 * The frontend can't see a real parent pointer (the recent projection carries only
 * id/title/archetype/kind/mode), but the "(fork)" suffix is a reliable signal we
 * own. These pure helpers read it so the row can show a quiet "copy of {source}"
 * sublabel and a legacy fork's empty first view can explain what carried over —
 * without any backend change.
 */

/** A possibly-nested "(fork)" suffix, optionally numbered: "(fork)", "(fork 2)". */
const FORK_SUFFIX = /\s*\((?:fork)(?:\s*\d+)?\)\s*$/i;

/** Is this chat title a fork (created with the "(fork)" suffix)? */
export function isFork(title: string | undefined): boolean {
    return !!title && FORK_SUFFIX.test(title);
}

/**
 * The source chat's name a fork was copied from — the title with the trailing
 * "(fork)" stripped. Returns null when the title isn't a fork or strips to empty.
 * Strips only ONE trailing suffix so "X (fork) (fork)" reads as a copy of
 * "X (fork)" (the immediate source), not the root.
 */
export function forkSource(title: string | undefined): string | null {
    if (!title || !FORK_SUFFIX.test(title)) return null;
    const base = title.replace(FORK_SUFFIX, "").trim();
    return base || null;
}
