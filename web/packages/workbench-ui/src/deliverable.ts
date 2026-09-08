/**
 * Deliverables — the files a session hands to the person in front of it.
 *
 * A published agent that produces a report has nowhere to put it: the visitor
 * can read any file in their own session through the scoped files projection,
 * but no panel offers one, and the chat never mentions a file the agent wrote.
 * ADR 0163 settles the shape: everything the agent writes under one fixed root,
 * `deliverable/`, is offered to the visitor from the chat with a download. The
 * root is a convention frozen into the release by the package's write grant,
 * not a field of the release schema — a declared list would change a schema
 * every verifier pins, for no gain over a root the method already controls.
 *
 * This module is the doctrine, kept free of the DOM so it is tested as data.
 */

export const DELIVERABLE_ROOT = "deliverable/";

export interface Deliverable {
    /** Release-relative path, always under {@link DELIVERABLE_ROOT}. */
    readonly path: string;
    /** The name the download is saved under: the last path segment. */
    readonly filename: string;
    /** The media type the download is served as, from the extension. */
    readonly mediaType: string;
}

const MEDIA_TYPES: Readonly<Record<string, string>> = {
    html: "text/html",
    htm: "text/html",
    md: "text/markdown",
    txt: "text/plain",
    json: "application/json",
    csv: "text/csv",
    pdf: "application/pdf",
};

/** A conservative default: a type the browser will save rather than execute. */
const FALLBACK_MEDIA_TYPE = "application/octet-stream";

export function mediaTypeFor(path: string): string {
    const dot = path.lastIndexOf(".");
    const extension = dot >= 0 ? path.slice(dot + 1).toLowerCase() : "";
    return MEDIA_TYPES[extension] ?? FALLBACK_MEDIA_TYPE;
}

/** Whether a workspace path is a deliverable: directly or deeper under the
 *  root, never the root itself, and never a dotfile — the same segment rule
 *  the Files panel uses to keep internal files out of sight. */
export function isDeliverablePath(path: string): boolean {
    if (!path.startsWith(DELIVERABLE_ROOT)) return false;
    const rest = path.slice(DELIVERABLE_ROOT.length);
    if (!rest) return false;
    return rest.split("/").every((segment) => segment.length > 0 && !segment.startsWith("."));
}

/** The deliverables among a workspace listing, in listing order. */
export function deliverablesIn(paths: readonly string[]): Deliverable[] {
    return paths.filter(isDeliverablePath).map((path) => ({
        path,
        filename: path.slice(path.lastIndexOf("/") + 1),
        mediaType: mediaTypeFor(path),
    }));
}

/** The deliverables that were not in the previous listing — what a turn just
 *  produced, and therefore what the panel announces. */
export function newDeliverables(
    previous: readonly string[],
    current: readonly string[],
): Deliverable[] {
    const seen = new Set(previous);
    return deliverablesIn(current.filter((path) => !seen.has(path)));
}
