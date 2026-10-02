/**
 * A file the agent offered the person in the chat (DR-0314).
 *
 * The agent calls `offer_download` with a path under `artifacts/`; the chat
 * turns that tool line into a card with a Download button. This module reads
 * the offer out of a transcript line and nothing else, so it is tested as data.
 * It decides what the card says; whether the bytes can be read is the
 * session's answer at click time.
 */
import type { TranscriptLine } from "./transcript";
import { filenameOf } from "./file-download";

export const OFFER_DOWNLOAD_TOOL = "offer_download";
export const OFFERABLE_ROOT = "artifacts/";

export interface OfferedDownload {
    /** Workspace path, always under {@link OFFERABLE_ROOT}. */
    readonly path: string;
    /** The name the file is saved under. */
    readonly filename: string;
    /** What the agent called it, when it said; otherwise the filename. */
    readonly title: string;
}

/** Whether a path is one the agent may offer: a file under `artifacts/`, with
 *  no empty, dot, or parent segment. */
export function isOfferablePath(path: string): boolean {
    if (!path.startsWith(OFFERABLE_ROOT)) return false;
    const rest = path.slice(OFFERABLE_ROOT.length);
    return rest.length > 0
        && rest.split("/").every((segment) => segment.length > 0 && !segment.startsWith("."));
}

/** The offer a tool line makes, or null when the line is not an offer the
 *  host accepted. A refused call stays an ordinary tool line, so its error is
 *  still read where every other tool's is. */
export function offeredDownload(line: TranscriptLine): OfferedDownload | null {
    if (line.kind !== "tool" || line.tool?.name !== OFFER_DOWNLOAD_TOOL || line.tool.ok === false) return null;
    let args: unknown;
    try {
        args = JSON.parse(line.tool.args ?? "");
    } catch {
        return null;
    }
    if (!args || typeof args !== "object") return null;
    const path = "path" in args && typeof args.path === "string" ? args.path.trim() : "";
    if (!isOfferablePath(path)) return null;
    const filename = filenameOf(path);
    const title = "title" in args && typeof args.title === "string" && args.title.trim()
        ? args.title.trim()
        : filename;
    return { path, filename, title };
}
