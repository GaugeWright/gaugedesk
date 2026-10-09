/**
 * URL-addressable desktop chat + file selection (UX-4). The desktop selection is Solid
 * signal state; these pure helpers mirror it into the browser URL (`?chat=<id>&file=<path>`)
 * so a chat — and the file open within it — is deep-linkable and shareable, and restore it
 * on load. Pure and testable — the App wires them to `window.location` / `window.history`
 * (mirrors `resolveControlPlaneBase`). The chat and file params are orthogonal: each
 * setter preserves the other's param, so mirroring one never clobbers the other.
 */

const CHAT_PARAM = "chat";
const FILE_PARAM = "file";

/** The chat id a URL search string addresses, or `null` when none is present. */
export function chatIdFromSearch(search: string): string | null {
    const id = new URLSearchParams(search).get(CHAT_PARAM);
    return id && id.trim() ? id : null;
}

/** A search string that addresses `id`, preserving any other query params. */
export function searchWithChat(search: string, id: string | null): string {
    const p = new URLSearchParams(search);
    if (id) p.set(CHAT_PARAM, id);
    else p.delete(CHAT_PARAM);
    const s = p.toString();
    return s ? `?${s}` : "";
}

/** The file path a URL search string addresses within the open chat, or `null` when none. */
export function fileFromSearch(search: string): string | null {
    const path = new URLSearchParams(search).get(FILE_PARAM);
    return path && path.trim() ? path : null;
}

/**
 * A search string carrying the in-chat file selection, preserving any other query params
 * (notably `chat`). `null` clears the `file` param — the shape when no file is open.
 */
export function searchWithFile(search: string, path: string | null): string {
    const p = new URLSearchParams(search);
    if (path && path.trim()) p.set(FILE_PARAM, path);
    else p.delete(FILE_PARAM);
    const s = p.toString();
    return s ? `?${s}` : "";
}
