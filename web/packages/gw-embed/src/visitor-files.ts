/**
 * What a Panel visitor may see of their session's workspace (DR-0310).
 *
 * A session has three folders the agent writes: `artifacts/` is for the
 * visitor, `work/` is the agent's scratchpad, and `outbox/` holds what is
 * collected to the owner's Inbox. Only `artifacts/` is shown. This module is
 * the one place the embed decides that, so the Files panel, the Viewer, and a
 * file link in the chat all agree.
 *
 * It is a presentation boundary, not an access control: the session host still
 * serves every path to a visitor holding the session capability, and a tool
 * call in the transcript still carries its arguments (WhippleScript WS-657).
 */
import type { EngagementId, FileEntry } from "@gaugewright/control-plane-client";
import type { EmbedSessionApi } from "./session-api";

export const VISITOR_ROOT = "artifacts";

export function isVisitorVisible(path: string): boolean {
    return path === VISITOR_ROOT || path.startsWith(`${VISITOR_ROOT}/`);
}

export function visitorEntries(entries: readonly FileEntry[]): FileEntry[] {
    return entries.filter((entry) => isVisitorVisible(entry.path));
}

function refuse(path: string): Error {
    return new Error(`“${path}” is not shared with you.`);
}

/** The session api as a visitor sees it: the listing narrowed to
 *  `artifacts/`, and every read of another path refused before it is made. */
export function visitorApi(api: EmbedSessionApi): EmbedSessionApi {
    const narrowed: Partial<EmbedSessionApi> = {
        getTree: async (id: EngagementId) => visitorEntries(await api.getTree(id)),
        getFile: async (id: EngagementId, path: string) => {
            if (!isVisitorVisible(path)) throw refuse(path);
            return api.getFile(id, path);
        },
        getFileWithCut: api.getFileWithCut && (async (id: EngagementId, path: string) => {
            if (!isVisitorVisible(path)) throw refuse(path);
            return api.getFileWithCut!(id, path);
        }),
        getFileBytes: api.getFileBytes && (async (id: EngagementId, path: string) => {
            if (!isVisitorVisible(path)) throw refuse(path);
            return api.getFileBytes!(id, path);
        }),
    };
    // A proxy rather than a spread: the edge client is a class, and a spread
    // would drop every method on its prototype.
    return new Proxy(api, {
        get(target, property, receiver) {
            if (Object.prototype.hasOwnProperty.call(narrowed, property)) {
                return narrowed[property as keyof EmbedSessionApi];
            }
            const value = Reflect.get(target, property, receiver);
            return typeof value === "function" ? value.bind(target) : value;
        },
    });
}
