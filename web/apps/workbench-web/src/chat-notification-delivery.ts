/**
 * Delivering a chat notice to the operating system (DR-0266), from either
 * runtime.
 *
 * The desktop asks its shell (`notify_chat`), which posts a native
 * notification and, when the person clicks it, brings the window forward and
 * dispatches {@link CHAT_NOTIFICATION_EVENT} with the chat's id. That is a
 * plain event inside the page, not a `gaugewright://` link, so nothing outside
 * the app can raise it. A browser build uses the web Notification API once the
 * person has allowed it for the site, and opens the chat on its click.
 *
 * Opening the chat is an ordinary selection: it goes through the same route,
 * admission and freshness checks as a click in the navigator.
 */
import type { ChatNotice } from "@gaugewright/control-plane-client";
import { noticeText } from "@gaugewright/workbench-ui";

const isTauri = () => typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

/** The event the desktop shell dispatches when a notification is clicked. */
export const CHAT_NOTIFICATION_EVENT = "gw-chat-notification";

/** Whether the person is looking at GaugeDesk: its window shown and focused.
 *  While they are, the task bar and the navigator already say what a
 *  notification would. */
export function personIsLooking(): boolean {
    if (typeof document === "undefined") return false;
    return document.visibilityState === "visible" && document.hasFocus();
}

export async function deliverChatNotice(notice: ChatNotice, open: (chat: string) => void): Promise<void> {
    const { title, body } = noticeText(notice);
    if (isTauri()) {
        try {
            const { invoke } = await import("@tauri-apps/api/core");
            await invoke("notify_chat", { chat: notice.chat, title, body });
        } catch {
            // A shell that predates the command: there is nothing to show with.
        }
        return;
    }
    const Web = globalThis.Notification;
    if (!Web || Web.permission !== "granted") return;
    try {
        // One notification per chat: a newer one replaces its predecessor.
        const shown = new Web(title, { body, tag: `gaugedesk-chat:${notice.chat}` });
        shown.onclick = () => {
            window.focus();
            open(notice.chat);
            shown.close();
        };
    } catch {
        // A browser that only notifies from a service worker: nothing to show.
    }
}
