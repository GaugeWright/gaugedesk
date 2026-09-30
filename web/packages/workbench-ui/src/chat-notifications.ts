/**
 * Operating-system notifications for chats (DR-0266): when a chat finishes a
 * turn or needs its person while that person is not looking at GaugeDesk.
 *
 * The Home decides *what* has happened — each chat's notice: the signal it has
 * raised and how many turns it has settled. This module decides what *this
 * device* does about it: the person's preference for this device, which turns
 * have ended since the device last looked, and the words.
 * The preference is the device's own rather than the account's, because
 * whether a computer or a browser tab may interrupt is a fact about that
 * device, and the attention rules (ADR 0082) that follow the account already
 * decide the task bar and the badges.
 *
 * A notification names the chat and why; it never carries the chat's content.
 * The operating system keeps notifications in its own history, outside the
 * Home's authority.
 */
import { createSignal } from "solid-js";
import type { ChatNotice } from "@gaugewright/control-plane-client";

/** What this device notifies for. */
export type NotificationPreference = "all" | "needs-me" | "off";

export interface NotificationChoice {
    readonly preference: NotificationPreference;
    readonly label: string;
    readonly hint: string;
}

/** The settings choices, in the order a settings surface shows them. */
export const NOTIFICATION_CHOICES: readonly NotificationChoice[] = [
    {
        preference: "all",
        label: "Finished or needs me",
        hint: "Notify when a chat's turn ends, and when a chat asks you something, conflicts, or stops on an error.",
    },
    {
        preference: "needs-me",
        label: "Needs me",
        hint: "Notify only when a chat asks you something, conflicts, or stops on an error.",
    },
    { preference: "off", label: "Off", hint: "Never notify on this device." },
];

export const NOTIFICATION_PREFERENCE_KEY = "gw.notifications";
const DEFAULT_PREFERENCE: NotificationPreference = "all";

function readPreference(): NotificationPreference {
    try {
        const stored = globalThis.localStorage?.getItem(NOTIFICATION_PREFERENCE_KEY);
        if (stored === "all" || stored === "needs-me" || stored === "off") return stored;
    } catch {
        /* storage unavailable: the default */
    }
    return DEFAULT_PREFERENCE;
}

const [preference, setPreferenceSignal] = createSignal<NotificationPreference>(readPreference());

/** This device's notification preference, reactive. */
export const notificationPreference = preference;

/** Change this device's preference. Kept for the session even when storage
 *  refuses to keep it for the next one. */
export function setNotificationPreference(next: NotificationPreference): void {
    setPreferenceSignal(next);
    try {
        globalThis.localStorage?.setItem(NOTIFICATION_PREFERENCE_KEY, next);
    } catch {
        /* this session only */
    }
}

/**
 * Whether this runtime can show a notification, as a settings surface needs
 * to say it. The desktop shell posts its own and needs no page permission
 * (`native`); a browser needs the person's permission for the site, which
 * only a click may ask for.
 */
export type NotificationPermissionState = "native" | "granted" | "default" | "denied" | "unsupported";

const isDesktopShell = () => typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

export function notificationPermission(): NotificationPermissionState {
    if (isDesktopShell()) return "native";
    const web = globalThis.Notification;
    if (!web) return "unsupported";
    return web.permission;
}

/** Ask the browser for permission. Call from a click; a browser refuses to
 *  ask otherwise. */
export async function requestNotificationPermission(): Promise<NotificationPermissionState> {
    const web = globalThis.Notification;
    if (isDesktopShell() || !web) return notificationPermission();
    try {
        await web.requestPermission();
    } catch {
        /* an older browser's callback form, or a refusal: read what stands */
    }
    return notificationPermission();
}

/** Whether a notice needs its person rather than only reporting an ending. */
export function noticeNeedsPerson(notice: ChatNotice): boolean {
    return notice.signal !== "turn-settled" || notice.failed;
}

/** Whether `preference` asks this device to notify for `notice`. */
export function preferenceWants(preference: NotificationPreference, notice: ChatNotice): boolean {
    if (preference === "off") return false;
    return preference === "all" || noticeNeedsPerson(notice);
}

/** The notification's words: the chat by name, and why. */
export function noticeText(notice: ChatNotice): { title: string; body: string } {
    const title = notice.title.trim() || "A chat";
    switch (notice.signal) {
        case "question":
            return { title, body: "Has a question for you." };
        case "conflict":
            return { title, body: "Has a conflict to repair." };
        case "turn-settled":
            return { title, body: notice.failed ? "Stopped on an error." : "Finished." };
    }
}

/**
 * Remembers, per Home, how many turns each chat had settled when this device
 * last read it, and reports the chats whose count has risen since: a turn has
 * ended, and the notice's signal says how the chat stands now. A signal that
 * changes without a settle — a question seen while its turn still runs, a
 * conflict repaired, a question answered from another device — is not an
 * ending, and raises nothing.
 *
 * The first read of a Home only learns. Whatever had already happened when
 * the device started looking is shown by the task bar and the badges, and
 * raising it again on every launch would teach the person to ignore the
 * notification.
 */
export class NoticeTracker {
    private readonly settled = new Map<string, Map<string, number>>();

    /** The notices in `notices` for turns that have ended since the last read
     *  of `home`. */
    fresh(home: string, notices: readonly ChatNotice[]): ChatNotice[] {
        const before = this.settled.get(home);
        const after = new Map(before);
        for (const notice of notices) {
            after.set(notice.chat, Math.max(notice.settle, before?.get(notice.chat) ?? 0));
        }
        this.settled.set(home, after);
        if (!before) return [];
        return notices.filter((notice) => notice.settle > (before.get(notice.chat) ?? 0));
    }
}
