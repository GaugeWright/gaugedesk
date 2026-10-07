/**
 * Why the desktop window's own control plane is not answering.
 *
 * The desktop window reaches its co-resident control plane over HTTP, so when
 * that control plane has stopped — it refused a store a newer GaugeDesk wrote,
 * or could not take its address — a request simply fails to connect, and the
 * webview's error says nothing more than that ("Load failed" in WebKit). The
 * shell knows why. The window registers a way to ask it, and a request this
 * package builds to that exact origin that fails to connect is rejected with
 * the shell's reason instead. A browser build registers nothing.
 *
 * The same failure also happens before the control plane has started. The
 * shell opens the window while the control plane is still opening its store,
 * so the window's first reads can arrive at an address nothing listens on
 * yet. That is not a failure, and must not be answered as one: on 2026-10-07
 * the first launch of 0.8.2 and of 0.8.5 each sent its first sixteen reads
 * about 0.3 s before the control plane listened, the sign-in status read
 * among them, and both windows came up signed out until the person signed in
 * again. So until the control plane has answered once, a read that cannot
 * connect waits for it — as long as the shell names no reason it stopped, and
 * for at most {@link LOCAL_CONTROL_PLANE_STARTUP_WAIT_MS}.
 */

/** How long a read waits for a control plane that has not answered yet. A
 * first open after an update can do work an ordinary launch does not, so this
 * is generous; a control plane that stopped says so at once instead. */
export const LOCAL_CONTROL_PLANE_STARTUP_WAIT_MS = 30_000;

/** Optional seams for {@link registerLocalControlPlaneFailure}. */
export interface LocalControlPlaneStartup {
    /** How long a read waits for the control plane's first answer. */
    readonly waitMs?: number;
    /** Pause between attempts; a test passes one that returns at once. */
    readonly sleep?: (ms: number) => Promise<void>;
    /** The clock the wait is measured on. */
    readonly now?: () => number;
}

interface Registration {
    readonly origin: string;
    readonly explain: () => Promise<string | null>;
    readonly waitMs: number;
    readonly sleep: (ms: number) => Promise<void>;
    readonly now: () => number;
    /** The control plane has answered a request at least once. */
    answered: boolean;
}

let registered: Registration | null = null;

function originOf(url: string): string | null {
    try {
        return new URL(url).origin;
    } catch {
        return null;
    }
}

/** A request to the local control plane could not connect, and the shell
 * said why. `message` is written for the person using the desktop. */
export class LocalControlPlaneUnavailable extends Error {
    constructor(message: string, cause: unknown) {
        super(message, { cause });
        this.name = "LocalControlPlaneUnavailable";
    }
}

/** Register the window's local control plane and how to ask why it is not
 * serving; `explain` answers `null` while it is. */
export function registerLocalControlPlaneFailure(
    base: string,
    explain: () => Promise<string | null>,
    startup: LocalControlPlaneStartup = {},
): void {
    const origin = originOf(base);
    if (!origin) return;
    registered = {
        origin,
        explain,
        waitMs: startup.waitMs ?? LOCAL_CONTROL_PLANE_STARTUP_WAIT_MS,
        sleep: startup.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms))),
        now: startup.now ?? (() => Date.now()),
        answered: false,
    };
}

/** Only a read is sent again. A request that could not connect never ran, but
 * a fetch reports a reset after delivery the same way, and only a read is
 * safe to repeat whichever it was. */
function repeatable(init: RequestInit): boolean {
    const method = (init.method ?? "GET").toUpperCase();
    return method === "GET" || method === "HEAD";
}

/** `fetch`, except that a request to the registered local control plane that
 * fails to connect is rejected with the shell's reason when it has one, and a
 * read sent before that control plane has ever answered waits for it to start.
 * An abort, an HTTP error status, or a request to any other origin is
 * untouched. */
export async function fetchLocalControlPlane(url: string, init: RequestInit): Promise<Response> {
    let started: number | null = null;
    let pause = 50;
    for (;;) {
        try {
            const response = await fetch(url, init);
            const current = registered;
            if (current && originOf(url) === current.origin) current.answered = true;
            return response;
        } catch (error) {
            const current = registered;
            // A fetch that could not connect rejects with a TypeError; an abort
            // is a DOMException and stays what it was.
            if (!current || !(error instanceof TypeError) || originOf(url) !== current.origin) throw error;
            const reason = await reasonFrom(current);
            if (reason) throw new LocalControlPlaneUnavailable(reason, error);
            if (current.answered || !repeatable(init)) throw error;
            const now = current.now();
            started ??= now;
            if (now - started + pause > current.waitMs) throw error;
            await current.sleep(pause);
            pause = Math.min(pause * 2, 1_000);
        }
    }
}

async function reasonFrom(current: Registration): Promise<string | null> {
    try {
        return await current.explain();
    } catch {
        return null;
    }
}

/** Test seam: forget any registration. */
export function resetLocalControlPlaneFailureForTest(): void {
    registered = null;
}
