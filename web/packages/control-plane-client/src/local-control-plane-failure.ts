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
 */

let registered: { readonly origin: string; readonly explain: () => Promise<string | null> } | null = null;

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
export function registerLocalControlPlaneFailure(base: string, explain: () => Promise<string | null>): void {
    const origin = originOf(base);
    if (!origin) return;
    registered = { origin, explain };
}

/** `fetch`, except that a request to the registered local control plane that
 * fails to connect is rejected with the shell's reason when it has one. An
 * abort, an HTTP error status, or a request to any other origin is untouched. */
export async function fetchLocalControlPlane(url: string, init: RequestInit): Promise<Response> {
    try {
        return await fetch(url, init);
    } catch (error) {
        throw await explainConnectFailure(url, error);
    }
}

async function explainConnectFailure(url: string, error: unknown): Promise<unknown> {
    const current = registered;
    // A fetch that could not connect rejects with a TypeError; an abort is a
    // DOMException and stays what it was.
    if (!current || !(error instanceof TypeError) || originOf(url) !== current.origin) return error;
    let reason: string | null;
    try {
        reason = await current.explain();
    } catch {
        return error;
    }
    return reason ? new LocalControlPlaneUnavailable(reason, error) : error;
}

/** Test seam: forget any registration. */
export function resetLocalControlPlaneFailureForTest(): void {
    registered = null;
}
