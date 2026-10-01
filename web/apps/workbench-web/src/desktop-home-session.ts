/**
 * The desktop UI's credential for its own Home (DR-0188).
 *
 * The Hub session stays sealed in the control plane (ADR 0123). After sign-in
 * the shell hands the webview a session valid on this Home only, over Tauri
 * IPC rather than loopback HTTP, where any local process could ask for it. It
 * is `null` whenever the UI should keep the local posture: a browser build,
 * nobody signed in, an expired sign-in, or an account with no standing here.
 */

const isTauri = () => typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

export async function desktopHomeSession(): Promise<string | null> {
    if (!isTauri()) return null;
    try {
        const { invoke } = await import("@tauri-apps/api/core");
        const token = await invoke<string | null>("home_session");
        return typeof token === "string" && token ? token : null;
    } catch {
        // A shell that predates the command, or refuses: the local posture.
        return null;
    }
}

/** What one answered sign-in status read changed for the window. */
export interface DesktopHomeSessionAnswer {
    /** The window's first answer: account-scoped reads may begin now, not before. */
    readonly first: boolean;
    /** The credential presented to the Home is not the one presented before. */
    readonly credentialMoved: boolean;
    /** The window now reaches its Home by the other route. */
    readonly remoteMoved: boolean;
}

/**
 * Follow each sign-in status read with the Home session it implies, and say
 * what the answer changed.
 *
 * Every account-scoped read the window makes — Workshop, Projects, Recent,
 * Tasks — is answered for the account this presents, so none may run before
 * the first answer and each must run again when the credential moves
 * (DR-0209, DR-0271). In 0.5.1 the window mounted between the status read
 * and its session: Workshop was read as the local account, kept after the
 * signed-in account's session arrived, and opening one of its legacy local
 * Agents was refused as another account's work (WS-613).
 *
 * A status read that is superseded before its session arrives is dropped. A
 * credential this did not present is never withdrawn by it.
 */
export function followDesktopHomeSession(options: {
    /** Present this credential on the window's Home requests from now on. */
    readonly present: (token: string | null) => void;
    /** Reach the Home through the account plane; true when that changed. */
    readonly reachRemotely: (remote: boolean) => boolean;
    readonly answered: (answer: DesktopHomeSessionAnswer) => void;
    readonly read?: () => Promise<string | null>;
}): (linked: boolean) => void {
    const read = options.read ?? desktopHomeSession;
    let held: string | null = null;
    let reads = 0;
    let answered = false;
    return (linked) => {
        const current = ++reads;
        void (linked ? read() : Promise.resolve(null)).then((token) => {
            if (current !== reads) return;
            const before = held;
            if (token) {
                held = token;
                options.present(token);
            } else if (held) {
                held = null;
                options.present(null);
            }
            const remoteMoved = options.reachRemotely(linked && !token);
            const first = !answered;
            answered = true;
            options.answered({ first, credentialMoved: held !== before, remoteMoved });
        });
    };
}
