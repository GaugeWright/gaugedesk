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
