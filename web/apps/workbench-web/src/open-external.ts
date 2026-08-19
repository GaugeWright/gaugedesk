/**
 * Open a URL in the person's **real browser**, from either runtime.
 *
 * The desktop webview silently drops `window.open` — Tauri v2 ships no
 * new-window handler, so the call "succeeds" and nothing appears. That is how
 * the sign-in button came to claim "finish signing in in your browser" over a
 * browser that never opened (2026-08-19). Here the desktop asks its shell to
 * open the system browser (the `open_external` command), and a browser build
 * keeps `window.open`.
 *
 * Resolves to whether a browser actually opened, so a surface can lead with a
 * copyable link when none did — never report the attempt as if it were the
 * outcome.
 */

const isTauri = () => typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

export async function openExternal(url: string): Promise<boolean> {
    if (isTauri()) {
        try {
            const { invoke } = await import("@tauri-apps/api/core");
            await invoke("open_external", { url });
            return true;
        } catch {
            // The shell refused (not http/https) or predates the command; there
            // is no browser to claim.
            return false;
        }
    }
    return window.open(url, "_blank", "noopener,noreferrer") !== null;
}
