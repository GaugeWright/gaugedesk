/**
 * Lets this window say why its own control plane is not answering.
 *
 * The shell records why the co-resident control plane stopped — a store a
 * newer GaugeDesk wrote, an address another program holds — and answers it
 * over Tauri IPC. Registered with the control-plane client, a request to that
 * control plane which fails to connect then fails with the shell's reason
 * rather than the webview's "Load failed", so whatever surface shows the error
 * shows the reason. Imported for its effect at the top of the workbench. A
 * browser build registers nothing.
 */

import { controlPlaneBase, registerLocalControlPlaneFailure } from "@gaugewright/control-plane-client";

const isTauri = () => typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

export async function desktopControlPlaneFailure(): Promise<string | null> {
    if (!isTauri()) return null;
    try {
        const { invoke } = await import("@tauri-apps/api/core");
        const failure = await invoke<{ kind?: unknown; message?: unknown } | null>("control_plane_failure");
        return typeof failure?.message === "string" && failure.message ? failure.message : null;
    } catch {
        // A shell that predates the command has no reason to give.
        return null;
    }
}

export function registerDesktopControlPlaneFailure(): void {
    if (!isTauri()) return;
    registerLocalControlPlaneFailure(controlPlaneBase(), desktopControlPlaneFailure);
}

registerDesktopControlPlaneFailure();
