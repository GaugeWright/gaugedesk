/**
 * Registers the desktop window's credential for its own control plane
 * (DR-0269), before the first request this window makes.
 *
 * The shell mints a secret at launch and requires it on every loopback
 * request; it hands the secret only to this window, over Tauri IPC. Imported
 * for its effect at the top of the workbench, so registration runs during
 * module evaluation, ahead of any component that could reach the network. A
 * browser build registers nothing and sends nothing.
 */

import { controlPlaneBase, registerLocalOperatorCredential } from "@gaugewright/control-plane-client";

const isTauri = () => typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

export async function desktopOperatorSecret(): Promise<string | null> {
    if (!isTauri()) return null;
    try {
        const { invoke } = await import("@tauri-apps/api/core");
        const secret = await invoke<string | null>("operator_secret");
        return typeof secret === "string" && secret ? secret : null;
    } catch {
        // A shell that predates the command: its control plane requires none.
        return null;
    }
}

export function registerDesktopOperatorCredential(): void {
    if (!isTauri()) return;
    registerLocalOperatorCredential(controlPlaneBase(), desktopOperatorSecret());
}

registerDesktopOperatorCredential();
