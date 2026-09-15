import type { AppearancePreferenceV1 } from "@gaugewright/control-plane-client";

export const DEFAULT_APPEARANCE: AppearancePreferenceV1 = {
    version: 1,
    interface_scale: "standard",
    contrast: "standard",
    motion: "system",
};

/** Apply the server-owned person preference to the one composed Desk root. */
export function applyAppearancePreference(
    preference: AppearancePreferenceV1,
    root: HTMLElement = document.documentElement,
): void {
    root.dataset.gwInterfaceScale = preference.interface_scale;
    root.dataset.gwContrast = preference.contrast;
    root.dataset.gwMotion = preference.motion;
}

export function resetAppearancePreference(root: HTMLElement = document.documentElement): void {
    applyAppearancePreference(DEFAULT_APPEARANCE, root);
}
