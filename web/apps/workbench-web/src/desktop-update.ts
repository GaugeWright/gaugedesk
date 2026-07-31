/** The signed desktop updater currently publishes the stable release lane. */
export const DESKTOP_UPDATE_CHANNEL = "stable" as const;

export interface SoftwareUpdatePolicy {
    readonly allowedChannels: readonly string[];
}

/** An absent policy, or one without a channel restriction, preserves the
 * unmanaged/solo updater behavior. A managed channel list is a ceiling. */
export function desktopUpdateAllowed(policy: SoftwareUpdatePolicy | null): boolean {
    return policy === null
        || policy.allowedChannels.length === 0
        || policy.allowedChannels.includes(DESKTOP_UPDATE_CHANNEL);
}
