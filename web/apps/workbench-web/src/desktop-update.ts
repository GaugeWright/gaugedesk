/** The signed desktop updater currently publishes the stable release lane. */
export const DESKTOP_UPDATE_CHANNEL = "stable" as const;

/** How long a running client waits before asking the update service again.
 *
 * Discovery is a timer rather than a subscription because the thing being
 * discovered is a static signed manifest fetched over plain HTTPS: nothing
 * pushes a release to a client that is already running, and there is no channel
 * to subscribe to. A client that asked once at startup therefore answers with
 * whatever was published *before it launched*, for as long as it stays open —
 * which for a desktop client is days, and is how a shipped release goes unseen
 * by the people already running the previous one.
 *
 * Six hours is chosen against the release cadence, not the cache: the endpoint
 * serves `max-age=60`, so this is far more conservative than the service
 * expects, and it still narrows "never" to within a working day. */
export const DESKTOP_UPDATE_RECHECK_MS = 6 * 60 * 60 * 1000;

/** Whether a client in this state should ask again on the recheck timer.
 *
 * An update already in hand cannot be improved on by asking again, and a check
 * that lands mid-install would replace the installing state with a discovery
 * result. Every other state — including a failed one — is worth re-asking. */
export function desktopUpdateShouldRecheck(kind: string | undefined): boolean {
    return kind !== "available" && kind !== "installing";
}

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
