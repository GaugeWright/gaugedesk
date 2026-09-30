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

/** Personal membership and explicit local mode have no organization software
 * policy. A selected organization still governs its own release channel. */
export function selectedDesktopUpdatePolicy(
    selected: { readonly personal: boolean } | null | undefined,
    localMode: boolean,
    readOrganizationPolicy: () => Promise<SoftwareUpdatePolicy | null>,
): Promise<SoftwareUpdatePolicy | null> {
    return selected?.personal || (!selected && localMode)
        ? Promise.resolve(null)
        : readOrganizationPolicy();
}

/** Whether the policy governing this desktop is known. Account membership can
 * arrive after the shell mounts, or never, when the Home refuses the selected
 * account. Local mode is an explicit choice and has no organization policy. */
export function desktopUpdateScopeReady(
    selected: { readonly personal: boolean } | null | undefined,
    localMode: boolean,
): boolean {
    return Boolean(selected) || localMode;
}

/** An absent policy, or one without a channel restriction, preserves the
 * unmanaged/solo updater behavior. A managed channel list is a ceiling. */
export function desktopUpdateAllowed(policy: SoftwareUpdatePolicy | null): boolean {
    return policy === null
        || policy.allowedChannels.length === 0
        || policy.allowedChannels.includes(DESKTOP_UPDATE_CHANNEL);
}

/** What a discovered update may do, given the policy that governs it.
 * `undefined` is a policy not yet known: no account scope has resolved, which
 * happens for as long as the selected account is refused by this computer's
 * Home. Discovery does not wait for it — the update service needs no account —
 * but installation does, because an unknown policy may be a ceiling. */
export function desktopUpdateOffer(
    policy: SoftwareUpdatePolicy | null | undefined,
): "available" | "restricted" | "held" {
    if (policy === undefined) return "held";
    return desktopUpdateAllowed(policy) ? "available" : "restricted";
}

/** How long discovery waits on the update service or the policy read. Without
 * a ceiling a request that never answers leaves "Checking for updates…" on
 * screen indefinitely, which reads as a hang rather than a failed check. */
export const DESKTOP_UPDATE_CHECK_TIMEOUT_MS = 30_000;

export function withDesktopUpdateTimeout<T>(
    work: Promise<T>,
    ms: number = DESKTOP_UPDATE_CHECK_TIMEOUT_MS,
): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const expired = new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`update check timed out after ${ms} ms`)), ms);
    });
    return Promise.race([work, expired]).finally(() => clearTimeout(timer));
}
