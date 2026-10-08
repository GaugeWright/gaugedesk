import { HomeTunnelError } from "@gaugewright/control-plane-client";

/** Whether Home discovery failed because the hosted account session is absent/expired. */
export function isHomeAuthenticationFailure(error: unknown): boolean {
    const message = error instanceof Error ? error.message : String(error ?? "");
    return /(?:^|:) 401(?:\s|$)/.test(message);
}

/** The ceiling on Home discovery as a whole — longer than the selected Home's
 * own dial timeout, so an asleep Home is still reported as that. */
export const HOME_DISCOVERY_TIMEOUT_MS = 45_000;

/** How long "Finding your Home…" stands alone before it offers account work.
 * A Home found sooner than this never shows the offer, so a desktop starting
 * up does not flash it. */
export const HOME_DISCOVERY_SLOW_MS = 3_000;

/** Where desk stands in finding the person's Home. */
export interface HomeGate {
    /** Discovery is still running. */
    readonly finding: boolean;
    /** It has run for longer than [`HOME_DISCOVERY_SLOW_MS`]. */
    readonly findingSlow: boolean;
    /** It ended in the failure card. */
    readonly failed: boolean;
    /** It ended with no Home serving the person. */
    readonly noHome: boolean;
}

/**
 * Whether an open GaugeApp takes the screen in place of the Home gate.
 *
 * Account work needs no Home (DR-0260): the account service answers Account
 * Settings, Trusted Devices and the rest. So a GaugeApp the person opened —
 * by a link, or from the gate's own Account settings — is shown while desk is
 * still finding their Home, when finding it failed, and when they have none.
 * Before this it was shown only in the last case: a Trusted Devices link
 * waited behind "Finding your Home…" for as long as discovery took, and the
 * failure card's Account settings changed the address and showed nothing.
 * Closing the GaugeApp returns to the gate.
 *
 * Discovery that has not yet been slow keeps its card, so a Home found at
 * once goes straight to the workbench, where the GaugeApp opens in its panes.
 */
export function accountWorkReplacesHomeGate(gaugeAppOpen: boolean, gate: HomeGate): boolean {
    if (!gaugeAppOpen) return false;
    if (gate.finding) return gate.findingSlow;
    return gate.failed || gate.noHome;
}

/** Whether a desktop Home reached over its relay said it cannot act for this
 * person: the Hub named them its owner, but GaugeDesk on that computer is not
 * signed in as them (DR-0206). It is running, and retrying cannot change the
 * answer; signing in at the computer can.
 *
 * Matched on the Home's own words (`relay_route_stack::RELAY_REFUSAL`), which
 * both transports keep: the tunnel reports the raw body and the direct route
 * its `error` text. */
export function isRelayClosedRefusal(error: unknown): boolean {
    const message = error instanceof Error ? error.message : String(error ?? "");
    return /: 403 /.test(message)
        && /this computer is not signed in to GaugeDesk as you/.test(message);
}

export type HomeDiscoveryFailure = {
    readonly kind: "failure";
    readonly authentication: boolean;
    readonly homeConnection: boolean;
    /** The Home refused remote connections outright; see [`isRelayClosedRefusal`]. */
    readonly relayClosed: boolean;
    readonly message: string;
};

/**
 * Turn bootstrap rejection into ordinary UI state. Solid resources propagate a
 * rejected fetcher through their error boundary before the recovery controls
 * can reliably mount, so hosted authentication failures must resolve here.
 */
export async function captureHomeDiscovery<T>(
    load: () => Promise<T>,
    timeoutMs = HOME_DISCOVERY_TIMEOUT_MS,
): Promise<T | HomeDiscoveryFailure> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
        // "Finding your Home…" has no control of its own, so it must end: a
        // discovery that never settles becomes the failure card, whose Retry
        // starts it again.
        return await Promise.race([
            load(),
            new Promise<never>((_, reject) => {
                timer = setTimeout(
                    () => reject(new Error("Finding your Home took too long")),
                    timeoutMs,
                );
            }),
        ]);
    } catch (error) {
        return {
            kind: "failure",
            authentication: isHomeAuthenticationFailure(error),
            homeConnection: error instanceof HomeTunnelError,
            relayClosed: isRelayClosedRefusal(error),
            message: error instanceof Error ? error.message : String(error ?? ""),
        };
    } finally {
        clearTimeout(timer);
    }
}
