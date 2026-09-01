/**
 * Adding a TokenWright box, as a state machine the panel only paints.
 *
 * The journey has more failure than success in it, and every failure is a person
 * standing at a machine with a string they copied. So the states are named for
 * what the operator should do next rather than for what went wrong inside, and
 * each carries the one sentence a panel can show without the operator opening a
 * console.
 *
 * The ordering matters and is not cosmetic:
 *
 * 1. **read** the pairing string — a bad paste must fail here, before anything
 *    dials, because "cannot connect" sends someone to look at their network when
 *    the real answer is that they copied one line short.
 * 2. **dial** the claim-code rendezvous and pin the certificate the string named.
 * 3. **claim**, which is the only moment the box will ever hand over the route
 *    that reaches it afterwards.
 * 4. **store** that record *before* reporting success. A claim that succeeded and
 *    was not persisted has spent the code and lost the box — the worst outcome
 *    available here, and the reason `save` is awaited inside the machine rather
 *    than left to the caller afterwards.
 *
 * @see tokenwright-pairing.ts in `control-plane-client` for the derivations.
 */

import {
    claimTokenWrightBox,
    parseTokenWrightInvite,
    type TokenWrightConnection,
    type TokenWrightInvite,
} from "@gaugewright/control-plane-client";

export type TokenWrightConnectPhase =
    | "idle"
    | "reading"
    | "dialling"
    | "claiming"
    | "storing"
    | "connected"
    | "failed";

export interface TokenWrightConnectState {
    readonly phase: TokenWrightConnectPhase;
    /** What to show. Present in every phase, because a spinner with no words is
     * indistinguishable from a hang. */
    readonly message: string;
    /** Set once the string parses, so the panel can show the operator which box
     * and relay they are about to trust before anything is dialled. */
    readonly invite?: TokenWrightInvite;
    readonly connection?: TokenWrightConnection;
    /** Whether trying the same string again could plausibly work. A damaged
     * paste is worth retrying; a spent claim code never is, and offering a retry
     * that cannot succeed is worse than offering none. */
    readonly retryable: boolean;
}

export const IDLE: TokenWrightConnectState = {
    phase: "idle",
    message: "Paste the pairing string printed on the box.",
    retryable: true,
};

/** A transport already opened against a locator, and the pin it actually got.
 *
 * The panel supplies this rather than the machine opening its own: who owns the
 * socket and when it is closed differs between the workbench and a test, and a
 * tunnel whose owner has gone leaves a leg spliced against the relay so that
 * *every later attempt to reach that box waits for a splice that cannot happen*.
 */
export interface OpenedBoxTransport {
    readonly json: (method: string, path: string, body?: unknown) => Promise<unknown>;
    /** The fingerprint the transport verified, not the one the box claims. */
    readonly presentedFingerprint?: string;
    readonly close?: () => void;
}

export interface ConnectDependencies {
    /** Open a pinned tunnel to the box named by a parsed pairing string. */
    readonly open: (invite: TokenWrightInvite) => Promise<OpenedBoxTransport>;
    /** Persist the claim. Must durably store before it resolves. */
    readonly save: (connection: TokenWrightConnection) => Promise<void>;
    readonly homeId: string;
    readonly homeKey: string;
    /** Reports each state as it is entered, so a panel can paint progress
     * without polling. */
    readonly onState?: (state: TokenWrightConnectState) => void;
}

function message(error: unknown): string {
    return error instanceof Error && error.message ? error.message : String(error);
}

/**
 * Run the journey. Never throws: every outcome is a state the panel can render,
 * because an exception escaping here would surface as a blank panel.
 */
export async function connectTokenWrightBox(
    token: string,
    dependencies: ConnectDependencies,
): Promise<TokenWrightConnectState> {
    const emit = (state: TokenWrightConnectState): TokenWrightConnectState => {
        dependencies.onState?.(state);
        return state;
    };

    emit({ phase: "reading", message: "Reading the pairing string…", retryable: true });
    let invite: TokenWrightInvite;
    try {
        invite = parseTokenWrightInvite(token);
    } catch (error) {
        // Retryable: this is a paste, and pasting again is exactly the fix.
        return emit({ phase: "failed", message: message(error), retryable: true });
    }

    emit({
        phase: "dialling",
        message: `Looking for the box on ${invite.relayEndpoint}…`,
        invite,
        retryable: true,
    });
    let transport: OpenedBoxTransport;
    try {
        transport = await dependencies.open(invite);
    } catch (error) {
        return emit({
            phase: "failed",
            invite,
            // Both halves are worth saying: a box that is not parked and a relay
            // that is unreachable look identical from here, and the operator can
            // check one of them in a second.
            message: `Could not reach the box: ${message(error)}. It may be switched off, or the relay may be unreachable from here.`,
            retryable: true,
        });
    }

    try {
        emit({ phase: "claiming", message: "Claiming the box…", invite, retryable: true });
        let connection: TokenWrightConnection;
        try {
            connection = await claimTokenWrightBox({
                json: transport.json,
                invite,
                homeId: dependencies.homeId,
                homeKey: dependencies.homeKey,
                presentedFingerprint: transport.presentedFingerprint,
            });
        } catch (error) {
            // Not retryable. Either the code was already spent, or the box
            // refused the proof — and in both cases pasting the same string
            // again produces the same refusal. Sending someone round that loop
            // hides the fact that they need a new code from the box.
            return emit({
                phase: "failed",
                invite,
                message: `${message(error)} If this box was already claimed, unpair it on the box to get a new pairing string.`,
                retryable: false,
            });
        }

        emit({ phase: "storing", message: "Saving how to reach it again…", invite, retryable: false });
        try {
            await dependencies.save(connection);
        } catch (error) {
            // The worst outcome here, and it must not be dressed up. The code is
            // spent, the box is claimed, and the one copy of its route did not
            // reach disk. Saying "failed" would suggest nothing happened.
            return emit({
                phase: "failed",
                invite,
                connection,
                message: `The box was claimed, but saving it failed: ${message(error)}. Do not close this window — the route below cannot be recovered, and without it the box must be unpaired in person.`,
                retryable: false,
            });
        }

        return emit({
            phase: "connected",
            invite,
            connection,
            message: `Connected. This box is now paired to ${dependencies.homeId}.`,
            retryable: false,
        });
    } finally {
        transport.close?.();
    }
}
