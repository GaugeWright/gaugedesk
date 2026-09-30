/**
 * What a desktop does, without asking, for a signed-in account that no Home
 * serves (DR-0264).
 *
 * The desktop used to answer that state with a card asking where projects
 * should run. Every option on it — a Home endpoint, the account's registered
 * Homes, Administration — is a way to reach a Home somewhere else, so none of
 * them could help a new account on its own computer.
 *
 * A fresh computer (never claimed, holding nothing a person made) becomes the
 * account's Home. DR-0219's explicit claim protects existing local work, and a
 * fresh computer has none.
 *
 * Any other computer is left to the card, which says whose it is and offers
 * the acts that work there. It is not sent to local mode: that is the
 * signed-out posture, which reaches models only through credentials saved on
 * this computer, so on a computer without them it returned the person to
 * sign-in, which returned them to local mode.
 *
 * Nothing is decided for an account that already has a Home or a shared
 * route, or while a project invitation is waiting.
 */
import type { HubSessionStatus } from "@gaugewright/control-plane-client";

export interface DesktopHomeDefaultInput {
    readonly desktop: boolean;
    readonly session: HubSessionStatus | null | undefined;
    readonly noHome: {
        readonly homes: readonly unknown[];
        readonly routes: readonly unknown[];
        readonly selectedHome?: string | null;
    } | null;
    readonly invitation: boolean;
}

/** Whether to claim this computer for the signed-in account without asking. */
export function claimWithoutAsking(input: DesktopHomeDefaultInput): boolean {
    const { session, noHome } = input;
    if (!input.desktop || !noHome || input.invitation) return false;
    if (!session?.linked || session.expired || !session.person) return false;
    if (noHome.homes.length > 0 || noHome.routes.length > 0 || noHome.selectedHome) return false;
    return session.homeClaim?.state === "available" && session.homeClaim.fresh;
}
