/**
 * Joining the two route channels a browser can read (DESK-5g, ADR 0133 §3).
 *
 * The serving Home publishes routes into the **root-signed directory record**;
 * the hub keeps a **route table** any holder of the person's session can write
 * into. ADR 0131 makes the first authoritative and the second a hint, and says a
 * hint may carry an endpoint but never a pin. This is where that ordering is
 * actually applied.
 *
 * The sequence is fixed and each step exists because the one before it cannot
 * stand alone:
 *
 *   1. Read the account's directory projection — without the root key there is
 *      no path to fetch, because the directory is addressed by that key.
 *   2. Pin it (ADR 0132). First sight records; a *different* key for the same
 *      subject is refused as an alarm rather than adopted.
 *   3. Fetch and verify the record. The signature proves only that whoever
 *      signed holds the key the record names, so it is compared against the pin
 *      — that comparison, not the signature, is what binds the record to this
 *      account.
 *   4. Fall back to the hub table for anything the signed record does not cover,
 *      at `unsigned`, so its endpoints remain usable and its pins are dropped.
 *
 * **Degrade, never fail closed.** An account that has published nothing, a hub
 * too old to serve the projection, a directory that is down, a build with no
 * verifier — all of these mean *no signed routes*, which is exactly today's
 * behaviour and not an error. The one condition that is *not* a degradation is a
 * root key that changed: that is surfaced, because silently adopting it is the
 * substitution the pin exists to catch.
 */

import { accountDirectory } from "./control-plane-account";
import type { RouteJson } from "./control-plane-transport";
import { directoryVerifierAvailable, verifySignedPut } from "./directory-module";
import { parseOpaqueHomeRoutes, type OpaqueHomeRoute } from "./home-routing";
import {
    pinRootKey,
    RootKeyConflict,
    signedHomeRoutes,
    DIRECTORY_ORIGIN,
} from "./signed-routes";

export interface ResolveHomeRoutesOptions {
    /** The account plane, for the projection and the hub table. */
    readonly json: RouteJson;
    /** The signed-in subject. Pins are per person (ADR 0132 §5). */
    readonly subject: string;
    readonly storage?: Pick<Storage, "getItem" | "setItem">;
    readonly fetchJson?: (url: string) => Promise<string | null>;
    /** Report a root key that changed. Never thrown at the caller, because a
     * substitution must not also take away the reachability the person had. */
    readonly onRootKeyConflict?: (error: RootKeyConflict) => void;
}

export interface ResolvedHomeRoutes {
    readonly routes: OpaqueHomeRoute[];
    /** Whether any route came from a verified record. Callers surface this;
     * they must not infer it from a route carrying a relay locator, because an
     * account may legitimately have none. */
    readonly verified: boolean;
}

/** The hub's table, read truthfully — a projection, never authority. */
async function hubRoutes(json: RouteJson): Promise<OpaqueHomeRoute[]> {
    return parseOpaqueHomeRoutes(await json("GET", "/account/home-routes"), "unsigned");
}

export async function resolveHomeRoutes(
    options: ResolveHomeRoutesOptions,
): Promise<ResolvedHomeRoutes> {
    const hub = await hubRoutes(options.json);
    if (!options.subject || !directoryVerifierAvailable()) {
        return { routes: hub, verified: false };
    }

    const projection = await accountDirectory(options.json);
    if (!projection) return { routes: hub, verified: false };

    const seam = {
        subject: options.subject,
        directoryOrigin: projection.origin || DIRECTORY_ORIGIN,
        verify: verifySignedPut,
        ...(options.storage ? { storage: options.storage } : {}),
        ...(options.fetchJson ? { fetchJson: options.fetchJson } : {}),
    };

    if (pinRootKey(seam, projection.rootPubkey) === "conflict") {
        options.onRootKeyConflict?.(
            new RootKeyConflict("the account root key changed since this browser first saw it"),
        );
        // Refuse the record, keep the endpoints. A substitution is a reason to
        // stop honouring pins, not a reason to strand the person.
        return { routes: hub, verified: false };
    }

    let signed: OpaqueHomeRoute[] | null;
    try {
        signed = await signedHomeRoutes(seam);
    } catch (error) {
        if (error instanceof RootKeyConflict) options.onRootKeyConflict?.(error);
        // A directory outage, a malformed record, a failed signature, a verifier
        // that would not load: every one means *no signed routes*. None of them
        // means a broken account, so each degrades to the hub's endpoints.
        return { routes: hub, verified: false };
    }
    if (!signed) return { routes: hub, verified: false };

    // Signed wins per project; the hub still answers for projects the record
    // does not mention, because a person may reach a project through an
    // invitation their own Home never authored a route for.
    const merged = new Map(hub.map((route) => [route.project, route]));
    for (const route of signed) merged.set(route.project, route);
    return { routes: [...merged.values()], verified: true };
}
