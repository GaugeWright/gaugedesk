/**
 * Reading project→Home routes from the **root-signed** directory record
 * (DESK-5c, [ADR 0131](../../../../specs/decisions/0131-a-home-authors-and-signs-its-own-reachability.md)
 * §2, [ADR 0132](../../../../specs/decisions/0132-a-browser-pins-the-account-root-key.md)).
 *
 * Two checks, and the second is the one that matters. `verifySignedPut` proves
 * the record is *self-consistent* — signed by whatever root it names. That alone
 * is worthless: a forger signs their own record with their own root and it
 * verifies perfectly. What makes it mean something is comparing that root
 * against the key this browser **pinned**, which is why the comparison lives
 * here rather than being folded into the verifier.
 *
 * The pin is trust-on-first-use, per ADR 0132: the first signed-in load for a
 * subject records the root it saw, and any later change is refused rather than
 * adopted. A public key is not a credential, so keeping it is not the at-rest
 * exposure `ENTSEC-6` forbids.
 */

import { parseOpaqueHomeRoutes, type OpaqueHomeRoute } from "./home-routing";

const PIN_PREFIX = "gw.root.";

/** The canonical blind-directory origin, matching the desktop's default. */
export const DIRECTORY_ORIGIN = "https://directory.gaugewright.com";

export interface SignedRouteOptions {
    /** The signed-in subject. Pins are per person: signing out and in as
     * someone else must not compare keys across them. */
    readonly subject: string;
    readonly directoryOrigin?: string;
    /** The wasm verifier — `verify_signed_put_json`. Injected so this is
     * testable, and so the signing contract stays owned by the Rust crate. */
    readonly verify: (json: string) => boolean;
    readonly fetchJson?: (url: string) => Promise<string | null>;
    readonly storage?: Pick<Storage, "getItem" | "setItem">;
}

function store(options: SignedRouteOptions): Pick<Storage, "getItem" | "setItem"> | null {
    if (options.storage) return options.storage;
    try {
        return globalThis.localStorage ?? null;
    } catch {
        // Private browsing, or storage denied. A pin is an improvement, not a
        // requirement: without one the caller falls back to endpoint-only.
        return null;
    }
}

export function pinnedRootKey(options: SignedRouteOptions): string | null {
    return store(options)?.getItem(PIN_PREFIX + options.subject) ?? null;
}

/** Record the root key for a subject. Refuses to overwrite a different one:
 * a changed root is an alarm, not an update. */
export function pinRootKey(options: SignedRouteOptions, root: string): "pinned" | "matched" | "conflict" {
    const existing = pinnedRootKey(options);
    if (existing === root) return "matched";
    if (existing) return "conflict";
    store(options)?.setItem(PIN_PREFIX + options.subject, root);
    return "pinned";
}

export class RootKeyConflict extends Error {}

/**
 * Fetch and verify the signed record, returning its routes at `signed`
 * provenance — so their relay locators may be honoured.
 *
 * Returns `null` when there is no record to read, which is an ordinary state:
 * an account that has never published one is not under attack.
 */
export async function signedHomeRoutes(
    options: SignedRouteOptions,
): Promise<OpaqueHomeRoute[] | null> {
    const origin = (options.directoryOrigin ?? DIRECTORY_ORIGIN).replace(/\/+$/, "");
    const pinned = pinnedRootKey(options);
    // Without a pin there is nothing to check the record against, and reading it
    // would only launder the hub's word into something that looks verified.
    const root = pinned;
    if (!root) return null;

    const fetchJson = options.fetchJson ?? (async (url) => {
        const response = await fetch(url, { headers: { accept: "application/json" } });
        if (response.status === 404) return null;
        if (!response.ok) throw new Error(`directory read failed: ${response.status}`);
        return response.text();
    });

    const body = await fetchJson(`${origin}/directory/${encodeURIComponent(root)}`);
    if (!body) return null;
    if (!options.verify(body)) {
        throw new Error("the account directory record failed signature verification");
    }
    const put = JSON.parse(body) as {
        entry?: { directory?: { root_pubkey?: unknown; home_routes?: unknown } };
    };
    const named = put.entry?.directory?.root_pubkey;
    // The signature proves only self-consistency. This is what binds the record
    // to *this* account rather than to whoever signed it.
    if (typeof named !== "string" || named !== root) {
        throw new RootKeyConflict(
            "the directory record is signed by a different account root than the pinned one",
        );
    }
    const routes = put.entry?.directory?.home_routes;
    return parseOpaqueHomeRoutes({ routes: Array.isArray(routes) ? routes : [] }, "signed");
}
